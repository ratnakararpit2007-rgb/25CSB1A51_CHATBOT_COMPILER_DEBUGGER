"""Multi-language sandbox runner supporting hardened Docker isolation and secure local execution."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
import uuid
from typing import Any

from languages import get_adapter
from security_config import get_security_config
from security_logger import log_security_event

IMAGE = os.environ.get("SANDBOX_IMAGE", "cpp-debug-sandbox:latest")
COMPILE_TIMEOUT = 10
RUN_TIMEOUT = 5
LLDB_TIMEOUT = 10
JOB_TTL_SEC = 1800

_HERE = os.path.dirname(os.path.abspath(__file__))


class SandboxError(RuntimeError):
    pass


def is_docker_available() -> bool:
    """Return True only if the Docker CLI and daemon are fully operational."""
    if os.environ.get("DISABLE_DOCKER") in ("1", "true", "yes") or os.environ.get("SANDBOX_MODE") == "local":
        return False
    try:
        r = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        return r.returncode == 0
    except Exception:
        return False


def is_docker_image_present(image_name: str = IMAGE) -> bool:
    """Return True if the target docker image is downloaded or built."""
    try:
        r = subprocess.run(
            ["docker", "image", "inspect", image_name],
            capture_output=True,
            text=True,
            timeout=3,
        )
        return r.returncode == 0
    except Exception:
        return False


def _docker_available() -> None:
    if not is_docker_available():
        raise SandboxError(
            "Docker is not available. Install Docker Desktop and start the engine."
        )


def _image_present() -> None:
    if not is_docker_image_present():
        dockerfile = os.path.join(_HERE, "Dockerfile")
        raise SandboxError(
            f"Sandbox image {IMAGE!r} is missing. Build it with: "
            f"docker build -t {IMAGE} -f {dockerfile} {_HERE}"
        )


def _posix_sandbox_preexec() -> None:
    """Apply POSIX process resource limits in local subprocess mode."""
    if os.name != "posix":
        return
    try:
        import resource
        cfg = get_security_config().sandbox
        # Set max CPU seconds limit
        resource.setrlimit(resource.RLIMIT_CPU, (cfg.local_max_cpu_sec, cfg.local_max_cpu_sec + 2))
        # Set max file size creation limit (e.g. 10MB)
        resource.setrlimit(resource.RLIMIT_FSIZE, (cfg.local_max_fsize_bytes, cfg.local_max_fsize_bytes))
    except Exception:
        pass


def get_sanitized_sandbox_env(workdir: str = "", base_env: dict[str, str] | None = None) -> dict[str, str]:
    """Return an execution environment scrubbed of host secrets and credentials."""
    cfg = get_security_config().sandbox
    env = dict(base_env if base_env is not None else os.environ)
    for k in cfg.scrub_env_keys:
        env.pop(k, None)
    for k in list(env.keys()):
        k_upper = k.upper()
        if any(term in k_upper for term in ("API_KEY", "SECRET", "PRIVATE_KEY", "AUTH_TOKEN", "CREDENTIAL")):
            env.pop(k, None)
    if workdir:
        env["TMPDIR"] = workdir
    env["LC_ALL"] = "C.UTF-8"
    return env


def _run_process(
    args: list[str],
    timeout: int,
    stdin: str | None = None,
    cwd: str | None = None,
    env: dict | None = None,
    apply_limits: bool = False,
) -> subprocess.CompletedProcess:
    try:
        preexec = _posix_sandbox_preexec if apply_limits and os.name == "posix" else None
        return subprocess.run(
            args,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=env,
            preexec_fn=preexec,
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(args, 124, exc.stdout or "", "Time Limit Exceeded (Timeout)")
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(args, 127, "", f"Binary or command not found: {exc}")
    except PermissionError as exc:
        return subprocess.CompletedProcess(args, 126, "", f"Permission denied executing binary: {exc}")
    except OSError as exc:
        return subprocess.CompletedProcess(args, -1, "", f"System execution error: {exc}")


class SandboxJob:
    """
    Unified Sandbox Job supporting both Docker containerization and
    secure local process sandboxing.
    """

    def __init__(self, source_code: str, language: str = "cpp", force_mode: str | None = None):
        self.language = (language or "cpp").lower()
        self.adapter = get_adapter(self.language)
        self.job_id = f"dbg-{self.language}-{uuid.uuid4().hex[:10]}"
        self.workdir = tempfile.mkdtemp(prefix=f"{self.job_id}-")

        # Determine file name for the language
        self.source_filename = self.adapter.file_name
        self.source_path = os.path.join(self.workdir, self.source_filename)

        with open(self.source_path, "w", encoding="utf-8") as fh:
            fh.write(source_code)
        os.chmod(self.workdir, 0o755)
        os.chmod(self.source_path, 0o644)

        # Decide execution mode: "docker" or "local"
        if force_mode == "docker":
            _docker_available()
            _image_present()
            self.mode = "docker"
        elif force_mode == "local" or os.environ.get("DISABLE_DOCKER") in ("1", "true", "yes") or os.environ.get("SANDBOX_MODE") == "local":
            self.mode = "local"
        else:
            # Auto-detect: prefer docker if available and image present, else local
            if is_docker_available() and is_docker_image_present(IMAGE):
                self.mode = "docker"
            else:
                self.mode = "local"

        if self.mode == "docker":
            self._start_docker_container()

    def _start_docker_container(self) -> None:
        cmd = [
            "docker", "run", "-d",
            "--name", self.job_id,
            "--network", "none",
            "--read-only",
            "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=64m",
            "--user", "65534:65534",
            "--cap-drop", "ALL",
            "--cap-add", "SYS_PTRACE",
            "--security-opt", "no-new-privileges",
            "--memory", "256m",
            "--cpus", "0.5",
            "--pids-limit", "64",
            "--ulimit", "nproc=32",
            "--ulimit", "nofile=64",
            "-e", "TMPDIR=/tmp",
            "-v", f"{self.workdir}:/work:rw",
            IMAGE,
            "sleep", str(JOB_TTL_SEC),
        ]
        r = _run_process(cmd, timeout=20)
        if r.returncode != 0:
            self.close()
            raise SandboxError(f"Failed to start sandbox container: {r.stderr.strip()}")

    def exec_cmd(self, argv: list[str], timeout: int, stdin: str | None = None) -> subprocess.CompletedProcess:
        if self.mode == "docker":
            args = ["docker", "exec", "-i", "-e", "TMPDIR=/tmp", self.job_id, *argv]
            r = _run_process(args, timeout=timeout + 2, stdin=stdin)
            if r.returncode == 124:
                subprocess.run(["docker", "kill", self.job_id], capture_output=True, timeout=5)
            return r
        else:
            # Local isolated execution
            # Remap container paths (/work -> self.workdir, /tmp -> self.workdir)
            local_argv = []
            for arg in argv:
                if arg.startswith("/work/"):
                    local_argv.append(os.path.join(self.workdir, arg[6:]))
                elif arg == "/work":
                    local_argv.append(self.workdir)
                elif arg.startswith("/tmp/"):
                    local_argv.append(os.path.join(self.workdir, arg[5:]))
                elif arg == "/tmp":
                    local_argv.append(self.workdir)
                else:
                    local_argv.append(arg)

            env = get_sanitized_sandbox_env(self.workdir)
            return _run_process(local_argv, timeout=timeout, stdin=stdin, cwd=self.workdir, env=env, apply_limits=True)

    def compile(self, src: str | None = None, out: str | None = None) -> tuple[int, str, str]:
        """
        Compile using the language adapter's compile command.
        For interpreted languages without a build step, validates syntax.
        """
        if self.mode == "docker":
            src_in = src or f"/work/{self.source_filename}"
            out_in = out or "/tmp/a.out"
        else:
            src_in = src or os.path.join(self.workdir, self.source_filename)
            out_in = out or os.path.join(self.workdir, "a.out")

        cmd = self.adapter.get_compile_cmd(src_in, out_in)
        if not cmd:
            # Interpreted language with no syntax command
            return 0, "", ""

        r = self.exec_cmd(cmd, timeout=COMPILE_TIMEOUT)
        return r.returncode, r.stdout, r.stderr

    def run_binary(self, stdin: str = "", bin_path: str | None = None) -> tuple[int, str, str]:
        """Execute the compiled binary or interpreted script."""
        if self.mode == "docker":
            target = bin_path or ("/tmp/a.out" if self.adapter.is_compiled else f"/work/{self.source_filename}")
            work_root = "/work"
        else:
            target = bin_path or (os.path.join(self.workdir, "a.out") if self.adapter.is_compiled else os.path.join(self.workdir, self.source_filename))
            work_root = self.workdir

        cmd = self.adapter.get_run_cmd(target, work_root)
        r = self.exec_cmd(cmd, timeout=RUN_TIMEOUT, stdin=stdin)
        return r.returncode, r.stdout, r.stderr

    def lldb(self, command: str, bin_path: str = "/tmp/a.out") -> tuple[int, str, str]:
        """Execute allowlisted LLDB command for C/C++ targets."""
        if self.mode == "docker":
            r = self.exec_cmd(
                ["lldb", "-b", "-o", "process launch", "-o", command, bin_path],
                timeout=LLDB_TIMEOUT,
            )
            return r.returncode, r.stdout, r.stderr
        else:
            target = bin_path if os.path.isabs(bin_path) else os.path.join(self.workdir, bin_path)
            lldb_bin = shutil.which("lldb")
            if not lldb_bin:
                return -1, "", "LLDB debugger not found on host."
            r = self.exec_cmd(
                [lldb_bin, "-b", "-o", "process launch", "-o", command, target],
                timeout=LLDB_TIMEOUT,
            )
            return r.returncode, r.stdout, r.stderr

    def write_candidate(self, code: str, name: str | None = None) -> str:
        """Write a code fix candidate into the job directory."""
        if not name:
            name = f"candidate{os.path.splitext(self.source_filename)[1]}"
        path = os.path.join(self.workdir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(code)
        os.chmod(path, 0o644)
        return f"/work/{name}" if self.mode == "docker" else path

    def close(self) -> None:
        """Teardown containers and remove temp directory."""
        if self.mode == "docker":
            subprocess.run(["docker", "rm", "-f", self.job_id], capture_output=True, timeout=10)
        shutil.rmtree(self.workdir, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False
