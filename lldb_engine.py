"""Allowlisted LLDB inspection inside the sandbox only."""

from sandbox_runner import SandboxJob


def execute_lldb_command(job: SandboxJob, command: str) -> str:
    code, stdout, stderr = job.lldb(command)
    if code == 124:
        return "LLDB Timeout: the command took too long."
    text = (stdout or "") + (("\n" + stderr) if stderr else "")
    return text.strip() or f"(no LLDB output, exit {code})"
