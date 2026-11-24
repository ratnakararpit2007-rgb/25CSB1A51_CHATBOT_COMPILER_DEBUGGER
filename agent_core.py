"""Multi-language ReAct orchestrator: reason → policy → sandbox → sanitize → repeat.

Integrates a 9-stage security analysis workflow:
1. Source Ingestion & Parsing
2. Static Analysis
3. Suspicious Pattern Detection
4. Security Vulnerability Detection
5. CWE Mapping (CWE-120, CWE-119, CWE-78, CWE-476, CWE-369, CWE-798, CWE-134, etc.)
6. Severity Classification (CRITICAL, HIGH, MEDIUM, LOW)
7. Dynamic Sandbox Verification & False-Positive Elimination
8. Security Report Generation
9. Secure Code Recommendations
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any

from agent_memory import AgentMemoryStore, ProvenanceMemoryList, TrustLevel
from compiler_service import compile_source, run_binary
from error_classifier import classify_error
from execution_guard import BudgetTracker, LoopDetector
from fix_engine import extract_code, validate_fix
from languages import get_adapter
from languages.base import TestCase
from lldb_engine import execute_lldb_command
from llm_client import GeminiError, LLMError, OllamaError, choose_tool
from output_sanitizer import sanitize_plain, sanitize_tool_output
from policy_gateway import validate_tool_call
from sandbox_runner import SandboxError, SandboxJob
from secure_scan import run_security_guardrail
from security_analyzer import (
    CWEFinding,
    generate_security_report,
    perform_security_analysis,
)
from security_config import get_security_config

SECURITY_ANALYSIS_STAGES = [
    "1. Source Ingestion & Parsing",
    "2. Static Analysis",
    "3. Suspicious Pattern Detection",
    "4. Security Vulnerability Detection",
    "5. CWE Mapping",
    "6. Severity Classification",
    "7. Dynamic Sandbox Verification",
    "8. Security Report Generation",
    "9. Secure Code Recommendations",
]

STAGE_COMPLETED = "COMPLETED"
STAGE_PARTIALLY_COMPLETED = "PARTIALLY_COMPLETED"
STAGE_FAILED = "FAILED"
STAGE_SKIPPED = "SKIPPED"


@dataclass
class AgentResult:
    root_cause: str = ""
    bugs: list[dict] = field(default_factory=list)
    summary: str = ""
    verified_fix: str = ""
    confidence: str = "low"
    learning_note: str = ""
    compile_status: int | None = None
    last_stdout: str = ""
    last_stderr: str = ""
    agent_log: str = ""
    scan_findings: list[str] = field(default_factory=list)
    error: str = ""
    finished: bool = False
    verified: bool = False
    language: str = "cpp"
    sandbox_mode: str = "local"
    # Enhanced security audit & workflow tracking fields
    cwe_findings: list[dict] = field(default_factory=list)
    stages_completed: list[str] = field(default_factory=list)
    stages_remaining: list[str] = field(default_factory=list)
    stage_statuses: dict[str, str] = field(default_factory=dict)
    current_stage: str = ""
    steps_completed: int = 0
    max_steps: int = 8
    failure_reason: str = ""
    recommendations: str = ""
    # Explicit separation of diagnosis vs code repair
    diagnosis_completed: bool = False
    fix_generated: bool = False
    fix_compiled: bool = False
    fix_passed_tests: bool = False


def _set_stage_status(result: AgentResult, stage: str, status: str) -> None:
    """Update stage status and synchronize stages_completed and stages_remaining."""
    result.stage_statuses[stage] = status
    if status == STAGE_COMPLETED:
        if stage in result.stages_remaining:
            result.stages_remaining.remove(stage)
        if stage not in result.stages_completed:
            result.stages_completed.append(stage)
    elif status in (STAGE_FAILED, STAGE_SKIPPED):
        if stage in result.stages_completed:
            result.stages_completed.remove(stage)
        if stage not in result.stages_remaining:
            result.stages_remaining.append(stage)
    elif status == STAGE_PARTIALLY_COMPLETED:
        if stage in result.stages_completed:
            result.stages_completed.remove(stage)
        if stage not in result.stages_remaining:
            result.stages_remaining.append(stage)


def _log_step(lines: list[str], n: int, thought: str, tool: str, observation: str) -> None:
    lines.append(f"Turn {n}: thought: {sanitize_plain(thought)}")
    lines.append(f"Turn {n}: tool: {tool}")
    lines.append(f"Turn {n}: observation:\n{observation}")
    lines.append("---")


def run_agent_job(
    source_code: str,
    language: str = "cpp",
    stdin: str = "",
    test_cases: list[TestCase] | None = None,
    enable_audit: bool = False,
    force_mode: str | None = None,
    ai_provider: str = "auto",
    gemini_api_key: str | None = None,
    gemini_model: str = "gemini-3.8-flash",
) -> AgentResult:
    """
    Run the multi-language ReAct debugging agent and 9-stage security scanner.
    Maintains full backward compatibility with all callers.
    """
    lang = (language or "cpp").lower()
    adapter = get_adapter(lang)
    sec_cfg = get_security_config()
    max_steps = sec_cfg.limits.max_agent_steps
    max_policy_fails = sec_cfg.limits.max_policy_fails

    result = AgentResult(
        language=lang,
        max_steps=max_steps,
        stages_remaining=list(SECURITY_ANALYSIS_STAGES),
        current_stage=SECURITY_ANALYSIS_STAGES[0],
    )
    log_lines: list[str] = []

    # ------------------------------------------------------------------
    # STAGE 1: Source Ingestion & Parsing
    # ------------------------------------------------------------------
    result.current_stage = SECURITY_ANALYSIS_STAGES[0]
    if (
        isinstance(source_code, str)
        and len(source_code.strip()) > 0
        and len(source_code.encode("utf-8")) <= sec_cfg.limits.max_code_bytes
    ):
        _set_stage_status(result, SECURITY_ANALYSIS_STAGES[0], STAGE_COMPLETED)
    else:
        _set_stage_status(result, SECURITY_ANALYSIS_STAGES[0], STAGE_FAILED)
        result.error = "Invalid or empty source code provided."
        result.failure_reason = "SOURCE_INGESTION_ERROR"
        return result

    # ------------------------------------------------------------------
    # STAGES 2–6: Static Analysis, Suspicious Pattern Detection,
    #             Vulnerability Detection, CWE Mapping, Severity Classification
    # ------------------------------------------------------------------
    result.current_stage = SECURITY_ANALYSIS_STAGES[1]
    legacy_findings, legacy_summary = run_security_guardrail(source_code, language=lang)
    result.scan_findings = legacy_findings
    if legacy_findings:
        log_lines.append(f"Pre-scan (advisory): {legacy_summary}")

    try:
        raw_cwe_findings: list[CWEFinding] = perform_security_analysis(source_code, language=lang)
        result.cwe_findings = [f.to_dict() for f in raw_cwe_findings]
        _set_stage_status(result, SECURITY_ANALYSIS_STAGES[1], STAGE_COMPLETED)
        _set_stage_status(result, SECURITY_ANALYSIS_STAGES[2], STAGE_COMPLETED)
        _set_stage_status(result, SECURITY_ANALYSIS_STAGES[3], STAGE_COMPLETED)
        _set_stage_status(result, SECURITY_ANALYSIS_STAGES[4], STAGE_COMPLETED)
        _set_stage_status(result, SECURITY_ANALYSIS_STAGES[5], STAGE_COMPLETED)
    except Exception as exc:
        raw_cwe_findings = []
        _set_stage_status(result, SECURITY_ANALYSIS_STAGES[1], STAGE_FAILED)
        _set_stage_status(result, SECURITY_ANALYSIS_STAGES[2], STAGE_FAILED)
        _set_stage_status(result, SECURITY_ANALYSIS_STAGES[3], STAGE_FAILED)
        _set_stage_status(result, SECURITY_ANALYSIS_STAGES[4], STAGE_FAILED)
        _set_stage_status(result, SECURITY_ANALYSIS_STAGES[5], STAGE_FAILED)
        log_lines.append(f"Static analysis error: {exc}")

    # ------------------------------------------------------------------
    # Prerequisites & Environment Checks
    # ------------------------------------------------------------------
    runtime_ok, runtime_msg = adapter.check_prerequisites()
    if not runtime_ok and force_mode != "docker":
        result.error = runtime_msg
        result.failure_reason = "PREREQUISITE_FAILED"
        result.learning_note = f"Install the {adapter.display_name} compiler or interpreter to execute and test code."
        result.agent_log = f"Prerequisite check failed:\n{runtime_msg}"
        _set_stage_status(result, SECURITY_ANALYSIS_STAGES[6], STAGE_SKIPPED)

        rc, sm, bg, rec = generate_security_report(raw_cwe_findings, language=lang)
        result.root_cause = rc
        result.summary = sm
        result.bugs = bg
        result.recommendations = rec
        result.diagnosis_completed = True
        _set_stage_status(result, SECURITY_ANALYSIS_STAGES[7], STAGE_COMPLETED if rc else STAGE_FAILED)
        _set_stage_status(result, SECURITY_ANALYSIS_STAGES[8], STAGE_COMPLETED if rec else STAGE_FAILED)
        result.current_stage = "Prerequisites Missing (Analysis Halted)"
        return result

    # ------------------------------------------------------------------
    # Initialize Sandbox Job
    # ------------------------------------------------------------------
    try:
        job = SandboxJob(source_code, language=lang, force_mode=force_mode)
        result.sandbox_mode = job.mode
    except SandboxError as exc:
        result.error = str(exc)
        result.failure_reason = "SANDBOX_INITIALIZATION_ERROR"
        result.agent_log = "\n".join(log_lines)
        _set_stage_status(result, SECURITY_ANALYSIS_STAGES[6], STAGE_FAILED)

        rc, sm, bg, rec = generate_security_report(raw_cwe_findings, language=lang)
        result.root_cause = rc
        result.summary = sm
        result.bugs = bg
        result.recommendations = rec
        result.diagnosis_completed = True
        _set_stage_status(result, SECURITY_ANALYSIS_STAGES[7], STAGE_COMPLETED if rc else STAGE_FAILED)
        _set_stage_status(result, SECURITY_ANALYSIS_STAGES[8], STAGE_COMPLETED if rec else STAGE_FAILED)
        result.current_stage = "Sandbox Error (Analysis Halted)"
        return result

    safe_code = sanitize_plain(source_code)
    memory_store = AgentMemoryStore(session_id=job.job_id)
    memory = ProvenanceMemoryList(store=memory_store)
    memory.append(f"Original source is loaded as {adapter.file_name} inside the sandbox.", source="system", trust_level=TrustLevel.TRUSTED_SYSTEM)
    memory.append(f"Active language environment: {adapter.display_name}.", source="system", trust_level=TrustLevel.TRUSTED_SYSTEM)
    memory.append(f"Student Source Code:\n```{adapter.syntax_name}\n{safe_code}\n```", source="student_input", trust_level=TrustLevel.SEMI_TRUSTED_USER)
    if legacy_findings:
        memory.append("Advisory pre-scan notes:\n" + sanitize_tool_output("\n".join(legacy_findings), "pre-scan"), source="pre-scan", trust_level=TrustLevel.TRUSTED_SYSTEM)

    initial_failure_reason = ""
    r_stat: int | None = None
    r_out: str = ""
    r_err: str = ""

    try:
        # ------------------------------------------------------------------
        # STAGE 7: Dynamic Sandbox Verification & False-Positive Elimination
        # ------------------------------------------------------------------
        result.current_stage = SECURITY_ANALYSIS_STAGES[6]
        c_status, c_out, c_err = compile_source(job)
        result.compile_status = c_status
        result.last_stdout = c_out
        result.last_stderr = c_err
        obs = sanitize_tool_output(
            f"compile_exit={c_status}\nstdout:\n{c_out}\nstderr:\n{c_err}",
            "compile",
        )
        memory.append(f"Initial compile observation:\n{obs}")
        log_lines.append(f"Step 0 (Deterministic {adapter.display_name} compile/syntax check)")
        log_lines.append(obs)

        if c_status != 0:
            initial_failure_reason = "COMPILATION_ERROR"
            _set_stage_status(result, SECURITY_ANALYSIS_STAGES[6], STAGE_PARTIALLY_COMPLETED)
            category, strategy = classify_error(c_err or c_out, language=lang)
            memory.append(
                f"Classifier hint: {category}. Strategy: {strategy}.\n"
                f"Note: Initial compilation/syntax check failed. Do NOT call 'run' or 'lldb'. "
                f"Call 'validate_fix' with the complete corrected {adapter.display_name} source code."
            )
            log_lines.append(f"Classifier hint: {category}")
        else:
            # Compiled successfully, test initial execution
            r_stat, r_out, r_err = run_binary(job, stdin=stdin)
            result.last_stdout = r_out
            result.last_stderr = r_err
            if "timeout" in (r_err or "").lower() or "timed out" in (r_err or "").lower():
                initial_failure_reason = "RUNTIME_TIMEOUT"
            elif r_stat != 0:
                initial_failure_reason = "RUNTIME_ERROR"
                cat, strat = classify_error(r_err or r_out, language=lang)
                memory.append(f"Initial run failed with exit {r_stat}. Error hint: {cat} - {strat}")
                log_lines.append(f"Initial run failed (exit {r_stat}): {cat}")

            _set_stage_status(result, SECURITY_ANALYSIS_STAGES[6], STAGE_COMPLETED)

            memory.append(
                "Initial compile succeeded.\n"
                "CRITICAL MULTI-BUG & SECURITY AUDIT REQUIREMENT:\n"
                "Thoroughly audit EVERY function and block. Student code frequently contains MULTIPLE bugs "
                "and vulnerabilities (e.g. CWE-120 buffer overflows, CWE-119 out-of-bounds loops, off-by-one errors, "
                "CWE-369 divide by zero, null dereferences, and type mismatches).\n"
                "Do NOT stop after identifying just one bug! Return ALL bugs in the 'bugs' array of 'finish' "
                "and correct ALL of them in your complete fixed code."
            )

        # Corroborate static findings against compiler & runtime outputs without dropping valid findings
        raw_cwe_findings = perform_security_analysis(
            source_code,
            language=lang,
            compile_status=c_status,
            compile_stderr=c_err,
            runtime_status=r_stat if c_status == 0 else None,
            runtime_stderr=r_err if c_status == 0 else "",
            runtime_stdout=r_out if c_status == 0 else "",
        )
        result.cwe_findings = [f.to_dict() for f in raw_cwe_findings]

        # ------------------------------------------------------------------
        # ReAct Orchestration Loop (Separating attempts from successful steps)
        # ------------------------------------------------------------------
        result.current_stage = SECURITY_ANALYSIS_STAGES[7]
        loop_detector = LoopDetector(session_id=job.job_id)
        budget_tracker = BudgetTracker(session_id=job.job_id)

        max_attempts = max_steps * 2
        attempt = 0
        successful_tool_steps = 0
        consecutive_parse_errors = 0
        max_parse_retries = 3
        consecutive_llm_errors = 0
        max_llm_retries = 2
        consecutive_loops = 0
        policy_fails = 0
        loop_failure_reason = ""

        verified_code = ""
        has_new_fix = False
        cached_compile: str | None = obs if c_status != 0 else obs
        cached_run: str | None = None
        last_run_stdin: str | None = stdin if c_status == 0 else None

        while successful_tool_steps < max_steps and attempt < max_attempts:
            attempt += 1
            result.steps_completed = successful_tool_steps

            state = "\n\n".join(memory[-8:])
            state += f"\n\nStep {successful_tool_steps + 1}/{max_steps} (attempt {attempt}). Choose the next tool as JSON."
            if successful_tool_steps >= max_steps - 1:
                state += "\nThis is your final execution step. You MUST call tool 'finish' with your diagnostic summary, root_cause, and fixed_code."

            # 1. Bounded LLM Tool Choice with retries
            try:
                raw_call = choose_tool(
                    state,
                    language=lang,
                    provider=ai_provider,
                    gemini_api_key=gemini_api_key,
                    gemini_model=gemini_model,
                )
                consecutive_llm_errors = 0
            except (OllamaError, GeminiError, LLMError) as exc:
                consecutive_llm_errors += 1
                log_lines.append(f"AI Provider error (retry {consecutive_llm_errors}/{max_llm_retries}): {exc}")
                if consecutive_llm_errors >= max_llm_retries:
                    result.error = str(exc)
                    loop_failure_reason = "LLM_ERROR"
                    break
                time.sleep(0.3)
                continue

            # 2. Handle Malformed JSON gracefully without discarding step budget
            if raw_call.get("_parse_error") or raw_call.get("tool") is None:
                consecutive_parse_errors += 1
                policy_fails += 1
                obs = sanitize_tool_output(
                    f"Model did not return valid JSON. Respond strictly with a single JSON object with 'thought', 'tool', and 'args'. (Attempt {consecutive_parse_errors}/{max_parse_retries})",
                    "orchestrator",
                )
                memory.append(obs)
                _log_step(log_lines, attempt, raw_call.get("thought", ""), "invalid_json", obs)
                if policy_fails >= max_policy_fails or consecutive_parse_errors >= max_parse_retries:
                    loop_failure_reason = "MAX_POLICY_FAILS"
                    break
                continue
            consecutive_parse_errors = 0

            # 3. Policy Gateway Validation
            ok, reason, call = validate_tool_call(raw_call)
            if not ok:
                policy_fails += 1
                obs = sanitize_tool_output(f"Policy rejection: {reason}", "policy")
                memory.append(obs)
                _log_step(log_lines, attempt, raw_call.get("thought", ""), str(raw_call.get("tool")), obs)
                if policy_fails >= max_policy_fails:
                    loop_failure_reason = "MAX_POLICY_FAILS"
                    break
                continue

            tool = call["tool"]
            args = call["args"]
            thought = call["thought"]

            # 4. Resource & Budget Monitor
            budget_ok, budget_reason = budget_tracker.record_usage(len(thought) + len(str(args)))
            if not budget_ok:
                obs = sanitize_tool_output(budget_reason, "execution_guard")
                memory.append(obs)
                _log_step(log_lines, attempt, thought, "budget_limit", obs)
                loop_failure_reason = "BUDGET_EXHAUSTED"
                break

            # 5. Non-destructive Loop Detection with warning before termination
            if tool != "finish":
                is_loop, loop_msg = loop_detector.record_and_check(tool, args)
                if is_loop:
                    consecutive_loops += 1
                    if consecutive_loops >= 2:
                        obs = sanitize_tool_output(f"{loop_msg} Halting ReAct loop to prevent infinite cycling.", "loop_detector")
                        memory.append(obs)
                        _log_step(log_lines, attempt, thought, tool, obs)
                        loop_failure_reason = "LOOP_TERMINATED"
                        break
                    else:
                        obs = sanitize_tool_output(
                            f"{loop_msg} Notice: Redundant identical call to '{tool}'. Please proceed with 'validate_fix' or 'finish'.",
                            "loop_detector",
                        )
                        memory.append(obs)
                        _log_step(log_lines, attempt, thought, tool, obs)
                        continue
            consecutive_loops = 0

            # 6. Execute Valid Tool Call (Advances successful tool step count)
            if tool == "compile":
                successful_tool_steps += 1
                if not has_new_fix and cached_compile is not None:
                    observation = cached_compile + "\n(Code unchanged since last compile; cached result returned.)"
                else:
                    st, out, err = compile_source(job)
                    result.compile_status = st
                    result.last_stdout, result.last_stderr = out, err
                    observation = sanitize_tool_output(
                        f"compile_exit={st}\nstdout:\n{out}\nstderr:\n{err}", "compile"
                    )
                    if st != 0:
                        cat, strat = classify_error(err or out, language=lang)
                        observation += f"\nClassifier hint: {cat} / {strat}"
                    cached_compile = observation
                    has_new_fix = False

            elif tool == "run":
                successful_tool_steps += 1
                if result.compile_status != 0:
                    observation = sanitize_tool_output(
                        "Cannot run: compilation failed (no runnable target exists). "
                        f"Call 'validate_fix' with the complete corrected {adapter.display_name} source code.",
                        "orchestrator",
                    )
                else:
                    current_stdin = args.get("stdin", stdin)
                    if not has_new_fix and cached_run is not None and current_stdin == last_run_stdin:
                        observation = cached_run + "\n(Binary unchanged; cached execution result returned.)"
                    else:
                        st, out, err = run_binary(job, stdin=current_stdin)
                        result.last_stdout, result.last_stderr = out, err
                        last_run_stdin = current_stdin
                        observation = sanitize_tool_output(
                            f"run_exit={st}\nstdout:\n{out}\nstderr:\n{err}", "run"
                        )
                        if st != 0:
                            cat, strat = classify_error(err or out, language=lang)
                            observation += f"\nClassifier hint: {cat} / {strat}"
                        cached_run = observation

            elif tool == "lldb":
                successful_tool_steps += 1
                if lang not in ("cpp", "c"):
                    observation = sanitize_tool_output(
                        f"LLDB debugger is only available for C and C++ programs. Current language is {adapter.display_name}.",
                        "orchestrator",
                    )
                elif result.compile_status != 0:
                    observation = sanitize_tool_output(
                        "Cannot run lldb: compilation failed. Call 'validate_fix' with corrected code.",
                        "orchestrator",
                    )
                else:
                    text = execute_lldb_command(job, args["command"])
                    observation = sanitize_tool_output(text, "lldb")

            elif tool == "validate_fix":
                successful_tool_steps += 1
                has_new_fix = True
                result.fix_generated = True

                raw_candidate = args.get("code", "")
                extracted = extract_code(raw_candidate, language=lang) or str(raw_candidate)

                accepted, code, msg = validate_fix(
                    job,
                    extracted,
                    language=lang,
                    stdin=stdin,
                    test_cases=test_cases,
                )
                observation = sanitize_tool_output(
                    f"accepted={accepted}\n{msg}", "validate_fix"
                )

                if accepted:
                    verified_code = code
                    result.verified = True
                    result.fix_compiled = True
                    result.fix_passed_tests = True
                    result.verified_fix = code
                    observation += (
                        "\nFix is verified and accepted! Call tool 'finish' now with "
                        "root_cause, fixed_code, confidence='high', and learning_note."
                    )
                else:
                    # Check whether fix at least compiles without test suite failures
                    acc_raw, raw_code, raw_msg = validate_fix(job, extracted, language=lang, stdin=stdin, test_cases=None)
                    if acc_raw:
                        result.fix_compiled = True
                        if not verified_code:
                            verified_code = raw_code
                            result.verified_fix = raw_code
                    elif not verified_code and extracted.strip():
                        # Preserve candidate fix for user inspection even if unverified
                        result.verified_fix = extracted.strip()

                    observation += (
                        "\nFix failed validation. Inspect the compiler or execution error above and "
                        f"call 'validate_fix' with another corrected complete {adapter.display_name} source."
                    )

            else:  # finish
                successful_tool_steps += 1
                result.finished = True
                result.diagnosis_completed = True
                result.root_cause = sanitize_plain(args.get("root_cause", ""))
                result.summary = sanitize_plain(args.get("summary", ""))
                result.confidence = sanitize_plain(args.get("confidence", "high")) or "high"
                result.learning_note = sanitize_plain(args.get("learning_note", ""))
                result.bugs = args.get("bugs") or []

                raw_cand = args.get("fixed_code", "")
                candidate = (extract_code(raw_cand, language=lang) or str(raw_cand)).strip()

                if candidate:
                    result.fix_generated = True
                    if result.verified and verified_code:
                        result.verified_fix = verified_code
                    else:
                        accepted, code, msg = validate_fix(
                            job,
                            candidate,
                            language=lang,
                            stdin=stdin,
                            test_cases=test_cases,
                        )
                        observation = sanitize_tool_output(
                            f"finish requested. post-check accepted={accepted}\n{msg}",
                            "validate_fix",
                        )
                        _log_step(log_lines, attempt, thought, "finish", observation)
                        memory.append(observation)

                        if accepted:
                            result.verified = True
                            result.fix_compiled = True
                            result.fix_passed_tests = True
                            result.verified_fix = code
                        else:
                            acc_no_tests, code_no_tests, _ = validate_fix(
                                job,
                                candidate,
                                language=lang,
                                stdin=stdin,
                                test_cases=None,
                            )
                            if acc_no_tests:
                                result.fix_compiled = True
                                result.verified = False
                                result.verified_fix = code_no_tests
                                result.confidence = "medium"
                            elif verified_code:
                                result.verified_fix = verified_code
                            else:
                                result.verified_fix = candidate
                                result.verified = False
                                if result.confidence == "high":
                                    result.confidence = "medium"
                elif verified_code:
                    result.verified_fix = verified_code
                else:
                    observation = sanitize_tool_output("finish called without fixed_code (security-only report)", "finish")
                    _log_step(log_lines, attempt, thought, "finish", observation)
                break

            memory.append(f"Observation after {tool}:\n{observation}")
            _log_step(log_lines, attempt, thought, tool, observation)

        result.steps_completed = successful_tool_steps
        if not result.verified_fix and verified_code:
            result.verified_fix = verified_code

        # ------------------------------------------------------------------
        # STAGES 8 & 9: Security Report Generation & Secure Code Recommendations
        # (Deterministic synthesis fallback guarantees complete, structured diagnosis)
        # ------------------------------------------------------------------
        synth_rc, synth_sum, synth_bugs, synth_recs = generate_security_report(
            raw_cwe_findings,
            language=lang,
            compile_status=result.compile_status,
            runtime_status=r_stat if c_status == 0 else None,
        )

        if not result.finished and not loop_failure_reason:
            loop_failure_reason = "STEP_CAP_EXHAUSTION"

        if not result.root_cause:
            if result.verified and result.verified_fix:
                result.root_cause = (
                    f"Identified vulnerabilities and bugs across the {adapter.display_name} source code. "
                    "A working, memory-safe fix was verified in the sandbox."
                )
                result.summary = synth_sum or "Verified Solution."
                result.confidence = "high"
                result.learning_note = synth_recs or "Inspect the verified fix above to see how each error was resolved."
            else:
                result.root_cause = synth_rc
                result.summary = synth_sum
                result.confidence = "medium"
                result.learning_note = synth_recs
            result.diagnosis_completed = True

        if not result.summary:
            result.summary = synth_sum

        if not result.recommendations:
            result.recommendations = synth_recs

        if not result.learning_note:
            result.learning_note = synth_recs

        # Populate bugs array from findings if empty
        if not result.bugs:
            if synth_bugs:
                result.bugs = synth_bugs
            elif result.root_cause:
                lines = [l.strip() for l in result.root_cause.split("\n") if l.strip()]
                extracted_items = []
                for l in lines:
                    if re.match(r"^(\d+[\.\)]|[\*\-\•])\s+", l):
                        text = re.sub(r"^(\d+[\.\)]|[\*\-\•])\s+", "", l)
                        extracted_items.append({
                            "location": "Identified Bug",
                            "type": "Security / Logic",
                            "description": text,
                            "fix_applied": "Resolved in verified fix" if result.verified_fix else "",
                        })
                if extracted_items:
                    result.bugs = extracted_items

        # Track Stage 8 and Stage 9 statuses based on actual generation
        if result.root_cause and result.summary:
            _set_stage_status(result, SECURITY_ANALYSIS_STAGES[7], STAGE_COMPLETED)
        else:
            _set_stage_status(result, SECURITY_ANALYSIS_STAGES[7], STAGE_FAILED)

        if result.recommendations or result.learning_note:
            _set_stage_status(result, SECURITY_ANALYSIS_STAGES[8], STAGE_COMPLETED)
        else:
            _set_stage_status(result, SECURITY_ANALYSIS_STAGES[8], STAGE_FAILED)

        # Set distinct failure reasons without overwriting meaningful prior causes
        if result.failure_reason:
            pass  # Keep prior error (e.g. SANDBOX_INITIALIZATION_ERROR)
        elif loop_failure_reason:
            result.failure_reason = loop_failure_reason
        elif initial_failure_reason and not result.verified:
            result.failure_reason = initial_failure_reason
        else:
            result.failure_reason = ""

        if result.verified_fix:
            result.fix_generated = True

        result.current_stage = (
            "Complete" if (len(result.stages_completed) == 9 and result.finished) else "Diagnosis Complete"
        )

        if enable_audit:
            from audit_logger import log_interaction

            log_interaction(
                user_prompt=f"Compile & Analyze ({adapter.display_name})",
                llm_response=result.root_cause,
                code_snippet=source_code,
                error_category="agent_job",
                fixed_code=result.verified_fix or "N/A",
            )

    finally:
        job.close()

    result.agent_log = "\n".join(log_lines)
    return result
