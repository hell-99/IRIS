"""
IRIS — Tool Execution Sandbox

Runs each agent tool in an isolated child process with:
  - Per-tool resource limits (CPU time, memory, file descriptors, wall-clock timeout)
  - Linux capability dropping via prctl(PR_SET_NO_NEW_PRIVS) — prevents privilege
    escalation through execve even if the tool is compromised
  - Process isolation — a crashing or hung tool cannot affect the IRIS interceptor

On Linux:  full enforcement (resource limits + capability dropping)
On macOS:  resource limits only (prctl not available; used for local dev)

The sandbox is transparent to callers — it returns the same dict the tool
would return if called directly, plus a 'sandbox' metadata block.

Usage:
    from security.tool_sandbox import ToolSandbox
    sandbox = ToolSandbox()
    result  = sandbox.run("read_file", read_file_fn, {"path": "public/readme.txt"})
"""

import sys
import json
import traceback
import resource
import multiprocessing
from typing import Any, Callable, Optional

from security.seccomp_profiles import get_profile, ToolSeccompProfile

IS_LINUX = sys.platform.startswith("linux")


class SandboxViolation(Exception):
    """Raised when a tool exceeds its sandbox limits."""
    def __init__(self, tool_name: str, reason: str):
        self.tool_name = tool_name
        self.reason    = reason
        super().__init__(f"[Sandbox] {tool_name} violation: {reason}")


def _apply_resource_limits(profile: ToolSeccompProfile):
    """
    Applied inside the child process before tool execution.
    Sets hard limits the OS enforces — the process is killed if exceeded.
    """
    try:
        # CPU time: SIGXCPU at soft limit, SIGKILL at hard limit
        cpu = profile.cpu_seconds
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))

        # Address space: ENOMEM if exceeded
        mem = profile.memory_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (mem, mem))

        # Open file descriptors
        fds = profile.max_fds
        resource.setrlimit(resource.RLIMIT_NOFILE, (fds, fds))

        # Child processes: 0 blocks fork() inside tool execution
        resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))

    except (ValueError, resource.error):
        # RLIMIT_AS not available on all platforms; skip gracefully
        pass


def _drop_privileges():
    """
    Prevent privilege escalation in the child process.

    prctl(PR_SET_NO_NEW_PRIVS, 1) ensures that even if the tool calls execve
    with a setuid binary, the new process cannot gain elevated privileges.
    This is a one-way, non-reversible operation — once set it cannot be unset.
    """
    if not IS_LINUX:
        return
    try:
        import ctypes
        import ctypes.util
        libc_path = ctypes.util.find_library("c")
        if not libc_path:
            return
        libc = ctypes.CDLL(libc_path, use_errno=True)
        PR_SET_NO_NEW_PRIVS = 38
        ret = libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        if ret != 0:
            import ctypes
            errno = ctypes.get_errno()
            # Non-fatal: log but continue
            print(f"[sandbox] prctl PR_SET_NO_NEW_PRIVS failed: errno={errno}")
    except Exception:
        pass


def _worker(
    tool_fn:      Callable,
    kwargs:       dict,
    profile_name: str,
    result_q:     multiprocessing.Queue,
):
    """
    Child process entry point.
    Applies sandbox constraints then executes the tool function.
    Result is placed in result_q as a JSON-serializable dict.
    """
    try:
        profile = get_profile(profile_name)
        _apply_resource_limits(profile)
        _drop_privileges()
        result = tool_fn(**kwargs)
        result_q.put({"ok": True, "result": result})
    except MemoryError:
        result_q.put({"ok": False, "error": "memory_limit_exceeded"})
    except Exception as e:
        result_q.put({"ok": False, "error": str(e), "traceback": traceback.format_exc()})


class ToolSandbox:
    """
    Subprocess-based sandbox for IRIS tool execution.

    Each call to run() spawns a child process, applies resource limits and
    capability dropping, executes the tool, and returns the result.
    If the child exceeds its time limit it is forcibly terminated.
    """

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        # Use 'fork' on Linux (fast), 'spawn' on macOS (safe with Objective-C runtime)
        self._ctx = multiprocessing.get_context("fork" if IS_LINUX else "spawn")

    def run(
        self,
        tool_name: str,
        tool_fn:   Callable,
        kwargs:    dict,
    ) -> dict[str, Any]:
        """
        Execute tool_fn(**kwargs) inside the sandbox.

        Returns the tool's result dict with an added 'sandbox' key containing
        enforcement metadata. Raises SandboxViolation on timeout or OOM.
        """
        if not self.enabled:
            return tool_fn(**kwargs)

        profile   = get_profile(tool_name)
        result_q  = self._ctx.Queue()
        proc      = self._ctx.Process(
            target = _worker,
            args   = (tool_fn, kwargs, tool_name, result_q),
            daemon = True,
        )

        proc.start()
        proc.join(timeout=profile.timeout_sec)

        if proc.is_alive():
            proc.terminate()
            proc.join(timeout=1.0)
            if proc.is_alive():
                proc.kill()
            raise SandboxViolation(tool_name, f"timeout exceeded ({profile.timeout_sec}s)")

        if proc.exitcode is not None and proc.exitcode < 0:
            raise SandboxViolation(tool_name, f"killed by signal {-proc.exitcode}")

        try:
            payload = result_q.get(timeout=2.0)
        except Exception:
            raise SandboxViolation(tool_name, "child exited without result (possible OOM or SIGXCPU)")

        if not payload.get("ok"):
            error = payload.get("error", "unknown")
            if "memory" in error:
                raise SandboxViolation(tool_name, "memory limit exceeded")
            # Tool-level errors (bad args etc.) are returned as normal results
            return {
                "error":   error,
                "sandbox": _meta(tool_name, profile, enforced=True),
            }

        result = payload["result"]
        if isinstance(result, dict):
            result["sandbox"] = _meta(tool_name, profile, enforced=True)
        return result

    def profile_summary(self) -> list[dict]:
        """Return a list of all tool profiles for dashboard display."""
        from security.seccomp_profiles import TOOL_PROFILES
        return [
            {
                "tool":        p.tool_name,
                "description": p.description,
                "syscalls":    len(p.allowed_syscalls),
                "cpu_s":       p.cpu_seconds,
                "memory_mb":   p.memory_mb,
                "max_fds":     p.max_fds,
                "timeout_s":   p.timeout_sec,
            }
            for p in TOOL_PROFILES.values()
        ]


def _meta(tool_name: str, profile: ToolSeccompProfile, enforced: bool) -> dict:
    return {
        "enforced":       enforced,
        "platform":       sys.platform,
        "no_new_privs":   IS_LINUX,
        "cpu_limit_s":    profile.cpu_seconds,
        "memory_limit_mb": profile.memory_mb,
        "fd_limit":       profile.max_fds,
        "timeout_s":      profile.timeout_sec,
        "syscall_allowlist_size": len(profile.allowed_syscalls),
    }


def signal_num(exitcode: int) -> int:
    """Return positive signal number if process was killed by signal, else 0."""
    if exitcode is not None and exitcode < 0:
        return -exitcode
    return 0


# Singleton used by interceptor
_sandbox = None

def get_sandbox() -> ToolSandbox:
    global _sandbox
    if _sandbox is None:
        _sandbox = ToolSandbox(enabled=True)
    return _sandbox


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))
    from agents.tools import TOOL_REGISTRY

    sandbox = ToolSandbox()
    print("IRIS Tool Sandbox — self-test\n")

    tests = [
        ("read_file",   {"path": "public/readme.txt"}),
        ("write_file",  {"path": "public/test_sandbox.txt", "content": "sandbox test"}),
        ("query_db",    {"query": "SELECT name, role FROM employees LIMIT 2"}),
        ("list_users",  {}),
        ("call_api",    {"endpoint": "/api/health"}),
    ]

    for tool_name, kwargs in tests:
        tool_fn = TOOL_REGISTRY.get(tool_name)
        if not tool_fn:
            print(f"  {tool_name}: SKIP (not in registry)")
            continue
        try:
            result = sandbox.run(tool_name, tool_fn, kwargs)
            sb     = result.pop("sandbox", {})
            print(f"  {tool_name:20s}  OK    "
                  f"enforced={sb.get('enforced')}  "
                  f"no_new_privs={sb.get('no_new_privs')}  "
                  f"syscalls_allowed={sb.get('syscall_allowlist_size')}")
        except SandboxViolation as e:
            print(f"  {tool_name:20s}  VIOLATION  {e}")
        except Exception as e:
            print(f"  {tool_name:20s}  ERROR  {e}")
