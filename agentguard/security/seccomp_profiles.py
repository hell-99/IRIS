"""
IRIS — Per-Tool Seccomp Allowlists

Each IRIS tool is granted only the Linux syscalls required for its legitimate
function. This enforces the principle of least privilege at the kernel level:
a compromised tool cannot make syscalls outside its declared allowlist.

Profiles are used two ways:
  1. Runtime enforcement via tool_sandbox.py (resource limits + prctl)
  2. Docker seccomp JSON generation via generate_docker_profile()

Tool isolation model:
  read_file       → filesystem reads only,  no network,  no fork
  write_file      → filesystem writes only, no network,  no fork
  query_db        → SQLite (file I/O + locking), no network, no fork
  call_api        → minimal (simulated in demo mode, no real network)
  execute_command → minimal (simulated, execve blocked)
  list_users      → minimal (returns static data)
  modify_permissions → minimal (simulated)
"""

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ToolSeccompProfile:
    tool_name:       str
    description:     str
    allowed_syscalls: list
    cpu_seconds:     int   = 5
    memory_mb:       int   = 64
    max_fds:         int   = 32
    timeout_sec:     float = 5.0


# Syscall groups — each tool gets the minimal set for its function

_FS_READ = [
    "read", "pread64", "readv",
    "open", "openat", "close",
    "stat", "fstat", "lstat", "newfstatat", "statx",
    "access", "faccessat",
    "lseek", "getcwd",
    "readlink", "readlinkat",
    "mmap", "mprotect", "munmap", "brk",
    "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
    "getuid", "getgid", "geteuid", "getegid",
    "getpid", "gettid",
    "exit", "exit_group",
    "futex", "ioctl", "fcntl",
]

_FS_WRITE_EXTRA = [
    "write", "pwrite64", "writev",
    "mkdir", "mkdirat",
    "creat", "unlink", "unlinkat",
    "rename", "renameat", "renameat2",
    "chmod", "fchmod",
    "ftruncate", "truncate",
]

_DB_EXTRA = [
    "write", "pwrite64",
    "flock", "fdatasync", "fsync",
    "ftruncate", "truncate",
    "getdents", "getdents64",
    "sendfile",
]

_MINIMAL = [
    "read", "write",
    "mmap", "mprotect", "munmap", "brk",
    "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
    "exit", "exit_group",
    "futex", "getpid", "gettid",
]

TOOL_PROFILES: dict[str, ToolSeccompProfile] = {
    "read_file": ToolSeccompProfile(
        tool_name        = "read_file",
        description      = "Filesystem reads only — no network, no writes, no process creation",
        allowed_syscalls = _FS_READ,
        cpu_seconds      = 2,
        memory_mb        = 32,
        max_fds          = 16,
        timeout_sec      = 3.0,
    ),
    "write_file": ToolSeccompProfile(
        tool_name        = "write_file",
        description      = "Filesystem read/write within sandbox — no network, no process creation",
        allowed_syscalls = _FS_READ + _FS_WRITE_EXTRA,
        cpu_seconds      = 2,
        memory_mb        = 32,
        max_fds          = 16,
        timeout_sec      = 3.0,
    ),
    "query_db": ToolSeccompProfile(
        tool_name        = "query_db",
        description      = "SQLite access — filesystem I/O + locking, no network, no fork",
        allowed_syscalls = _FS_READ + _DB_EXTRA,
        cpu_seconds      = 5,
        memory_mb        = 64,
        max_fds          = 32,
        timeout_sec      = 5.0,
    ),
    "call_api": ToolSeccompProfile(
        tool_name        = "call_api",
        description      = "Simulated API — minimal syscalls, no real network in demo mode",
        allowed_syscalls = _MINIMAL,
        cpu_seconds      = 2,
        memory_mb        = 32,
        max_fds          = 8,
        timeout_sec      = 3.0,
    ),
    "execute_command": ToolSeccompProfile(
        tool_name        = "execute_command",
        description      = "Simulated command execution — execve blocked, minimal syscalls only",
        allowed_syscalls = _MINIMAL,
        cpu_seconds      = 2,
        memory_mb        = 32,
        max_fds          = 8,
        timeout_sec      = 3.0,
    ),
    "list_users": ToolSeccompProfile(
        tool_name        = "list_users",
        description      = "Returns static user list — minimal syscalls",
        allowed_syscalls = _MINIMAL,
        cpu_seconds      = 1,
        memory_mb        = 16,
        max_fds          = 4,
        timeout_sec      = 2.0,
    ),
    "modify_permissions": ToolSeccompProfile(
        tool_name        = "modify_permissions",
        description      = "Simulated permission update — minimal syscalls",
        allowed_syscalls = _MINIMAL,
        cpu_seconds      = 1,
        memory_mb        = 16,
        max_fds          = 4,
        timeout_sec      = 2.0,
    ),
}

DEFAULT_PROFILE = ToolSeccompProfile(
    tool_name        = "unknown",
    description      = "Default fallback — filesystem read allowlist",
    allowed_syscalls = _FS_READ,
    cpu_seconds      = 3,
    memory_mb        = 64,
    max_fds          = 16,
    timeout_sec      = 5.0,
)


def get_profile(tool_name: str) -> ToolSeccompProfile:
    return TOOL_PROFILES.get(tool_name, DEFAULT_PROFILE)


# Syscalls the Python interpreter needs at startup/import time,
# beyond what individual tools require.
_PYTHON_RUNTIME = [
    "arch_prctl", "set_tid_address", "set_robust_list",
    "prlimit64", "getrlimit", "setrlimit",
    "uname", "statfs",
    "execve",                           # needed for initial process launch only
    "clone", "fork", "vfork",           # needed by multiprocessing
    "wait4", "waitid", "waitpid",
    "getppid", "getpgrp", "setsid",
    "getgroups",
    "umask", "chdir", "fchdir",
    "pipe", "pipe2",
    "dup", "dup2", "dup3",
    "socket", "connect", "bind", "listen", "accept", "accept4",
    "getsockname", "getpeername",
    "sendto", "recvfrom", "sendmsg", "recvmsg",
    "getsockopt", "setsockopt", "shutdown",
    "select", "pselect6", "poll", "ppoll",
    "epoll_create", "epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait",
    "nanosleep", "clock_nanosleep",
    "clock_gettime", "clock_getres", "gettimeofday", "time", "times",
    "getrusage", "sysinfo",
    "kill", "tgkill", "tkill",
    "madvise", "mincore", "mlock", "munlock",
    "prctl", "capget", "capset",
    "inotify_init1", "inotify_add_watch", "inotify_rm_watch",
    "eventfd2", "signalfd4",
    "timerfd_create", "timerfd_settime", "timerfd_gettime",
    "memfd_create", "getrandom", "rseq",
    "copy_file_range",
    "mkdir", "mkdirat", "rmdir",
    "symlink", "symlinkat", "link", "linkat",
    "unlink", "unlinkat",
    "rename", "renameat", "renameat2",
    "chmod", "fchmod", "chown", "fchown", "lchown",
    "getdents", "getdents64",
    "sendfile",
]

# Syscalls blocked regardless of what any tool claims to need.
# These are privilege escalation and container escape vectors.
BLOCKED_DANGEROUS = [
    "ptrace",             # debugger attachment / memory inspection
    "process_vm_readv",   # cross-process memory read
    "process_vm_writev",  # cross-process memory write
    "kexec_load",         # load new kernel image
    "kexec_file_load",    # load new kernel image (file descriptor variant)
    "init_module",        # kernel module insertion
    "finit_module",       # kernel module insertion (fd variant)
    "delete_module",      # kernel module removal
    "mount",              # filesystem mount (container escape)
    "umount2",            # filesystem unmount
    "pivot_root",         # container escape via root pivot
    "chroot",             # partial isolation bypass
    "swapon",             # swap device management
    "swapoff",            # swap device management
    "reboot",             # system reboot
    "syslog",             # kernel ring buffer access
    "acct",               # process accounting (info disclosure)
    "settimeofday",       # system clock manipulation
    "adjtimex",           # clock skew (log tampering aid)
    "clock_settime",      # clock manipulation
    "nfsservctl",         # NFS server control
    "perf_event_open",    # hardware perf counters (side-channel)
    "bpf",                # Berkeley Packet Filter (privilege escalation)
    "userfaultfd",        # user-space page fault handler (escape vector)
    "add_key",            # kernel keyring write
    "request_key",        # kernel keyring read
    "keyctl",             # kernel keyring management
    "io_uring_setup",     # io_uring (container escape research vector)
    "io_uring_enter",
    "io_uring_register",
    "lookup_dcookie",     # profiling filesystem cookie
    "mbind",              # NUMA memory policy
    "migrate_pages",      # NUMA page migration
    "move_pages",         # NUMA page migration
]


def generate_docker_profile() -> dict:
    """
    Generate a Docker-compatible seccomp JSON profile for the IRIS container.

    Strategy: deny-by-default (SCMP_ACT_ERRNO), explicitly allow the union
    of all tool allowlists plus Python runtime requirements, with dangerous
    syscalls removed even if they appear in a tool allowlist.

    Output is suitable for:
        docker run --security-opt seccomp=docker/seccomp/iris.json ...
        (or the security_opt field in docker-compose.yml)
    """
    # Union of all tool allowlists + Python runtime
    allowed: set[str] = set(_PYTHON_RUNTIME)
    for p in TOOL_PROFILES.values():
        allowed.update(p.allowed_syscalls)

    # Strip dangerous syscalls — these are never allowed regardless
    allowed -= set(BLOCKED_DANGEROUS)

    return {
        "defaultAction": "SCMP_ACT_ERRNO",
        "architectures": [
            "SCMP_ARCH_X86_64",
            "SCMP_ARCH_X86",
            "SCMP_ARCH_X32",
            "SCMP_ARCH_AARCH64",
        ],
        "syscalls": [
            {
                "names":   sorted(allowed),
                "action":  "SCMP_ACT_ALLOW",
                "comment": "IRIS agent sandbox — union of tool allowlists + Python runtime",
            },
        ],
    }


def write_docker_profile(path: str = "docker/seccomp/iris.json"):
    """Write the Docker seccomp JSON profile to disk."""
    profile = generate_docker_profile()
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(profile, indent=2))
    print(f"[seccomp] Written {len(profile['syscalls'][0]['names'])} allowed syscalls → {out}")
    print(f"[seccomp] {len(BLOCKED_DANGEROUS)} dangerous syscalls explicitly removed")
    return profile


if __name__ == "__main__":
    write_docker_profile()
    print("\nPer-tool profiles:")
    for name, p in TOOL_PROFILES.items():
        print(f"  {name:20s}  {len(p.allowed_syscalls):3d} syscalls  "
              f"cpu={p.cpu_seconds}s  mem={p.memory_mb}MB  timeout={p.timeout_sec}s")
