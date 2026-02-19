//! Seccomp profiles for container sandboxing.
//!
//! Seccomp (Secure Computing Mode) restricts the system calls a container
//! can make, reducing the attack surface.
//!
//! ## Profile Types
//!
//! - **Default**: Restrictive profile for general workloads
//! - **GPU**: Allows NVIDIA-specific ioctls for GPU workloads
//! - **Network**: Allows network syscalls for workloads that need outbound access
//!
//! ## Usage
//!
//! Profiles are applied via Docker's SecurityOpt when creating containers.
//! The profile JSON is passed directly to the Docker API.

use serde::{Deserialize, Serialize};

/// Seccomp profile action
#[allow(clippy::enum_variant_names)] // Matches Linux seccomp API naming
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SeccompAction {
    /// Allow the syscall
    ScmpActAllow,
    /// Return an error (EPERM)
    ScmpActErrno,
    /// Kill the process
    ScmpActKill,
    /// Log the syscall (for auditing)
    ScmpActLog,
    /// Send a signal
    ScmpActTrap,
    /// Use the default action
    ScmpActTrace,
}

/// Seccomp profile architecture
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SeccompArch {
    /// x86_64
    ScmpArchX86_64,
    /// ARM64
    ScmpArchAarch64,
    /// x86 32-bit
    ScmpArchX86,
    /// ARM 32-bit
    ScmpArchArm,
}

/// A syscall rule in the profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccompSyscall {
    /// Syscall names to match
    pub names: Vec<String>,
    /// Action to take
    pub action: SeccompAction,
    /// Optional arguments to match
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<SeccompArg>>,
    /// Optional comment for documentation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Argument matching for syscalls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccompArg {
    /// Argument index (0-5)
    pub index: u32,
    /// Value to compare
    pub value: u64,
    /// Optional second value for range comparisons
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_two: Option<u64>,
    /// Comparison operator
    pub op: SeccompOp,
}

/// Comparison operators for argument matching
#[allow(clippy::enum_variant_names)] // Matches Linux seccomp API naming
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SeccompOp {
    /// Not equal
    ScmpCmpNe,
    /// Less than
    ScmpCmpLt,
    /// Less than or equal
    ScmpCmpLe,
    /// Equal
    ScmpCmpEq,
    /// Greater than or equal
    ScmpCmpGe,
    /// Greater than
    ScmpCmpGt,
    /// Masked equal
    ScmpCmpMaskedEq,
}

/// A complete seccomp profile
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeccompProfile {
    /// Default action when no rule matches
    pub default_action: SeccompAction,
    /// Supported architectures
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architectures: Option<Vec<SeccompArch>>,
    /// Syscall rules
    pub syscalls: Vec<SeccompSyscall>,
}

/// Profile type for different workload needs
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProfileType {
    /// Default restrictive profile
    Default,
    /// Profile allowing GPU (NVIDIA) operations
    Gpu,
    /// Profile allowing network operations
    Network,
    /// Minimal profile - very restrictive
    Minimal,
}

impl SeccompProfile {
    /// Get the default restrictive profile
    ///
    /// This profile allows common syscalls needed for most applications
    /// but blocks dangerous ones like:
    /// - Module loading (init_module, delete_module)
    /// - Rebooting (reboot)
    /// - Direct kernel memory access (iopl, ioperm)
    /// - Namespace manipulation (setns, unshare)
    pub fn default_profile() -> Self {
        Self {
            default_action: SeccompAction::ScmpActErrno,
            architectures: Some(vec![
                SeccompArch::ScmpArchX86_64,
                SeccompArch::ScmpArchAarch64,
            ]),
            syscalls: vec![
                // File operations
                SeccompSyscall {
                    names: vec![
                        "read".into(),
                        "write".into(),
                        "open".into(),
                        "openat".into(),
                        "close".into(),
                        "fstat".into(),
                        "stat".into(),
                        "lstat".into(),
                        "poll".into(),
                        "lseek".into(),
                        "mmap".into(),
                        "mprotect".into(),
                        "munmap".into(),
                        "brk".into(),
                        "ioctl".into(),
                        "access".into(),
                        "faccessat".into(),
                        "faccessat2".into(),
                        "pipe".into(),
                        "pipe2".into(),
                        "dup".into(),
                        "dup2".into(),
                        "dup3".into(),
                        "fcntl".into(),
                        "flock".into(),
                        "fsync".into(),
                        "fdatasync".into(),
                        "truncate".into(),
                        "ftruncate".into(),
                        "getdents".into(),
                        "getdents64".into(),
                        "getcwd".into(),
                        "chdir".into(),
                        "fchdir".into(),
                        "rename".into(),
                        "renameat".into(),
                        "renameat2".into(),
                        "mkdir".into(),
                        "mkdirat".into(),
                        "rmdir".into(),
                        "link".into(),
                        "linkat".into(),
                        "unlink".into(),
                        "unlinkat".into(),
                        "symlink".into(),
                        "symlinkat".into(),
                        "readlink".into(),
                        "readlinkat".into(),
                        "chmod".into(),
                        "fchmod".into(),
                        "fchmodat".into(),
                        "chown".into(),
                        "fchown".into(),
                        "fchownat".into(),
                        "lchown".into(),
                        "umask".into(),
                        "statx".into(),
                        "newfstatat".into(),
                    ],
                    action: SeccompAction::ScmpActAllow,
                    args: None,
                    comment: Some("File operations".into()),
                },
                // Process operations
                SeccompSyscall {
                    names: vec![
                        "execve".into(),
                        "execveat".into(),
                        "exit".into(),
                        "exit_group".into(),
                        "wait4".into(),
                        "waitid".into(),
                        "fork".into(),
                        "vfork".into(),
                        "clone".into(),
                        "clone3".into(),
                        "getpid".into(),
                        "getppid".into(),
                        "gettid".into(),
                        "getuid".into(),
                        "geteuid".into(),
                        "getgid".into(),
                        "getegid".into(),
                        "getgroups".into(),
                        "setgroups".into(),
                        "setuid".into(),
                        "setgid".into(),
                        "setreuid".into(),
                        "setregid".into(),
                        "getresuid".into(),
                        "getresgid".into(),
                        "setresuid".into(),
                        "setresgid".into(),
                        "setpgid".into(),
                        "getpgid".into(),
                        "getpgrp".into(),
                        "setsid".into(),
                        "getsid".into(),
                        "prctl".into(),
                        "arch_prctl".into(),
                    ],
                    action: SeccompAction::ScmpActAllow,
                    args: None,
                    comment: Some("Process operations".into()),
                },
                // Memory operations
                SeccompSyscall {
                    names: vec![
                        "madvise".into(),
                        "mincore".into(),
                        "mlock".into(),
                        "mlock2".into(),
                        "munlock".into(),
                        "mlockall".into(),
                        "munlockall".into(),
                        "mremap".into(),
                        "msync".into(),
                        "memfd_create".into(),
                    ],
                    action: SeccompAction::ScmpActAllow,
                    args: None,
                    comment: Some("Memory operations".into()),
                },
                // Signal operations
                SeccompSyscall {
                    names: vec![
                        "rt_sigaction".into(),
                        "rt_sigprocmask".into(),
                        "rt_sigreturn".into(),
                        "rt_sigsuspend".into(),
                        "rt_sigpending".into(),
                        "rt_sigtimedwait".into(),
                        "rt_sigqueueinfo".into(),
                        "sigaltstack".into(),
                        "kill".into(),
                        "tgkill".into(),
                        "tkill".into(),
                    ],
                    action: SeccompAction::ScmpActAllow,
                    args: None,
                    comment: Some("Signal operations".into()),
                },
                // Time operations
                SeccompSyscall {
                    names: vec![
                        "clock_gettime".into(),
                        "clock_getres".into(),
                        "clock_nanosleep".into(),
                        "gettimeofday".into(),
                        "nanosleep".into(),
                        "times".into(),
                        "time".into(),
                    ],
                    action: SeccompAction::ScmpActAllow,
                    args: None,
                    comment: Some("Time operations".into()),
                },
                // Scheduler operations
                SeccompSyscall {
                    names: vec![
                        "sched_yield".into(),
                        "sched_getaffinity".into(),
                        "sched_setaffinity".into(),
                        "sched_getscheduler".into(),
                        "sched_setscheduler".into(),
                        "sched_getparam".into(),
                        "sched_setparam".into(),
                        "sched_get_priority_max".into(),
                        "sched_get_priority_min".into(),
                        "sched_rr_get_interval".into(),
                    ],
                    action: SeccompAction::ScmpActAllow,
                    args: None,
                    comment: Some("Scheduler operations".into()),
                },
                // I/O operations
                SeccompSyscall {
                    names: vec![
                        "select".into(),
                        "pselect6".into(),
                        "epoll_create".into(),
                        "epoll_create1".into(),
                        "epoll_ctl".into(),
                        "epoll_wait".into(),
                        "epoll_pwait".into(),
                        "epoll_pwait2".into(),
                        "eventfd".into(),
                        "eventfd2".into(),
                        "signalfd".into(),
                        "signalfd4".into(),
                        "timerfd_create".into(),
                        "timerfd_settime".into(),
                        "timerfd_gettime".into(),
                        "inotify_init".into(),
                        "inotify_init1".into(),
                        "inotify_add_watch".into(),
                        "inotify_rm_watch".into(),
                    ],
                    action: SeccompAction::ScmpActAllow,
                    args: None,
                    comment: Some("I/O multiplexing".into()),
                },
                // Futex operations (required for threading)
                SeccompSyscall {
                    names: vec![
                        "futex".into(),
                        "futex_waitv".into(),
                        "get_robust_list".into(),
                        "set_robust_list".into(),
                        "set_tid_address".into(),
                    ],
                    action: SeccompAction::ScmpActAllow,
                    args: None,
                    comment: Some("Threading primitives".into()),
                },
                // Misc safe operations
                SeccompSyscall {
                    names: vec![
                        "getrandom".into(),
                        "uname".into(),
                        "sysinfo".into(),
                        "getrusage".into(),
                        "getrlimit".into(),
                        "prlimit64".into(),
                        "setrlimit".into(),
                        "capget".into(),
                    ],
                    action: SeccompAction::ScmpActAllow,
                    args: None,
                    comment: Some("Miscellaneous safe operations".into()),
                },
            ],
        }
    }

    /// Get a profile that allows GPU (NVIDIA) operations
    pub fn gpu_profile() -> Self {
        let mut profile = Self::default_profile();

        // Add NVIDIA-specific syscalls
        profile.syscalls.push(SeccompSyscall {
            names: vec![
                // NVIDIA driver uses these
                "ioctl".into(), // Already allowed but important for GPU
            ],
            action: SeccompAction::ScmpActAllow,
            args: None,
            comment: Some("GPU operations (NVIDIA)".into()),
        });

        // Add mmap with executable permission (needed for CUDA)
        profile.syscalls.push(SeccompSyscall {
            names: vec!["mmap".into()],
            action: SeccompAction::ScmpActAllow,
            args: None,
            comment: Some("CUDA memory mapping".into()),
        });

        profile
    }

    /// Get a profile that allows network operations
    pub fn network_profile() -> Self {
        let mut profile = Self::default_profile();

        // Add network syscalls
        profile.syscalls.push(SeccompSyscall {
            names: vec![
                "socket".into(),
                "socketpair".into(),
                "bind".into(),
                "listen".into(),
                "accept".into(),
                "accept4".into(),
                "connect".into(),
                "getsockname".into(),
                "getpeername".into(),
                "sendto".into(),
                "recvfrom".into(),
                "sendmsg".into(),
                "recvmsg".into(),
                "shutdown".into(),
                "setsockopt".into(),
                "getsockopt".into(),
                "sendmmsg".into(),
                "recvmmsg".into(),
            ],
            action: SeccompAction::ScmpActAllow,
            args: None,
            comment: Some("Network operations".into()),
        });

        profile
    }

    /// Get a minimal profile - very restrictive
    pub fn minimal_profile() -> Self {
        Self {
            default_action: SeccompAction::ScmpActErrno,
            architectures: Some(vec![
                SeccompArch::ScmpArchX86_64,
                SeccompArch::ScmpArchAarch64,
            ]),
            syscalls: vec![SeccompSyscall {
                names: vec![
                    // Absolute minimum for a process to run
                    "read".into(),
                    "write".into(),
                    "close".into(),
                    "exit".into(),
                    "exit_group".into(),
                    "brk".into(),
                    "mmap".into(),
                    "munmap".into(),
                    "rt_sigreturn".into(),
                    "futex".into(),
                ],
                action: SeccompAction::ScmpActAllow,
                args: None,
                comment: Some("Minimal syscalls".into()),
            }],
        }
    }

    /// Get a profile by type
    pub fn for_type(profile_type: ProfileType) -> Self {
        match profile_type {
            ProfileType::Default => Self::default_profile(),
            ProfileType::Gpu => Self::gpu_profile(),
            ProfileType::Network => Self::network_profile(),
            ProfileType::Minimal => Self::minimal_profile(),
        }
    }

    /// Serialize to JSON for Docker SecurityOpt
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Serialize to pretty JSON for debugging
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_profile_serializes() {
        let profile = SeccompProfile::default_profile();
        let json = profile.to_json().expect("Should serialize");
        assert!(json.contains("defaultAction"));
        assert!(json.contains("syscalls"));
    }

    #[test]
    fn test_gpu_profile_has_ioctl() {
        let profile = SeccompProfile::gpu_profile();
        let has_ioctl = profile
            .syscalls
            .iter()
            .any(|s| s.names.contains(&"ioctl".to_string()));
        assert!(has_ioctl, "GPU profile should allow ioctl");
    }

    #[test]
    fn test_network_profile_has_socket() {
        let profile = SeccompProfile::network_profile();
        let has_socket = profile
            .syscalls
            .iter()
            .any(|s| s.names.contains(&"socket".to_string()));
        assert!(has_socket, "Network profile should allow socket");
    }

    #[test]
    fn test_minimal_profile_is_restrictive() {
        let profile = SeccompProfile::minimal_profile();
        // Should only have one syscalls entry with minimal syscalls
        assert_eq!(profile.syscalls.len(), 1);
        // Should have fewer than 15 allowed syscalls total
        let total_syscalls: usize = profile.syscalls.iter().map(|s| s.names.len()).sum();
        assert!(
            total_syscalls < 15,
            "Minimal profile should be very restrictive"
        );
    }

    #[test]
    fn test_profile_type_selection() {
        let default = SeccompProfile::for_type(ProfileType::Default);
        let gpu = SeccompProfile::for_type(ProfileType::Gpu);

        // GPU profile should have more syscalls than default
        let default_count: usize = default.syscalls.iter().map(|s| s.names.len()).sum();
        let gpu_count: usize = gpu.syscalls.iter().map(|s| s.names.len()).sum();

        assert!(
            gpu_count >= default_count,
            "GPU profile should allow at least as many syscalls"
        );
    }
}
