import { BpfHelperReferenceItem, EbpfMacroReferenceItem } from '../types/ebpf';

export const BPF_HELPERS_CATALOG: BpfHelperReferenceItem[] = [
  // ============================================================================
  // PROCESS & TASK CONTEXT HELPERS
  // ============================================================================
  {
    id: 'helper-get-current-pid-tgid',
    helperIdOrType: 'BPF_FUNC_get_current_pid_tgid (#14)',
    name: 'bpf_get_current_pid_tgid()',
    category: 'Process & Task Context',
    minKernel: 'Linux 4.2+',
    signature: '__u64 bpf_get_current_pid_tgid(void)',
    returnValueSpec: '64-bit integer: upper 32 bits = TGID (user-space PID), lower 32 bits = TID (kernel thread ID).',
    allowedProgramTypes: ['kprobe', 'kretprobe', 'tracepoint', 'fentry', 'fexit', 'uprobe', 'lsm', 'cgroup'],
    shortSummary:
      'Returns the packed 64-bit Thread Group ID (process ID) and Thread ID of the task currently executing on the local CPU core.',
    whatItDoes: [
      'Reads the current CPU’s active struct task_struct pointer and packs task->tgid into bits [63:32] and task->pid into bits [31:0] of register R0.',
      'Critical Linux terminology nuance: what user space calls a "Process ID (PID)" (shown in ps or top) is called tgid (Thread Group ID) inside the Linux kernel! What the kernel calls task->pid is actually the individual Thread ID (TID). For the main thread of a process, TGID == TID; for spawned threads (via clone3/pthread_create), all threads share the same TGID in the upper 32 bits while having distinct TIDs in the lower 32 bits.'
    ],
    howItWorksUnderTheHood: [
      'Executes in ~3 nanoseconds by reading the per-CPU current_task variable (on x86_64 via the %gs segment register), fetching current->tgid and current->pid, and returning ((u64)tgid << 32) | (u32)pid.'
    ],
    whyUseInsteadOf: {
      alternative: 'Reading task->tgid via bpf_get_current_task() + bpf_probe_read_kernel()',
      explanation:
        'bpf_get_current_pid_tgid() is a single inline register instruction after JIT compilation and provides a unique 64-bit correlation key (pid_tgid) for matching sys_enter and sys_exit events per thread.'
    },
    verifierSafetyContract: [
      'Cannot be called from pure packet-driver hooks like XDP or TC ingress where no user process context is guaranteed (in softirq context, current points to whichever arbitrary process was interrupted or ksoftirqd!).',
      'Always shift right by 32 (bpf_get_current_pid_tgid() >> 32) when reporting the user-facing PID to Go userspace.'
    ],
    registerMapping: [
      { reg: 'R1–R5', meaning: 'Unused (takes void)' },
      { reg: 'R0 (Return)', meaning: '(__u64)tgid << 32 | (__u32)tid' }
    ],
    cExample: `__u64 id = bpf_get_current_pid_tgid();
__u32 pid = id >> 32;          // User-space Process ID (TGID)
__u32 tid = (__u32)id;         // Kernel Thread ID (TID)

// Use the full 64-bit id as a hash map key when correlating entry/exit per thread:
bpf_map_update_elem(&inflight_syscalls, &id, &start_ts, BPF_ANY);`,
    goNote: 'In Go structs passed to ringbuf/maps, store PID and TID as uint32 fields.'
  },

  {
    id: 'helper-get-current-uid-gid',
    helperIdOrType: 'BPF_FUNC_get_current_uid_gid (#15)',
    name: 'bpf_get_current_uid_gid()',
    category: 'Process & Task Context',
    minKernel: 'Linux 4.2+',
    signature: '__u64 bpf_get_current_uid_gid(void)',
    returnValueSpec: '64-bit integer: upper 32 bits = GID (Group ID), lower 32 bits = UID (User ID).',
    allowedProgramTypes: ['kprobe', 'kretprobe', 'tracepoint', 'fentry', 'fexit', 'uprobe', 'lsm'],
    shortSummary:
      'Returns the real User ID (UID) and Group ID (GID) of the current task in the initial user namespace.',
    whatItDoes: [
      'Fetches current_cred() from the running task_struct, converts the kernel KUID/KGID to the root user namespace via from_kuid(&init_user_ns, cred->uid), and packs (u64)gid << 32 | (u32)uid.'
    ],
    howItWorksUnderTheHood: [
      'Accesses current->cred under RCU protection and extracts uid.val (lower 32 bits) and gid.val (upper 32 bits).'
    ],
    whyUseInsteadOf: {
      alternative: 'Parsing /proc/<pid>/status in Go userspace after receiving an event',
      explanation:
        'A short-lived process (like a 2ms chmod or id command) will have already exited before your Go userspace reader can open /proc/<pid>/status! Capturing UID/GID synchronously inside the eBPF hook is race-free.'
    },
    verifierSafetyContract: [
      'Notice the bit-packing order is the opposite of pid_tgid: for uid_gid, UID is in the LOWER 32 bits (& 0xFFFFFFFF) and GID is in the UPPER 32 bits (>> 32)!'
    ],
    registerMapping: [
      { reg: 'R0 (Return)', meaning: '(__u64)gid << 32 | (__u32)uid' }
    ],
    cExample: `__u64 ug = bpf_get_current_uid_gid();
__u32 uid = (__u32)ug;         // Lower 32 bits = UID (0 is root)
__u32 gid = ug >> 32;          // Upper 32 bits = GID`,
    goNote: 'Map uid == 0 to "root" in your Go userspace telemetry enriquecer.'
  },

  {
    id: 'helper-get-current-comm',
    helperIdOrType: 'BPF_FUNC_get_current_comm (#16)',
    name: 'bpf_get_current_comm()',
    category: 'Process & Task Context',
    minKernel: 'Linux 4.2+',
    signature: 'long bpf_get_current_comm(void *buf, __u32 size_of_buf)',
    returnValueSpec: '0 on success, or negative error code (-EINVAL / -EFAULT) on failure.',
    allowedProgramTypes: ['kprobe', 'kretprobe', 'tracepoint', 'fentry', 'fexit', 'uprobe', 'lsm'],
    shortSummary:
      'Copies the 16-byte short executable name (task->comm, e.g., "nginx", "envoy", "kubelet") into a destination buffer.',
    whatItDoes: [
      'Safely copies up to TASK_COMM_LEN (16 bytes, always NUL-terminated) from current->comm into the stack or ringbuffer memory pointed to by buf.'
    ],
    howItWorksUnderTheHood: [
      'Calls strscpy_pad(buf, current->comm, size_of_buf) inside the kernel, ensuring that unused trailing bytes in buf are zeroed out so uninitialized kernel stack data cannot leak to user space.'
    ],
    whyUseInsteadOf: {
      alternative: 'Reading /proc/<pid>/comm from Go userspace',
      explanation:
        'Avoids the extra open/read/close syscalls in Go and guarantees the process name is captured even for short-lived processes.'
    },
    verifierSafetyContract: [
      'buf must point to writable stack memory or a reserved BPF map/ringbuf value, and size_of_buf must be a positive compile-time constant (typically 16).'
    ],
    registerMapping: [
      { reg: 'R1', meaning: 'void *buf (destination pointer)' },
      { reg: 'R2', meaning: '__u32 size_of_buf (typically 16)' },
      { reg: 'R0 (Return)', meaning: '0 on success, negative errno on error' }
    ],
    cExample: `char comm[16];
bpf_get_current_comm(&comm, sizeof(comm));`,
    goNote: 'Convert [16]byte to a Go string via unix.ByteSliceToString(ev.Comm[:]).'
  },

  {
    id: 'helper-get-current-task-btf',
    helperIdOrType: 'BPF_FUNC_get_current_task_btf (#158)',
    name: 'bpf_get_current_task_btf()',
    category: 'Process & Task Context',
    minKernel: 'Linux 5.11+',
    signature: 'struct task_struct *bpf_get_current_task_btf(void)',
    returnValueSpec: 'Typed BTF pointer (PTR_TO_BTF_ID) to the current struct task_struct.',
    allowedProgramTypes: ['kprobe', 'tracepoint', 'fentry', 'fexit', 'lsm', 'uprobe'],
    shortSummary:
      'Returns a BTF-verified pointer to current task_struct that allows direct pointer dereferencing (task->real_parent->tgid) without helper calls.',
    whatItDoes: [
      'Unlike the older bpf_get_current_task() (#35) which returns an untyped scalar unsigned long requiring bpf_probe_read_kernel() for every field, bpf_get_current_task_btf() returns a Verifier-tracked PTR_TO_BTF_ID.',
      'This enables the eBPF JIT compiler to emit direct native CPU memory loads (mov rax, [rdi + offset]) when walking task->real_parent, task->nsproxy, or task->mm!'
    ],
    howItWorksUnderTheHood: [
      'The Verifier validates field accesses against vmlinux BTF type information at load time, eliminating runtime helper call overhead.'
    ],
    whyUseInsteadOf: {
      alternative: 'bpf_get_current_task() + nested bpf_probe_read_kernel()',
      explanation:
        'Direct BTF pointer loads compile down to single CPU instructions instead of function calls and integrate seamlessly with BPF_CORE_READ().'
    },
    verifierSafetyContract: [
      'Requires a BTF-enabled kernel (Linux 5.11+) and vmlinux.h.'
    ],
    registerMapping: [
      { reg: 'R0 (Return)', meaning: 'PTR_TO_BTF_ID (struct task_struct *)' }
    ],
    cExample: `struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
__u32 ppid = BPF_CORE_READ(task, real_parent, tgid);`,
    goNote: 'cilium/ebpf automatically performs CO-RE field relocations on struct task_struct.'
  },

  // ============================================================================
  // MEMORY & POINTER PROBING HELPERS
  // ============================================================================
  {
    id: 'helper-probe-read-user-str',
    helperIdOrType: 'BPF_FUNC_probe_read_user_str (#114)',
    name: 'bpf_probe_read_user_str()',
    category: 'Memory & Pointer Probing',
    minKernel: 'Linux 5.5+',
    signature: 'long bpf_probe_read_user_str(void *dst, __u32 size, const void *unsafe_ptr)',
    returnValueSpec: 'Positive length of copied string (including NUL byte) on success, or negative errno (-EFAULT) on page fault.',
    allowedProgramTypes: ['kprobe', 'kretprobe', 'tracepoint', 'fentry', 'fexit', 'uprobe', 'lsm'],
    shortSummary:
      'Safely copies a NUL-terminated string from User-Space virtual memory (__user *) into eBPF stack or map memory.',
    whatItDoes: [
      'Reads up to size bytes from a user-space virtual address (unsafe_ptr) into dst, stopping at the first NUL (\\0) byte and guaranteeing that dst is always NUL-terminated.',
      'Temporarily disables hardware SMAP (Supervisor Mode Access Prevention) via stac/clac instructions on x86_64 and installs a kernel exception-table handler so that if unsafe_ptr is NULL, unmapped, or paged out to swap, the kernel catches the page fault gracefully and returns -EFAULT instead of crashing the OS!'
    ],
    howItWorksUnderTheHood: [
      'Wraps strncpy_from_user_nofault(dst, unsafe_ptr, size) with pagefault_disable(). If a minor/major page fault occurs, the CPU exception fixup table jumps out cleanly and zeroes the destination buffer.'
    ],
    whyUseInsteadOf: {
      alternative: 'Legacy bpf_probe_read() or bpf_probe_read_kernel_str()',
      explanation:
        'On architectures with strict separate address spaces (ARM64, s390x, or x86_64 with SMAP), reading a user-space pointer with bpf_probe_read_kernel_str() ALWAYS fails with -EFAULT!'
    },
    verifierSafetyContract: [
      'dst must be a valid pointer to writable eBPF stack or map/ringbuf memory.',
      'size must be a known bounded positive integer not exceeding the allocation size of dst.'
    ],
    registerMapping: [
      { reg: 'R1', meaning: 'void *dst (kernel/BPF destination buffer)' },
      { reg: 'R2', meaning: '__u32 size (max bytes to copy)' },
      { reg: 'R3', meaning: 'const void *unsafe_ptr (user-space address)' },
      { reg: 'R0 (Return)', meaning: 'Bytes copied (including \\0) or -EFAULT (-14)' }
    ],
    cExample: `// Reading pathname argument from sys_enter_openat / sys_enter_execve
const char *user_path = (const char *)ctx->args[0];
long copied = bpf_probe_read_user_str(&ev->filename, sizeof(ev->filename), user_path);
if (copied < 0) {
    // Page was unmapped or not faulted in yet
}`,
    goNote: 'In Go, trim at the first NUL byte using bytes.IndexByte(buf[:], 0).'
  },

  {
    id: 'helper-probe-read-user',
    helperIdOrType: 'BPF_FUNC_probe_read_user (#112)',
    name: 'bpf_probe_read_user()',
    category: 'Memory & Pointer Probing',
    minKernel: 'Linux 5.5+',
    signature: 'long bpf_probe_read_user(void *dst, __u32 size, const void *unsafe_ptr)',
    returnValueSpec: '0 on success, or negative error (-EFAULT) if user memory address is unmapped.',
    allowedProgramTypes: ['kprobe', 'kretprobe', 'tracepoint', 'fentry', 'fexit', 'uprobe', 'lsm'],
    shortSummary:
      'Safely copies fixed-size binary structs or buffers (such as struct sockaddr_in, TLS payload bytes, or argv pointers) from User-Space memory.',
    whatItDoes: [
      'Copies exactly size bytes from a user-space pointer into eBPF memory with page-fault protection. If the read fails partway through, the entire destination buffer is zeroed.'
    ],
    howItWorksUnderTheHood: [
      'Invokes copy_from_user_nofault(dst, unsafe_ptr, size) with page faults disabled.'
    ],
    whyUseInsteadOf: {
      alternative: 'bpf_probe_read_user_str()',
      explanation:
        'Use bpf_probe_read_user() for binary structs (struct sockaddr_in, struct clone_args, pointer arrays) that legitimately contain 0x00 zero bytes in the middle of fields!'
    },
    verifierSafetyContract: [
      'If size is computed dynamically (e.g., from a syscall return length), you MUST clamp and bitmask size (e.g., size &= 0xFF) so the Verifier can prove the upper bound.'
    ],
    registerMapping: [
      { reg: 'R1', meaning: 'void *dst (BPF stack/map destination)' },
      { reg: 'R2', meaning: '__u32 size (exact byte count)' },
      { reg: 'R3', meaning: 'const void *unsafe_ptr (user pointer)' },
      { reg: 'R0 (Return)', meaning: '0 on success, -EFAULT on fault' }
    ],
    cExample: `struct sockaddr_in uaddr = {};
bpf_probe_read_user(&uaddr, sizeof(uaddr), (const void *)ctx->args[1]);`,
    goNote: 'Ideal for reading fixed C structs or raw HTTP/TLS byte slices.'
  },

  {
    id: 'helper-probe-read-kernel',
    helperIdOrType: 'BPF_FUNC_probe_read_kernel (#113)',
    name: 'bpf_probe_read_kernel()',
    category: 'Memory & Pointer Probing',
    minKernel: 'Linux 5.5+',
    signature: 'long bpf_probe_read_kernel(void *dst, __u32 size, const void *unsafe_ptr)',
    returnValueSpec: '0 on success, or -EFAULT if kernel address is invalid.',
    allowedProgramTypes: ['kprobe', 'kretprobe', 'tracepoint', 'fentry', 'fexit', 'lsm'],
    shortSummary:
      'Safely reads bytes from an arbitrary Kernel-Space virtual memory address (used under the hood by BPF_CORE_READ).',
    whatItDoes: [
      'Copies size bytes from a kernel-space pointer (such as struct sock *, struct file *, or struct dentry *) into eBPF stack or map memory while catching any bad-pointer dereferences.'
    ],
    howItWorksUnderTheHood: [
      'Calls copy_from_kernel_nofault(dst, unsafe_ptr, size), verifying that unsafe_ptr falls within the canonical kernel virtual address range.'
    ],
    whyUseInsteadOf: {
      alternative: 'Calling bpf_probe_read_kernel() manually',
      explanation:
        'In 95% of cases, you should write BPF_CORE_READ(src, field) instead of manual bpf_probe_read_kernel() calls—BPF_CORE_READ expands to bpf_probe_read_kernel() automatically AND emits BTF CO-RE field offset relocations!'
    },
    verifierSafetyContract: [
      'Never pass a user-space pointer to bpf_probe_read_kernel()—the kernel range check will immediately reject it with -EFAULT.'
    ],
    registerMapping: [
      { reg: 'R1', meaning: 'void *dst' },
      { reg: 'R2', meaning: '__u32 size' },
      { reg: 'R3', meaning: 'const void *unsafe_kernel_ptr' },
      { reg: 'R0 (Return)', meaning: '0 on success, negative errno on error' }
    ],
    cExample: `// Direct usage (prefer BPF_CORE_READ(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr))
__u32 daddr = 0;
bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);`,
    goNote: 'Combined with bpf2go, CO-RE relocations patch the byte offset at LoadAndAssign time.'
  },

  // ============================================================================
  // BPF MAP OPERATIONS
  // ============================================================================
  {
    id: 'helper-map-lookup-elem',
    helperIdOrType: 'BPF_FUNC_map_lookup_elem (#1)',
    name: 'bpf_map_lookup_elem()',
    category: 'BPF Map Operations',
    minKernel: 'Linux 3.18+',
    signature: 'void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)',
    returnValueSpec: 'Direct kernel pointer to the map value inside the map (or NULL if key not found).',
    allowedProgramTypes: ['All Program Types (XDP, TC, kprobe, tracepoint, fentry, lsm, cgroup)'],
    shortSummary:
      'Looks up a key in a BPF map and returns a direct, mutable kernel pointer to the stored value in-place.',
    whatItDoes: [
      'Hashes or indexes key inside map and returns a direct pointer to the in-kernel memory slot holding the value (NOT a copy!).',
      'Because it returns a direct pointer into the map’s memory, your eBPF program can mutate fields in-place (e.g. val->packets++ or __sync_fetch_and_add(&val->bytes, len)) without needing a second bpf_map_update_elem() call!'
    ],
    howItWorksUnderTheHood: [
      'For BPF_MAP_TYPE_ARRAY / PERCPU_ARRAY, the Verifier inlines the lookup into a direct array pointer calculation (base + index * elem_size) with zero function-call overhead!'
    ],
    whyUseInsteadOf: {
      alternative: 'Copying values out and calling bpf_map_update_elem() on every packet',
      explanation:
        'Mutating the returned pointer in-place (via Per-CPU maps or atomic builtins) avoids hash bucket re-insertions and memory copies on the fast path.'
    },
    verifierSafetyContract: [
      'CRITICAL VERIFIER RULE: The return register R0 is typed as PTR_TO_MAP_VALUE_OR_NULL. You MUST perform an explicit if (!val) return ...; check before dereferencing val, or the Verifier will reject your program with "R0 invalid mem access \'map_value_or_null\'"!'
    ],
    registerMapping: [
      { reg: 'R1', meaning: 'const void *map (CONST_PTR_TO_MAP)' },
      { reg: 'R2', meaning: 'const void *key (pointer to stack/packet key)' },
      { reg: 'R0 (Return)', meaning: 'PTR_TO_MAP_VALUE_OR_NULL' }
    ],
    cExample: `__u32 key = 0;
__u64 *counter = bpf_map_lookup_elem(&pkt_stats, &key);
if (!counter) {
    return XDP_PASS; // Mandatory NULL check for Verifier!
}
__sync_fetch_and_add(counter, 1);`,
    goNote: 'Read from Go userspace via objs.PktStats.Lookup(&key, &val).'
  },

  {
    id: 'helper-map-update-elem',
    helperIdOrType: 'BPF_FUNC_map_update_elem (#2)',
    name: 'bpf_map_update_elem()',
    category: 'BPF Map Operations',
    minKernel: 'Linux 3.18+',
    signature: 'long bpf_map_update_elem(struct bpf_map *map, const void *key, const void *value, __u64 flags)',
    returnValueSpec: '0 on success, or negative errno (-E2BIG if hash map is full, -EEXIST if BPF_NOEXIST failed).',
    allowedProgramTypes: ['All Program Types'],
    shortSummary:
      'Inserts or overwrites a key-value entry inside a BPF map according to the specified update policy flag.',
    whatItDoes: [
      'Copies sizeof(key) and sizeof(value) from your eBPF stack into the target BPF map under RCU synchronization.'
    ],
    howItWorksUnderTheHood: [
      'Allocates a hash bucket element from the map’s preallocated slab pool (or evicts the oldest entry if the map is BPF_MAP_TYPE_LRU_HASH) and links it atomically.'
    ],
    whyUseInsteadOf: {
      alternative: 'Using BPF_MAP_TYPE_HASH without eviction on untrusted network keys',
      explanation:
        'When tracking network flows or TCP connections, pair bpf_map_update_elem() with BPF_MAP_TYPE_LRU_HASH so the map never returns -E2BIG during a SYN flood.'
    },
    verifierSafetyContract: [
      'Both key and value must point to fully initialized stack/map memory matching the exact byte sizes declared in __type(key, ...) and __type(value, ...).',
      'flags must be one of BPF_ANY (0: create or overwrite), BPF_NOEXIST (1: create only if absent), or BPF_EXIST (2: update only if present).'
    ],
    registerMapping: [
      { reg: 'R1', meaning: 'struct bpf_map *map' },
      { reg: 'R2', meaning: 'const void *key' },
      { reg: 'R3', meaning: 'const void *value' },
      { reg: 'R4', meaning: '__u64 flags (BPF_ANY=0, BPF_NOEXIST=1, BPF_EXIST=2)' },
      { reg: 'R0 (Return)', meaning: '0 on success, negative errno on failure' }
    ],
    cExample: `__u64 pid_tgid = bpf_get_current_pid_tgid();
__u64 ts = bpf_ktime_get_ns();
bpf_map_update_elem(&start_times, &pid_tgid, &ts, BPF_ANY);`,
    goNote: 'Update from Go userspace via objs.MyMap.Put(&key, &val).'
  },

  // ============================================================================
  // RINGBUFFER & TELEMETRY HELPERS
  // ============================================================================
  {
    id: 'helper-ringbuf-reserve-submit',
    helperIdOrType: 'BPF_FUNC_ringbuf_reserve (#131) & submit (#132)',
    name: 'bpf_ringbuf_reserve() & bpf_ringbuf_submit()',
    category: 'RingBuffer & Telemetry',
    minKernel: 'Linux 5.8+',
    signature: 'void *bpf_ringbuf_reserve(void *ringbuf, __u64 size, __u64 flags)',
    returnValueSpec: 'Pointer to reserved zero-copy slot inside the RingBuffer, or NULL if ringbuffer is full.',
    allowedProgramTypes: ['All Program Types (Linux 5.8+)'],
    shortSummary:
      'Reserves a variable-length or fixed-size memory slot directly inside a shared BPF_MAP_TYPE_RINGBUF and commits it to Go userspace with zero extra memory copies.',
    whatItDoes: [
      'bpf_ringbuf_reserve() atomically advances the producer position in the MPSC ring buffer and returns a direct pointer to the ring buffer page.',
      'Your eBPF program populates the struct fields directly in that shared memory slot—bypassing the 512-byte eBPF stack limit entirely!—and then calls bpf_ringbuf_submit(ev, 0) to mark the record visible to the Go ringbuf.Reader.'
    ],
    howItWorksUnderTheHood: [
      'Uses a two-phase lightweight spinlock / atomic commit protocol over memory-mapped kernel pages shared with user space via epoll.'
    ],
    whyUseInsteadOf: {
      alternative: 'bpf_perf_event_output() or bpf_ringbuf_output()',
      explanation:
        'Eliminates allocating large structs on the tiny 512-byte eBPF stack AND eliminates copying the struct from the stack into the ringbuffer!'
    },
    verifierSafetyContract: [
      'STRICT VERIFIER REFERENCE TRACKING: Once bpf_ringbuf_reserve() returns a non-NULL pointer, EVERY single exit path of your eBPF program MUST call either bpf_ringbuf_submit(ptr, 0) OR bpf_ringbuf_discard(ptr, 0)! If you return early without submitting or discarding, the Verifier rejects the program with "Unreleased reference"!'
    ],
    registerMapping: [
      { reg: 'R1', meaning: 'void *ringbuf (pointer to BPF_MAP_TYPE_RINGBUF)' },
      { reg: 'R2', meaning: '__u64 size (compile-time constant sizeof(struct event))' },
      { reg: 'R3', meaning: '__u64 flags (must be 0)' },
      { reg: 'R0 (Return)', meaning: 'PTR_TO_MEM_OR_NULL (alloc_mem)' }
    ],
    cExample: `struct event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
if (!ev) return 0; // Safe to return when NULL

if (should_ignore(ev)) {
    bpf_ringbuf_discard(ev, 0); // MUST discard before early return!
    return 0;
}
bpf_ringbuf_submit(ev, 0);
return 0;`,
    goNote: 'Consume in Go using rd, err := ringbuf.NewReader(objs.Events) and rd.Read().'
  },

  {
    id: 'helper-ktime-get-ns',
    helperIdOrType: 'BPF_FUNC_ktime_get_ns (#5)',
    name: 'bpf_ktime_get_ns()',
    category: 'RingBuffer & Telemetry',
    minKernel: 'Linux 3.18+',
    signature: '__u64 bpf_ktime_get_ns(void)',
    returnValueSpec: 'Monotonic nanoseconds elapsed since system boot (excluding suspend time).',
    allowedProgramTypes: ['All Program Types'],
    shortSummary:
      'Returns high-resolution monotonic clock time in nanoseconds (CLOCK_MONOTONIC) for computing exact function, I/O, and network latencies.',
    whatItDoes: [
      'Reads the CPU hardware Time Stamp Counter (TSC on x86_64 or CNTVCT_EL0 on ARM64) scaled to nanoseconds since boot.'
    ],
    howItWorksUnderTheHood: [
      'Executes in ~15ns without locks and is strictly monotonic (never jumps backward during NTP clock adjustments).'
    ],
    whyUseInsteadOf: {
      alternative: 'Wall-clock time when measuring duration deltas',
      explanation:
        'Monotonic nanoseconds never skew during NTP time steps, making delta = bpf_ktime_get_ns() - start_ts accurate to the nanosecond. (In Linux 5.7+, use bpf_ktime_get_boot_ns() if you want time including system suspend).'
    },
    verifierSafetyContract: [
      'Always returns a valid 64-bit unsigned scalar in R0; cannot fail.'
    ],
    registerMapping: [
      { reg: 'R0 (Return)', meaning: '__u64 monotonic nanoseconds' }
    ],
    cExample: `__u64 delta_ns = bpf_ktime_get_ns() - *start_ts;`,
    goNote: 'Convert to time.Duration in Go via time.Duration(ev.DeltaNs) * time.Nanosecond.'
  },

  // ============================================================================
  // NETWORKING, REDIRECTION & CONTROL FLOW
  // ============================================================================
  {
    id: 'helper-xdp-adjust-head',
    helperIdOrType: 'BPF_FUNC_xdp_adjust_head (#44)',
    name: 'bpf_xdp_adjust_head()',
    category: 'Networking & Redirection',
    minKernel: 'Linux 4.8+',
    signature: 'long bpf_xdp_adjust_head(struct xdp_md *xdp_md, int delta)',
    returnValueSpec: '0 on success, or negative error if headroom is insufficient.',
    allowedProgramTypes: ['XDP'],
    shortSummary:
      'Moves the ctx->data pointer forward or backward in an XDP packet buffer to encapsulate (VXLAN/Geneve/IPIP) or decapsulate outer headers at line rate.',
    whatItDoes: [
      'A negative delta (e.g. -sizeof(struct iphdr)) expands packet headroom toward ctx->data_meta so you can prepend a tunnel header; a positive delta strips outer headers.'
    ],
    howItWorksUnderTheHood: [
      'Adjusts the rx_buffer->data offset inside the NIC driver DMA ring without copying the packet payload.'
    ],
    whyUseInsteadOf: {
      alternative: 'Linux kernel tunnel netdevices (vxlan0 / ipip0)',
      explanation:
        'Encapsulating packets in XDP avoids allocating sk_buff structures and processes DSR (Direct Server Return) load balancing at 15M+ packets/sec per core.'
    },
    verifierSafetyContract: [
      'CRITICAL VERIFIER RULE: Calling bpf_xdp_adjust_head() INVALIDATES all existing packet pointers (data, data_end, eth, iph)! You MUST reload void *data = (void *)(long)ctx->data; and void *data_end = (void *)(long)ctx->data_end; and re-verify bounds after calling this helper!'
    ],
    registerMapping: [
      { reg: 'R1', meaning: 'struct xdp_md *ctx' },
      { reg: 'R2', meaning: 'int delta (negative grows header, positive shrinks)' },
      { reg: 'R0 (Return)', meaning: '0 on success, negative errno on failure' }
    ],
    cExample: `if (bpf_xdp_adjust_head(ctx, (int)sizeof(struct vlan_hdr)) < 0)
    return XDP_DROP;
// MUST reload data & data_end pointers after adjust_head!
void *data = (void *)(long)ctx->data;
void *data_end = (void *)(long)ctx->data_end;`,
    goNote: 'Used heavily by Cilium XDP Maglev load balancer for DSR encapsulation.'
  },

  {
    id: 'helper-tail-call',
    helperIdOrType: 'BPF_FUNC_tail_call (#12)',
    name: 'bpf_tail_call()',
    category: 'Networking & Redirection',
    minKernel: 'Linux 4.2+',
    signature: 'long bpf_tail_call(void *ctx, struct bpf_map *prog_array_map, __u32 index)',
    returnValueSpec: 'Does NOT return on success (jumps directly to target program)! Returns negative error only if target slot is empty or max tail-call depth (33) is exceeded.',
    allowedProgramTypes: ['XDP', 'TC', 'kprobe', 'tracepoint', 'fentry', 'lsm'],
    shortSummary:
      'Performs a zero-stack-overhead jump from one eBPF program into another eBPF program stored in a BPF_MAP_TYPE_PROG_ARRAY.',
    whatItDoes: [
      'Reuses the current stack frame and jumps execution directly to the JITed entry point of the eBPF program at prog_array_map[index], much like the execve() syscall does for processes.'
    ],
    howItWorksUnderTheHood: [
      'The x86_64/ARM64 JIT patches a direct jump instruction (jmp) when the program array slot is populated, chaining up to 33 programs together, each with its own independent 1-million instruction Verifier budget.'
    ],
    whyUseInsteadOf: {
      alternative: 'Putting all protocol parsers and policy rules in a single monolithic eBPF program',
      explanation:
        'Allows hot-swapping individual protocol parsers or security policy stages atomically from Go userspace without reloading the root hook!'
    },
    verifierSafetyContract: [
      'All programs in the BPF_MAP_TYPE_PROG_ARRAY must have the exact same program type and context struct as the caller.',
      'Always provide a fallback return statement immediately after bpf_tail_call() in case the map slot at index is empty.'
    ],
    registerMapping: [
      { reg: 'R1', meaning: 'void *ctx (current program context)' },
      { reg: 'R2', meaning: 'struct bpf_map *prog_array_map' },
      { reg: 'R3', meaning: '__u32 index (slot in prog array)' }
    ],
    cExample: `bpf_tail_call(ctx, &jmp_table, PROTO_HTTP_PARSER);
// Fallback only reached if jmp_table[PROTO_HTTP_PARSER] is empty:
return XDP_PASS;`,
    goNote: 'Populate the prog array in Go via objs.JmpTable.Put(uint32(idx), uint32(objs.HttpParser.FD())).'
  },

  {
    id: 'helper-d-path',
    helperIdOrType: 'BPF_FUNC_d_path (#147)',
    name: 'bpf_d_path()',
    category: 'Timers, Locks & Kfuncs',
    minKernel: 'Linux 5.9+',
    signature: 'long bpf_d_path(struct path *path, char *buf, __u32 sz)',
    returnValueSpec: 'Positive string length on success, or negative error on failure.',
    allowedProgramTypes: ['fentry', 'fexit', 'lsm'],
    shortSummary:
      'Resolves a kernel struct path * (mount + dentry) into its canonical, symlink-free full filesystem path string (e.g. "/etc/pam.d/common-auth").',
    whatItDoes: [
      'Walks the kernel VFS dentry and vfsmount hierarchy from leaf to root to reconstruct the full absolute file path—immune to relative-path tricks (../../../) and user-space TOCTOU pointer swaps!'
    ],
    howItWorksUnderTheHood: [
      'Calls the internal kernel d_path() function directly on the BTF-typed &file->f_path pointer.'
    ],
    whyUseInsteadOf: {
      alternative: 'Reading raw user-space string pointers in sys_enter_openat',
      explanation:
        'A user calling openat(fd, "../shadow", ...) gives you only "../shadow" in sys_enter_openat. bpf_d_path(&file->f_path, ...) inside lsm/file_open or fentry/vfs_open gives you the true resolved "/etc/shadow" path!'
    },
    verifierSafetyContract: [
      'Only allowed in BTF-enabled tracing (fentry/fexit) and BPF LSM hooks on allowlisted kernel functions where holding VFS locks cannot deadlock.'
    ],
    registerMapping: [
      { reg: 'R1', meaning: 'struct path *path (e.g. &file->f_path)' },
      { reg: 'R2', meaning: 'char *buf (destination buffer)' },
      { reg: 'R3', meaning: '__u32 sz (buffer size)' },
      { reg: 'R0 (Return)', meaning: 'Resolved path length or negative errno' }
    ],
    cExample: `SEC("lsm/file_open")
int BPF_PROG(enforce_file_open, struct file *file) {
    char full_path[128];
    bpf_d_path(&file->f_path, full_path, sizeof(full_path));
    return 0;
}`,
    goNote: 'Attach via link.AttachLSM(link.LSMOptions{Program: objs.EnforceFileOpen}).'
  },

  {
    id: 'helper-timer-init',
    helperIdOrType: 'BPF_FUNC_timer_init (#169) & Kfuncs',
    name: 'bpf_timer_init() & bpf_timer_start()',
    category: 'Timers, Locks & Kfuncs',
    minKernel: 'Linux 5.15+',
    signature: 'long bpf_timer_init(struct bpf_timer *timer, struct bpf_map *map, __u64 flags)',
    returnValueSpec: '0 on success, or negative errno (-EBUSY / -EINVAL).',
    allowedProgramTypes: ['All Program Types (Linux 5.15+)'],
    shortSummary:
      'Embeds a kernel high-resolution timer (hrtimer) directly inside a BPF map value to run periodic background callbacks in the kernel without user-space polling.',
    whatItDoes: [
      'Allows an eBPF program to schedule a BPF callback function to fire N nanoseconds in the future—even if no new packets or syscalls occur! Used for garbage-collecting stale map entries, refilling rate-limit token buckets, and flushing aggregated telemetry.'
    ],
    howItWorksUnderTheHood: [
      'Wraps a Linux kernel struct hrtimer whose lifecycle is tied to the enclosing BPF map element.'
    ],
    whyUseInsteadOf: {
      alternative: 'Iterating over millions of BPF map entries from a Go userspace ticker every second',
      explanation:
        'Eliminates costly user-to-kernel map iteration syscalls by handling expiration and token-bucket refills purely inside Ring 0.'
    },
    verifierSafetyContract: [
      'struct bpf_timer must be embedded as a field inside a BPF map value struct, and the map pointer passed to bpf_timer_init() must match the map containing that value.'
    ],
    registerMapping: [
      { reg: 'R1', meaning: 'struct bpf_timer *timer (field inside map value)' },
      { reg: 'R2', meaning: 'struct bpf_map *map (enclosing BPF map)' },
      { reg: 'R3', meaning: '__u64 flags (CLOCK_MONOTONIC = 1)' }
    ],
    cExample: `bpf_timer_init(&elem->timer, &flow_map, 1 /* CLOCK_MONOTONIC */);
bpf_timer_set_callback(&elem->timer, expire_flow_cb);
bpf_timer_start(&elem->timer, 5000000000ULL /* 5 sec */, 0);`,
    goNote: 'Requires BTF map definition so the kernel knows the byte offset of struct bpf_timer.'
  },

  {
    id: 'helper-redirect-map',
    helperIdOrType: 'BPF_FUNC_redirect_map (#51)',
    name: 'bpf_redirect_map()',
    category: 'Networking & Redirection',
    minKernel: 'Linux 4.14+',
    signature: 'long bpf_redirect_map(struct bpf_map *map, __u32 key, __u64 flags)',
    returnValueSpec: 'Returns XDP_REDIRECT (4) on success, or flags fallback value (e.g. XDP_PASS / XDP_DROP) on lookup failure.',
    allowedProgramTypes: ['XDP', 'TC'],
    shortSummary:
      'Redirects an XDP packet directly to another network interface (DEVMAP), another CPU core (CPUMAP), or a user-space AF_XDP socket (XSKMAP) in batches.',
    whatItDoes: [
      'Stores the target map and index in the per-CPU bpf_redirect_info structure and returns XDP_REDIRECT (4). When the NIC driver finishes the NAPI poll batch, xdp_do_flush() transmits up to 64 redirected frames in a single DMA burst!'
    ],
    howItWorksUnderTheHood: [
      'Avoids allocating an sk_buff or traversing the host IP routing table; packets jump straight from ingress NIC RX ring to egress NIC TX ring or container veth peer.'
    ],
    whyUseInsteadOf: {
      alternative: 'Linux bridge or iptables FORWARD chain',
      explanation:
        '3–5x higher forwarding throughput for Kubernetes Pod-to-Pod veth routing and AF_XDP zero-copy packet processing.'
    },
    verifierSafetyContract: [
      'map must be a BPF_MAP_TYPE_DEVMAP, BPF_MAP_TYPE_CPUMAP, or BPF_MAP_TYPE_XSKMAP.'
    ],
    registerMapping: [
      { reg: 'R1', meaning: 'struct bpf_map *map (DEVMAP / CPUMAP / XSKMAP)' },
      { reg: 'R2', meaning: '__u32 key (target slot or queue index)' },
      { reg: 'R3', meaning: '__u64 flags (fallback verdict e.g. XDP_PASS)' },
      { reg: 'R0 (Return)', meaning: 'XDP_REDIRECT (4) or fallback verdict' }
    ],
    cExample: `// Redirect packet to AF_XDP socket bound to current RX queue, or pass to kernel stack:
return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);`,
    goNote: 'Populate DEVMAP with interface ifindex integers from Go net.InterfaceByName().'
  },

  {
    id: 'helper-send-signal',
    helperIdOrType: 'BPF_FUNC_send_signal (#109)',
    name: 'bpf_send_signal()',
    category: 'Timers, Locks & Kfuncs',
    minKernel: 'Linux 5.3+',
    signature: 'long bpf_send_signal(__u32 sig)',
    returnValueSpec: '0 on success, or negative errno (-EPERM / -EBUSY).',
    allowedProgramTypes: ['kprobe', 'tracepoint', 'fentry', 'fexit', 'uprobe', 'lsm'],
    shortSummary:
      'Sends a POSIX signal (such as SIGKILL=9 or SIGSTOP=19) synchronously from the kernel to the currently executing thread.',
    whatItDoes: [
      'Delivers signal sig to the current task_struct before the task returns from kernel mode back to user space.'
    ],
    howItWorksUnderTheHood: [
      'Calls do_send_sig_info(sig, SEND_SIG_PRIV, current, PIDTYPE_PID) (or schedules via irq_work if called in NMI context).'
    ],
    whyUseInsteadOf: {
      alternative: 'Sending an event to Go userspace and calling syscall.Kill(pid, SIGKILL) in Go',
      explanation:
        'Killing a malicious process from user space takes 50–500 microseconds (after the exploit payload has already executed!). bpf_send_signal(9) terminates the offending thread before the current syscall even returns to user mode—though for preventive blocking on Linux 5.7+, prefer BPF LSM returning -EPERM.'
    },
    verifierSafetyContract: [
      'Only affects the current task on the local CPU core.'
    ],
    registerMapping: [
      { reg: 'R1', meaning: '__u32 sig (e.g. 9 for SIGKILL, 19 for SIGSTOP)' },
      { reg: 'R0 (Return)', meaning: '0 on success, negative errno on failure' }
    ],
    cExample: `if (detected_rwx_shellcode_injection) {
    bpf_send_signal(9 /* SIGKILL */);
}`,
    goNote: 'To terminate only the calling thread vs the entire thread group, compare bpf_send_signal_thread() vs bpf_send_signal().'
  },

  {
    id: 'helper-spin-lock',
    helperIdOrType: 'BPF_FUNC_spin_lock (#93) & unlock (#94)',
    name: 'bpf_spin_lock() & bpf_spin_unlock()',
    category: 'Timers, Locks & Kfuncs',
    minKernel: 'Linux 5.1+',
    signature: 'long bpf_spin_lock(struct bpf_spin_lock *lock)',
    returnValueSpec: '0 (always succeeds; Verifier enforces lock/unlock pairing).',
    allowedProgramTypes: ['XDP', 'TC', 'cgroup', 'fentry', 'tracepoint (non-kprobe)'],
    shortSummary:
      'Acquires and releases a fine-grained spinlock embedded inside a BPF map value to atomically update multi-field structs across CPU cores.',
    whatItDoes: [
      'When updating a single counter across cores, Per-CPU maps or __sync_fetch_and_add() are sufficient. However, when you need to atomically update MULTIPLE related fields together (such as a Token Bucket’s tokens_remaining AND last_refill_ts), bpf_spin_lock(&val->lock) guarantees no other CPU core can interleave updates.'
    ],
    howItWorksUnderTheHood: [
      'Acquires an arch_spin_lock inside the map element while preemption and interrupts are disabled on the local CPU.'
    ],
    whyUseInsteadOf: {
      alternative: 'Multiple separate __sync_fetch_and_add() calls on interdependent fields',
      explanation:
        'Prevents torn reads and race conditions when maintaining sliding windows, token buckets, or ring pointers inside a shared map entry.'
    },
    verifierSafetyContract: [
      'STRICT VERIFIER RULES: (1) While holding a bpf_spin_lock, you CANNOT call any other BPF helper functions! (2) You MUST call bpf_spin_unlock(&val->lock) on every branch before returning. (3) The map MUST be BTF-defined with __type(value, ...).'
    ],
    registerMapping: [
      { reg: 'R1', meaning: 'struct bpf_spin_lock *lock (field inside map value)' }
    ],
    cExample: `bpf_spin_lock(&bucket->lock);
bucket->tokens += refilled;
bucket->last_ts = now;
bpf_spin_unlock(&bucket->lock);`,
    goNote: 'When looking up a spinlock-protected map from Go, pass ebpf. LookupLock flag.'
  }
];

export const EBPF_MACROS_CATALOG: EbpfMacroReferenceItem[] = [
  // ============================================================================
  // SEC() HOOK DIRECTIVES
  // ============================================================================
  {
    id: 'macro-sec-directive',
    name: 'SEC("...") Section Attribute Macro',
    category: 'SEC() Hook Directives',
    headerFile: '<bpf/bpf_helpers.h>',
    syntax: 'SEC("section_name/hook_target")',
    shortSummary:
      'Places a C function or BPF map definition into a dedicated ELF binary section so Go’s cilium/ebpf loader knows its exact program type and kernel attachment target.',
    whatIsItAndPurpose: [
      'When Clang compiles your .bpf.c file with -target bpf, it produces a standard ELF object file (.o). By default, C compilers put all functions into a single .text section and all global variables into .data or .bss.',
      'The SEC("...") macro instructs Clang to place each eBPF program into a named ELF section such as SEC("xdp"), SEC("tracepoint/syscalls/sys_enter_execve"), SEC("kprobe/tcp_v4_connect"), SEC("fentry/vfs_read"), or SEC("lsm/file_open"), and places BTF map definitions into SEC(".maps").',
      'When bpf2go and cilium/ebpf parse the ELF binary, they inspect the SEC() string prefix to automatically set ProgramSpec.Type (e.g. ebpf.XDP, ebpf.TracePoint, ebpf.Kprobe, ebpf.Tracing, ebpf.LSM) and ProgramSpec.AttachTo!'
    ],
    underTheHoodExpansion: {
      whatYouWrite: `SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) { ... }`,
      whatCompilerSees: `__attribute__((section("tracepoint/syscalls/sys_enter_execve"), used))
int handle_execve(struct trace_event_raw_sys_enter *ctx) { ... }`,
      explanation:
        'Expands to GCC/Clang __attribute__((section(...), used)), preventing dead-code elimination and embedding the hook metadata in the ELF section table.'
    },
    whyUseInsteadOfRawCode: {
      rawAlternative: 'Writing raw __attribute__((section(...))) or manually configuring ebpf.ProgramSpec in Go',
      rationale:
        'Follows the standardized libbpf / cilium/ebpf section naming convention so bpf2go generates ready-to-attach ProgramSpecs automatically.'
    },
    verifierAndPortabilityNotes: [
      'Common SEC() prefixes supported by cilium/ebpf: "xdp", "tc" / "classifier", "kprobe/<fn>", "kretprobe/<fn>", "fentry/<fn>", "fexit/<fn>", "tp/<cat>/<name>", "tracepoint/<cat>/<name>", "uprobe/<func>", "uretprobe/<func>", "lsm/<hook>", "cgroup/skb", "cgroup/connect4", "sockops", and ".maps".'
    ],
    cAndGoExample: `// In Kernel C:
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_tcp_connect, struct sock *sk) { return 0; }

// In Go (cilium/ebpf):
kp, err := link.Kprobe("tcp_v4_connect", objs.TraceTcpConnect, nil)`
  },

  // ============================================================================
  // CO-RE STRUCT READING MACROS
  // ============================================================================
  {
    id: 'macro-bpf-core-read',
    name: 'BPF_CORE_READ()',
    category: 'CO-RE Struct Reading Macros',
    headerFile: '<bpf/bpf_core_read.h>',
    syntax: 'BPF_CORE_READ(src, a, b, c, ...)',
    shortSummary:
      'Chains multiple BTF-relocated kernel pointer dereferences (src->a->b->c) into safe, nested bpf_probe_read_kernel() calls in a single expression.',
    whatIsItAndPurpose: [
      'In traditional eBPF (and in kprobes/tracepoints where pointers are not BTF-trusted), you cannot write task->real_parent->nsproxy->uts_ns->name.nodename because dereferencing arbitrary kernel pointers directly is forbidden by the Verifier unless each hop is checked via bpf_probe_read_kernel().',
      'Writing 4 nested bpf_probe_read_kernel() calls with temporary stack variables by hand is verbose and error-prone. BPF_CORE_READ(task, real_parent, tgid) uses C statement-expressions and variadic macro recursion to generate all intermediate temporary variables and __builtin_preserve_access_index() CO-RE relocations automatically!'
    ],
    underTheHoodExpansion: {
      whatYouWrite: `__u32 ppid = BPF_CORE_READ(task, real_parent, tgid);`,
      whatCompilerSees: `({
    typeof((task)->real_parent) __t1;
    bpf_probe_read_kernel(&__t1, sizeof(__t1),
        __builtin_preserve_access_index(&((task)->real_parent)));
    typeof(__t1->tgid) __t2;
    bpf_probe_read_kernel(&__t2, sizeof(__t2),
        __builtin_preserve_access_index(&(__t1->tgid)));
    __t2;
})`,
      explanation:
        'Each comma-separated field hop emits a CO-RE relocation record in .BTF.ext and safely copies the intermediate pointer via bpf_probe_read_kernel().'
    },
    whyUseInsteadOfRawCode: {
      rawAlternative: 'Manual bpf_probe_read_kernel() chains with hardcoded struct offsets',
      rationale:
        'Reduces 15 lines of boilerplate C to 1 readable expression while guaranteeing your compiled .o binary runs across Linux 5.4 through 6.12+ without recompilation.'
    },
    verifierAndPortabilityNotes: [
      'Only use BPF_CORE_READ() for KERNEL-space pointers! If you are reading a user-space struct chain, use BPF_CORE_READ_USER(src, a, b) instead.'
    ],
    cAndGoExample: `struct task_struct *task = (struct task_struct *)bpf_get_current_task();
// Safely walks task -> real_parent -> real_parent -> tgid (Grandparent PID!)
__u32 gppid = BPF_CORE_READ(task, real_parent, real_parent, tgid);`
  },

  {
    id: 'macro-bpf-core-read-str-into',
    name: 'BPF_CORE_READ_STR_INTO() & BPF_CORE_READ_INTO()',
    category: 'CO-RE Struct Reading Macros',
    headerFile: '<bpf/bpf_core_read.h>',
    syntax: 'BPF_CORE_READ_STR_INTO(dst_buf, src, field1, field2, ...)',
    shortSummary:
      'Walks a chain of kernel pointers and copies the final field (either a NUL-terminated string or a large struct) directly into dst_buf without allocating an extra copy on the 512B stack.',
    whatIsItAndPurpose: [
      'Because BPF_CORE_READ() returns its result by value via a C statement expression, it allocates a temporary variable on the eBPF stack. For 4-byte or 8-byte scalars that is fine, but for a 64-byte char array or large struct, returning by value wastes precious 512-byte stack space!',
      'BPF_CORE_READ_STR_INTO(&ev->dentry_name, file, f_path.dentry, d_name.name) walks the intermediate pointers and writes the final NUL-terminated kernel string directly into your ringbuffer event struct!'
    ],
    underTheHoodExpansion: {
      whatYouWrite: `BPF_CORE_READ_STR_INTO(&ev->comm, task, real_parent, comm);`,
      whatCompilerSees: `({
    typeof(task->real_parent) __t1;
    bpf_probe_read_kernel(&__t1, sizeof(__t1),
        __builtin_preserve_access_index(&(task->real_parent)));
    bpf_probe_read_kernel_str(&ev->comm, sizeof(ev->comm),
        __builtin_preserve_access_index(&(__t1->comm)));
})`,
      explanation:
        'Uses bpf_probe_read_kernel() for all intermediate pointer hops and bpf_probe_read_kernel_str() directly into dst_buf for the final string field.'
    },
    whyUseInsteadOfRawCode: {
      rawAlternative: 'Copying strings onto the local 512B stack before copying into a RingBuffer event',
      rationale:
        'Writes directly into your bpf_ringbuf_reserve() slot, keeping stack usage near 0 bytes.'
    },
    verifierAndPortabilityNotes: [
      'Works for both char[] arrays embedded inside kernel structs (like task->comm) and const char * pointers (like dentry->d_name.name).'
    ],
    cAndGoExample: `// Read the filename of an open struct file * directly into our ringbuf event:
BPF_CORE_READ_STR_INTO(&ev->filename, file, f_path.dentry, d_name.name);`
  },

  {
    id: 'macro-bpf-core-read-user',
    name: 'BPF_CORE_READ_USER()',
    category: 'CO-RE Struct Reading Macros',
    headerFile: '<bpf/bpf_core_read.h>',
    syntax: 'BPF_CORE_READ_USER(src_user_ptr, field1, field2, ...)',
    shortSummary:
      'Identical to BPF_CORE_READ(), except every pointer dereference hop uses bpf_probe_read_user() to traverse User-Space struct pointers safely.',
    whatIsItAndPurpose: [
      'When tracing user-space applications with uprobes (or reading nested user-space syscall structures like struct msghdr -> msg_iov -> iov_base), all pointers reside in user virtual memory (__user).',
      'Using regular BPF_CORE_READ() on user-space pointers fails with -EFAULT because it calls bpf_probe_read_kernel(). BPF_CORE_READ_USER() substitutes bpf_probe_read_user() at every hop while preserving BTF type layout support.'
    ],
    underTheHoodExpansion: {
      whatYouWrite: `void *base = BPF_CORE_READ_USER(msg, msg_iov, iov_base);`,
      whatCompilerSees: `({
    typeof(msg->msg_iov) __t1;
    bpf_probe_read_user(&__t1, sizeof(__t1), &(msg->msg_iov));
    typeof(__t1->iov_base) __t2;
    bpf_probe_read_user(&__t2, sizeof(__t2), &(__t1->iov_base));
    __t2;
})`,
      explanation:
        'Generates nested bpf_probe_read_user() calls for each struct pointer dereference in user space.'
    },
    whyUseInsteadOfRawCode: {
      rawAlternative: 'Manual nested bpf_probe_read_user() calls',
      rationale:
        'Clean one-line traversal of nested user-space structs in uprobes and syscall handlers.'
    },
    verifierAndPortabilityNotes: [
      'Can be combined with bpf_probe_read_user_str() once you obtain the final char * user pointer.'
    ],
    cAndGoExample: `// Traverse user-space struct msghdr -> struct iovec -> iov_len:
size_t iov_len = BPF_CORE_READ_USER(user_msghdr, msg_iov, iov_len);`
  },

  // ============================================================================
  // KPROBE & TRAMPOLINE ARGUMENT MACROS
  // ============================================================================
  {
    id: 'macro-bpf-kprobe-kretprobe',
    name: 'BPF_KPROBE() & BPF_KRETPROBE()',
    category: 'Kprobe & Trampoline Argument Macros',
    headerFile: '<bpf/bpf_tracing.h>',
    syntax: 'int BPF_KPROBE(prog_name, type1 arg1, type2 arg2, ...)',
    shortSummary:
      'Unpacks CPU architecture-specific pt_regs registers (PT_REGS_PARM1..5 / PT_REGS_RC) into clean, typed C function parameters.',
    whatIsItAndPurpose: [
      'When a kprobe fires at the entry of a kernel function like tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len), the eBPF program receives only a single raw pointer: struct pt_regs *ctx containing the saved CPU registers (rdi, rsi, rdx on x86_64; x0, x1, x2 on ARM64).',
      'BPF_KPROBE(trace_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len) generates an outer wrapper that takes struct pt_regs *ctx, extracts each register via PT_REGS_PARM1(ctx), PT_REGS_PARM2(ctx), etc., and passes them as strongly-typed C arguments to your inline function body!'
    ],
    underTheHoodExpansion: {
      whatYouWrite: `SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_connect, struct sock *sk, struct sockaddr *uaddr) {
    return 0;
}`,
      whatCompilerSees: `int trace_connect(struct pt_regs *ctx);
static __always_inline int ____trace_connect(struct pt_regs *ctx, struct sock *sk, struct sockaddr *uaddr);
int trace_connect(struct pt_regs *ctx) {
    return ____trace_connect(ctx, (struct sock *)PT_REGS_PARM1(ctx), (struct sockaddr *)PT_REGS_PARM2(ctx));
}`,
      explanation:
        'Generates a trampoline wrapper that maps PT_REGS_PARM1..5 (or PT_REGS_RC for BPF_KRETPROBE) into named typed parameters while keeping ctx accessible.'
    },
    whyUseInsteadOfRawCode: {
      rawAlternative: 'Writing (struct sock *)ctx->di (which fails to compile on ARM64!) or manual PT_REGS_PARM1 casts',
      rationale:
        'Eliminates manual register casting and ensures cross-architecture portability between x86_64 and ARM64.'
    },
    verifierAndPortabilityNotes: [
      'Must define __TARGET_ARCH_x86 or __TARGET_ARCH_arm64 before including <bpf/bpf_tracing.h> (passed via clang -D__TARGET_ARCH_x86 in bpf2go).'
    ],
    cAndGoExample: `SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(on_accept_exit, struct sock *newsk) {
    if (!newsk) return 0;
    // newsk is automatically extracted from PT_REGS_RC(ctx)!
    return 0;
}`
  },

  {
    id: 'macro-bpf-prog',
    name: 'BPF_PROG() (for fentry / fexit / LSM / tp_btf)',
    category: 'Kprobe & Trampoline Argument Macros',
    headerFile: '<bpf/bpf_tracing.h>',
    syntax: 'int BPF_PROG(prog_name, type1 arg1, type2 arg2, [ret_type ret])',
    shortSummary:
      'Unpacks BTF trampoline context arrays (unsigned long long *ctx) used by modern fentry, fexit, tp_btf, and BPF LSM programs into typed BTF pointers.',
    whatIsItAndPurpose: [
      'Unlike kprobes (which pass a struct pt_regs * CPU register dump), modern BTF-powered hooks—fentry, fexit, tp_btf, and lsm—pass a raw array of 64-bit unsigned integers (unsigned long long *ctx) where ctx[0] is argument 1, ctx[1] is argument 2, and (for fexit/lsm) the final slot is the function’s return value.',
      'BPF_PROG() unpacks ctx[0..N] into typed arguments that the eBPF Verifier recognizes as trusted PTR_TO_BTF_ID pointers! This means inside BPF_PROG you can dereference sk->__sk_common.skc_daddr directly without even calling bpf_probe_read_kernel()!'
    ],
    underTheHoodExpansion: {
      whatYouWrite: `SEC("fexit/tcp_v4_connect")
int BPF_PROG(trace_connect_exit, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret) {
    return 0;
}`,
      whatCompilerSees: `int trace_connect_exit(unsigned long long *ctx) {
    return ____trace_connect_exit(ctx, (struct sock *)ctx[0], (struct sockaddr *)ctx[1], (int)ctx[2], (int)ctx[3]);
}`,
      explanation:
        'Maps the 64-bit BTF trampoline slot array ctx[0..N] into typed function arguments, including the return value as the final parameter in fexit hooks.'
    },
    whyUseInsteadOfRawCode: {
      rawAlternative: 'Using BPF_KPROBE on fentry/lsm hooks (which reads the wrong offsets!)',
      rationale:
        'CRITICAL DISTINCTION: Use BPF_KPROBE/BPF_KRETPROBE ONLY for kprobe/kretprobe/uprobe. Use BPF_PROG ONLY for fentry/fexit/lsm/tp_btf!'
    },
    verifierAndPortabilityNotes: [
      'In SEC("fexit/..."), BPF_PROG gives you BOTH the original input arguments AND the function return value in the same hook—eliminating the need for a hash map to correlate entry and exit!'
    ],
    cAndGoExample: `SEC("fexit/vfs_read")
int BPF_PROG(trace_vfs_read_exit, struct file *file, char *buf, size_t count, loff_t *pos, ssize_t ret) {
    // Both input 'file' AND return 'ret' (bytes read) are available simultaneously!
    return 0;
}`
  },

  {
    id: 'macro-pt-regs-parm',
    name: 'PT_REGS_PARM1..5() & PT_REGS_RC()',
    category: 'Kprobe & Trampoline Argument Macros',
    headerFile: '<bpf/bpf_tracing.h>',
    syntax: 'PT_REGS_PARM1(ctx) / PT_REGS_PARM1_CORE(ctx) / PT_REGS_RC(ctx)',
    shortSummary:
      'Architecture-agnostic macros that map C function argument positions 1–5 and return value to the underlying CPU ABI registers in struct pt_regs.',
    whatIsItAndPurpose: [
      'On x86_64 System V ABI, the first 5 function arguments are passed in CPU registers %rdi, %rsi, %rdx, %rcx, %r8, and the return value is in %rax. On ARM64 (AArch64), arguments 1–5 are passed in x0..x4 and the return value is in x0.',
      'PT_REGS_PARM1(ctx) through PT_REGS_PARM5(ctx) and PT_REGS_RC(ctx) abstract away these hardware register differences. When reading an inner pt_regs struct (such as in syscall wrappers __x64_sys_*), use PT_REGS_PARM1_CORE(real_regs) which wraps the register read in BPF_CORE_READ().'
    ],
    underTheHoodExpansion: {
      whatYouWrite: `void *arg1 = (void *)PT_REGS_PARM1(ctx);
long retval = PT_REGS_RC(ctx);`,
      whatCompilerSees: `// On x86_64 (__TARGET_ARCH_x86):
void *arg1 = (void *)((ctx)->di);
long retval = ((ctx)->ax);
// On ARM64 (__TARGET_ARCH_arm64):
void *arg1 = (void *)((ctx)->regs[0]);
long retval = ((ctx)->regs[0]);`,
      explanation:
        'Selects the target CPU architecture’s struct pt_regs field at compile time based on __TARGET_ARCH_*.'
    },
    whyUseInsteadOfRawCode: {
      rawAlternative: 'Hardcoding ctx->di or ctx->ax',
      rationale:
        'Hardcoding x86_64 register names breaks compilation immediately when deploying your eBPF program to AWS Graviton or Apple Silicon ARM64 nodes.'
    },
    verifierAndPortabilityNotes: [
      'When attaching a kprobe to a raw Linux 4.17+ syscall wrapper (__x64_sys_openat), PT_REGS_PARM1(ctx) is actually a pointer to an INNER struct pt_regs *! Use PT_REGS_PARM2_CORE((struct pt_regs *)PT_REGS_PARM1(ctx)) or prefer tracepoints.'
    ],
    cAndGoExample: `SEC("uprobe/SSL_write")
int trace_ssl_write(struct pt_regs *ctx) {
    const void *buf = (const void *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);
    return 0;
}`
  },

  // ============================================================================
  // BTF MAP DEFINITION & COMPILER MACROS
  // ============================================================================
  {
    id: 'macro-btf-map-uint-type',
    name: '__uint() & __type() BTF Map Macros',
    category: 'BTF Map Definition & Compiler Macros',
    headerFile: '<bpf/bpf_helpers.h>',
    syntax: '__uint(name, val) and __type(name, type)',
    shortSummary:
      'Declares BTF-typed eBPF maps in SEC(".maps") using C pointer-type metadata so Go’s bpf2go can validate key/value types at compile time.',
    whatIsItAndPurpose: [
      'Instead of the legacy struct bpf_map_def (which erased key and value types to raw integers sizeof(key)), modern eBPF defines maps as an anonymous C struct inside SEC(".maps") using __uint(type, BPF_MAP_TYPE_HASH), __uint(max_entries, 10240), __type(key, __u32), and __type(value, struct flow_metrics).',
      'Because __type(value, struct flow_metrics) embeds the full C struct type into the ELF binary’s .BTF section, the Linux kernel and cilium/ebpf can inspect exact field names, pretty-print map values via bpftool map dump, and support kernel features like bpf_spin_lock and bpf_timer.'
    ],
    underTheHoodExpansion: {
      whatYouWrite: `struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct stats);
} my_map SEC(".maps");`,
      whatCompilerSees: `struct {
    int (*type)[BPF_MAP_TYPE_HASH];
    int (*max_entries)[4096];
    __u32 *key;
    struct stats *value;
} my_map __attribute__((section(".maps"), used));`,
      explanation:
        '__uint(k, v) expands to a pointer to an array of size v (encoding the integer constant in BTF type metadata without allocating memory!), and __type(k, T) expands to a pointer T *.'
    },
    whyUseInsteadOfRawCode: {
      rawAlternative: 'Legacy struct bpf_map_def',
      rationale:
        'Required by modern libbpf and cilium/ebpf for BTF map validation, spinlocks, timers, and inner-map-of-maps definitions.'
    },
    verifierAndPortabilityNotes: [
      'Note that for BPF_MAP_TYPE_RINGBUF, max_entries MUST be a power-of-two multiple of the host page size (e.g. 1 << 24 for 16 MB) and no __type(key/value) is needed.'
    ],
    cAndGoExample: `struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u64);
} active_flows SEC(".maps");`
  },

  {
    id: 'macro-always-inline-printk',
    name: '__always_inline & bpf_printk()',
    category: 'BTF Map Definition & Compiler Macros',
    headerFile: '<bpf/bpf_helpers.h>',
    syntax: 'static __always_inline int helper_fn(...) / bpf_printk(fmt, ...)',
    shortSummary:
      '__always_inline forces Clang to inline helper C functions into the caller, and bpf_printk() formats debug strings to /sys/kernel/debug/tracing/trace_pipe.',
    whatIsItAndPurpose: [
      '__always_inline expands to __attribute__((always_inline)), instructing Clang to inline your C helper function directly into the main eBPF program body. This avoids BPF-to-BPF subprogram call frame overhead and allows the Verifier to track packet bounds checks across helper calls seamlessly.',
      'bpf_printk(fmt, ...) is a convenience macro around bpf_trace_printk() that places the format string into a read-only section and emits formatted debug messages to /sys/kernel/debug/tracing/trace_pipe.'
    ],
    underTheHoodExpansion: {
      whatYouWrite: `bpf_printk("pkt from %pI4 port %d\\n", &ip, port);`,
      whatCompilerSees: `({
    static const char ____fmt[] = "pkt from %pI4 port %d\\n";
    bpf_trace_printk(____fmt, sizeof(____fmt), &ip, port);
})`,
      explanation:
        'Allocates the format string constant and invokes helper #6 (bpf_trace_printk).'
    },
    whyUseInsteadOfRawCode: {
      rawAlternative: 'Raw bpf_trace_printk() with manual sizeof(fmt)',
      rationale:
        'Clean printf-style syntax during local development (though in production, always replace bpf_printk with BPF_MAP_TYPE_RINGBUF).'
    },
    verifierAndPortabilityNotes: [
      'On kernels < 5.13, bpf_printk() supports at most 3 format arguments (%d, %s, %p). On Linux 5.13+, it uses bpf_snprintf_btf and supports 4+ arguments including %pI4 for IPv4 addresses!'
    ],
    cAndGoExample: `static __always_inline bool is_http_get(const char *payload) {
    return payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T';
}`
  }
];

