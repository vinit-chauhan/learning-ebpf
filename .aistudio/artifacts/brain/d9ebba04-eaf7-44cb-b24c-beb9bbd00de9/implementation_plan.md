# KernelPulse Curriculum & Reference Expansion Plan: Linux Syscalls, BPF Helpers, Macros & Advanced Tracing

This plan expands **KernelPulse** into an all-in-one eBPF reference and learning encyclopedia by introducing an interactive **Syscalls, BPF Helpers & Macros Reference Explorer** alongside **6 new Concept Encyclopedia chapters** (bringing the total to 18 chapters) and **6 new step-by-step C + Go (`cilium/ebpf`) tutorials** (bringing the total to 21 hands-on labs).

---

## 1. Interactive Kernel Reference Explorer (Syscalls, BPF Helpers & C Macros)

We will add a dedicated, searchable **Reference Explorer** (accessible directly from the navigation bar and cross-linked from Concepts and Tutorials) organized into three deep-dive technical catalogs:

### A. Traceable Linux System Calls Catalog (20+ High-Value Syscalls)
Organized by kernel subsystem (**Process & Execution**, **Filesystem & VFS**, **Network & Sockets**, **Memory, Privilege & Security**):
- **Process & Execution**: `execve`, `execveat`, `clone3`, `fork`, `exit_group`, `ptrace`, `prctl`
- **Filesystem & VFS**: `openat`, `openat2`, `read`, `write`, `unlinkat`, `renameat2`, `memfd_create`, `fchmodat`
- **Networking & Sockets**: `socket`, `connect`, `accept4`, `bind`, `sendto`, `recvfrom`, `setsockopt`
- **Memory & Privilege Escalation**: `mmap`, `mprotect`, `bpf`, `setuid`, `capset`, `init_module`, `mount`

**Every syscall reference card includes**:
1. **Hook Attachment Paths**: Exact `SEC("tracepoint/syscalls/sys_enter_<name>")`, `SEC("tracepoint/syscalls/sys_exit_<name>")`, `SEC("fentry/__x64_sys_<name>")`, and recommended **BPF LSM** alternative when blocking or TOCTOU safety is required.
2. **Kernel Context & Argument Layout**: Exact fields inside `struct trace_event_raw_sys_enter` (`ctx->args[0..5]`), including which arguments are **user-space pointers (`__user char *`)** vs. scalar values/file descriptors.
3. **Pointer & Verifier Rules**: Explicit guidance on why `bpf_probe_read_user_str()` or `bpf_probe_read_user()` must be used for syscall pointer arguments, how to handle page faults safely, and how to correlate `sys_enter` arguments with `sys_exit` return codes (`ret`) using a PID/TID-keyed hash map.
4. **Copyable C + Go (`cilium/ebpf`) Snippet**: Ready-to-use kernel `.bpf.c` probe and Go `link.Tracepoint("syscalls", "sys_enter_*", ...)` loader code.

### B. BPF Helper Functions & Modern Kfuncs Catalog (25+ Core Helpers)
Organized by functional domain (**Process & Task Context**, **Memory & Pointer Probing**, **BPF Map Operations**, **RingBuffer & Events**, **Networking & Packet Manipulation**, **Timers, Locks & Security Enforcement**):
- **Context & Identity**: `bpf_get_current_pid_tgid()`, `bpf_get_current_uid_gid()`, `bpf_get_current_comm()`, `bpf_get_current_task_btf()`, `bpf_get_Current_cgroup_id()`, `bpf_get_smp_processor_id()`, `bpf_ktime_get_ns()`
- **Memory Probing & CO-RE**: `bpf_probe_read_kernel()`, `bpf_probe_read_kernel_str()`, `bpf_probe_read_user()`, `bpf_probe_read_user_str()`, `bpf_copy_from_user()` (sleepable `.s` programs)
- **Map & State Management**: `bpf_map_lookup_elem()`, `bpf_map_update_elem()`, `bpf_map_delete_elem()`, `bpf_for_each_map_elem()`
- **RingBuffer & Telemetry**: `bpf_ringbuf_reserve()`, `bpf_ringbuf_submit()`, `bpf_ringbuf_discard()`, `bpf_ringbuf_output()`, `bpf_printk()`
- **Packet, Socket & Control Flow**: `bpf_xdp_adjust_head()`, `bpf_redirect_map()`, `bpf_skb_load_bytes()`, `bpf_sock_hash_update()`, `bpf_tail_call()`, `bpf_d_path()`, `bpf_send_signal()`, `bpf_timer_init()`
- **Modern BTF Kfuncs**: `bpf_rdonly_cast()`, `bpf_task_acquire()`, `bpf_task_release()`, `bpf_dynptr_from_mem()`

**Every helper entry includes**:
1. **Exact C Signature & Register ABI**: Input registers (`R1–R5`) and return value (`R0`).
2. **Verifier Contract**: Mandatory safety checks required by the static verifier (e.g., `if (!ptr) return 0;` after `bpf_map_lookup_elem` or `bpf_ringbuf_reserve`, or balancing `bpf_ringbuf_submit`/`bpf_ringbuf_discard` across all branch paths).
3. **Program Type Compatibility & Min Kernel Version**: Matrix showing which hooks (`XDP`, `TC`, `kprobe`, `tracepoint`, `fentry`, `lsm`) permit the helper.
4. **What / How / Why Comparison**: E.g., why use `bpf_probe_read_user_str()` instead of `bpf_probe_read_kernel_str()`, or why use `bpf_ringbuf_reserve()` + `bpf_ringbuf_submit()` instead of `bpf_ringbuf_output()`.

### C. eBPF C Macros, `SEC()` Directives & BTF Annotations Reference (20+ Macros)
A complete reference decoding the macros from `<bpf/bpf_helpers.h>`, `<bpf/bpf_tracing.h>`, and `<bpf/bpf_core_read.h>`:
- **Section & Hook Macros**: `SEC("...")` table mapping every section prefix (`xdp`, `tc`, `kprobe/`, `kretprobe/`, `fentry/`, `fexit/`, `tp/`, `tracepoint/`, `uprobe/`, `lsm/`, `cgroup/skb`, `cgroup/connect4`, `iter/task`) to its context struct and Go `cilium/ebpf/link` attachment function.
- **CO-RE & Struct Reading Macros**: `BPF_CORE_READ()`, `BPF_CORE_READ_INTO()`, `BPF_CORE_READ_STR_INTO()`, `BPF_CORE_READ_USER()`, `BPF_CORE_READ_BITFIELD_PROBED()`.
- **Calling Convention & Trampoline Macros**: `BPF_KPROBE()`, `BPF_KRETPROBE()`, `BPF_PROG()`, `PT_REGS_PARM1..5()`, `PT_REGS_RC()`.
- **BTF Map Definition & Compiler Macros**: `__uint(type, ...)`, `__uint(max_entries, ...)`, `__type(key, ...)`, `__type(value, ...)`, `__array(...)`, `__always_inline`, `bpf_printk()`.

**Every macro entry includes**:
1. **Under-the-Hood Expansion**: Side-by-side comparison showing the clean macro call vs. the raw compiler attributes / nested `bpf_probe_read_kernel()` calls it expands into.
2. **Why We Use It**: How it prevents architecture-specific register bugs (`x86_64` vs `arm64`) and enables BTF CO-RE field relocations.

---

## 2. Expanded Concept Encyclopedia (12 → 18 Deep-Dive Chapters)

We will add **6 new comprehensive chapters** to `CONCEPT_TOPICS`, each featuring **"1. What is X?"**, **"2. How X Works Under the Hood"** (with step-by-step lifecycle & code), **"3. Why Use X Instead of Y?"** (with quantitative comparison tables), and an **Interactive Comprehension Check**:

- **Chapter 13: `fentry` & `fexit` BTF Trampolines** — Why `fentry`/`fexit` with `BPF_PROG` achieves 5–10x lower overhead than `kprobe`/`kretprobe` and gives `fexit` access to both input arguments and the return value simultaneously.
- **Chapter 14: User-Space vs. Kernel-Space Memory Addressing in eBPF** — Virtual memory spaces, SMAP/SMEP hardware protections, page faults on swapped user pages, sleepable (`fentry.s` / `uprobe.s`) programs, and why mixing `bpf_probe_read_user` and `bpf_probe_read_kernel` fails.
- **Chapter 15: Linux System Call Internals & Syscall Tracing Strategies** — How a userspace `syscall` instruction transitions into `do_syscall_64`, why raw `kprobe/__x64_sys_*` breaks due to `pt_regs` wrapper indirection, and when to choose `tracepoint/syscalls/sys_enter_*` vs. `fentry` vs. `BPF LSM`.
- **Chapter 16: BPF Helper Functions vs. Kernel Kfuncs** — How the 5-argument register calling convention (`R1–R5`) works, why Linux froze traditional UAPI helpers (`enum bpf_func_id`), and how modern BTF `kfuncs` expose extensible kernel capabilities.
- **Chapter 17: Concurrency, Atomics, Spinlocks & Timers in eBPF** — Handling multi-core race conditions on shared BPF maps: when to use Per-CPU maps vs. `__sync_fetch_and_add` vs. `struct bpf_spin_lock`, and how `struct bpf_timer` runs periodic background GC inside the kernel.
- **Chapter 18: Cgroup v2 eBPF Hooks for Container Networking & Governance** — Attaching eBPF programs to Kubernetes pod cgroups (`cgroup/skb`, `cgroup/connect4`, `cgroup/sockops`) to transparently rewrite destination IPs (kube-proxy replacement) and enforce per-container socket policies.

---

## 3. Expanded Step-by-Step Tracing Curriculum (15 → 21 Labs)

We will expand `TUTORIAL_LESSONS` from 15 to **21 guided C + Go (`cilium/ebpf`) labs** (7 Beginner, 7 Mid-Level, 7 Advanced), each with a Concept Read-Through, synchronized C/Go checkpoint walkthroughs, and a hands-on Verifier diagnostic challenge:

### New Beginner Labs
- **Lab 06: Tracing File Opens & Deletions (`sys_enter_openat2` & `sys_enter_unlinkat`)** — Reading `__user` filename strings safely with `bpf_probe_read_user_str()` and correlating `sys_enter` with `sys_exit` file descriptors.
- **Lab 07: Mastering `BPF_KPROBE` & `BPF_CORE_READ` Macros (Process Ancestry Tracker)** — Walking `task_struct->real_parent->real_parent` pointer chains in a single CO-RE macro call to detect suspicious shell spawns (e.g., `nginx -> sh -> curl`).

### New Mid-Level Labs
- **Lab 13: Zero-Overhead Function Latency with `fentry` & `fexit` Trampolines** — Replacing `kprobe` + `kretprobe` hash-map correlation with `SEC("fexit/tcp_v4_connect")` and `BPF_PROG` to access both input `struct sock *` and return `int ret` in a single hook.
- **Lab 14: Container-Aware Socket Load Balancing with `cgroup/connect4`** — Using `SEC("cgroup/connect4")` and `link.AttachCgroup` in Go to intercept outbound `connect()` calls at the socket layer before a single SYN packet is generated.

### New Advanced Labs
- **Lab 20: Detecting Fileless Malware (`memfd_create` + `execveat` + `mprotect` RWX)** — Multi-syscall security correlation detecting in-memory ELF execution (`memfd_create` anonymous file descriptors executed via `execveat` or `mprotect(PROT_READ|PROT_WRITE|PROT_EXEC)`).
- **Lab 21: In-Kernel Sliding-Window Rate Limiter with `bpf_spin_lock` & `bpf_timer`** — Building a thread-safe token bucket inside a shared BPF map using `bpf_spin_lock` and scheduling automatic bucket refills with `bpf_timer_init()` and `bpf_timer_set_callback()`.
