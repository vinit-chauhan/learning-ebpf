import { ConceptTopic } from '../types/ebpf';

export const CONCEPT_TOPICS: ConceptTopic[] = [
  {
    id: 'ebpf-architecture-fundamentals',
    index: '01',
    title: 'eBPF Virtual Machine & Execution Model',
    subtitle: 'Safe, event-driven sandboxed execution inside the Linux kernel',
    category: 'Foundations & Architecture',
    readTime: '12 min read',
    minKernel: 'Linux 4.14+',
    summary:
      'Understand how eBPF transforms the Linux kernel into a programmable runtime without modifying kernel source code or risking kernel panics.',
    whatIsIt: {
      heading: 'What is the eBPF Runtime?',
      paragraphs: [
        'Extended Berkeley Packet Filter (eBPF) is an in-kernel virtual machine and event-driven execution engine built directly into the Linux kernel. It allows engineers to load custom, sandboxed bytecode programs into the kernel at runtime that execute in response to specific system events—such as network packet arrivals, system calls, kernel function entries, or security hooks.',
        'Historically, observing or changing Linux kernel behavior required either waiting years for upstream kernel patches or loading Linux Kernel Modules (LKMs) written in raw C. A single null pointer dereference or infinite loop in a kernel module immediately causes a kernel panic, crashing the entire host and all running containers.',
        'eBPF solves this fundamental tension between safety and programmability. Every eBPF program is verified by an in-kernel Static Verifier before it is ever allowed to run, and then compiled by a Just-In-Time (JIT) compiler into native CPU instructions (x86_64, ARM64) running at native kernel speed.'
      ],
      keyTakeaways: [
        '11 64-bit registers (R0–R10, where R10 is a read-only frame pointer) and a strict 512-byte stack frame.',
        'Event-driven execution: eBPF programs do not run as background daemons; they wake up when a kernel hook fires, execute deterministically in nanoseconds, and exit.',
        'Zero context-switch overhead for in-kernel aggregation compared to ptrace or userspace proxies.'
      ],
      mentalModelAnalogy:
        'Think of eBPF as what JavaScript did for static HTML web browsers: instead of recompiling the browser to add interactive behavior, JavaScript runs inside a secure browser sandbox triggered by DOM events. eBPF runs inside a verified kernel sandbox triggered by kernel events.'
    },
    howItWorks: {
      heading: 'How eBPF Programs Compile, Verify, and Execute',
      paragraphs: [
        'Developing an eBPF application always involves two distinct halves: the Kernel-Side eBPF Program (written in restricted C and compiled via Clang/LLVM into ELF `.o` bytecode) and the Userspace Control Plane (written in Go using `cilium/ebpf`).',
        'When your Go program starts, it parses the ELF object, creates any declared BPF maps via the `bpf(BPF_MAP_CREATE)` syscall, and submits the bytecode instructions via `bpf(BPF_PROG_LOAD)`. The kernel Verifier then simulates every possible branch path. Once verified, the JIT translates the generic 64-bit eBPF instructions into native machine instructions, and your Go loader attaches the program file descriptor to a hook point.'
      ],
      lifecycleSteps: [
        {
          step: '01',
          actor: 'USERSPACE',
          title: 'Clang / bpf2go Compilation',
          detail: 'Restricted C (.bpf.c) is compiled by LLVM into an ELF binary containing eBPF bytecode instructions, map definitions, and BTF type metadata.'
        },
        {
          step: '02',
          actor: 'SYSCALL',
          title: 'bpf(BPF_PROG_LOAD) Invocation',
          detail: 'The Go cilium/ebpf loader reads the embedded ELF spec, creates BPF maps, resolves map file descriptors in the bytecode, and invokes the bpf() system call.'
        },
        {
          step: '03',
          actor: 'VERIFIER',
          title: 'Static Safety Verification & JIT',
          detail: 'The kernel Verifier walks the Control Flow Graph (CFG), proving termination (no unbounded loops), valid pointer bounds, and helper permissions before JIT-compiling to native x86_64/ARM64.'
        },
        {
          step: '04',
          actor: 'KERNEL_HOOK',
          title: 'Event-Driven Hook Attachment',
          detail: 'Via bpf_link (e.g., link.AttachXDP or link.Tracepoint), the JITed function is wired to a kernel event and runs whenever that code path is hit.'
        },
        {
          step: '05',
          actor: 'BPF_MAP',
          title: 'State Aggregation & RingBuf Streaming',
          detail: 'The eBPF program updates Per-CPU maps or pushes structured events to a BPF Ring Buffer, which the Go application reads asynchronously.'
        }
      ],
      codeLanguage: 'c',
      codeTitle: 'minimal_execve.bpf.c — Canonical Kernel eBPF Structure',
      codeSnippet: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    char comm[16];

    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("Process execve detected: PID=%d COMM=%s\\n", pid, comm);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`
    },
    whyUseInsteadOf: {
      heading: 'Why Do We Use eBPF Instead of Linux Kernel Modules (LKMs) or ptrace?',
      primaryTech: 'eBPF Programs',
      alternativeTech: 'Linux Kernel Modules (LKM) & ptrace',
      rationaleParagraphs: [
        'Before eBPF, deep system visibility or custom packet processing required either loading a custom Linux Kernel Module (LKM) or using `ptrace` (like `strace` does). LKMs have unrestricted access to kernel memory: a single race condition or out-of-bounds pointer crashes the entire physical machine. Furthermore, LKMs break across kernel upgrades because internal kernel ABI structures change constantly.',
        'Conversely, `ptrace` is safe because it runs in userspace, but it pauses the target process twice per system call, causing 10x–40x latency slowdowns in production workloads. eBPF delivers the best of both worlds: mathematical safety guarantees via the Verifier, zero kernel compilation overhead via CO-RE, and nanosecond in-kernel execution.'
      ],
      comparisonTable: [
        {
          dimension: 'Crash Safety',
          primaryChoice: 'Guaranteed safe by Static Verifier before load',
          alternativeChoice: 'Unrestricted memory access; bugs cause Kernel Panic',
          winner: 'primary'
        },
        {
          dimension: 'Execution Overhead',
          primaryChoice: '~20–80 nanoseconds (JIT native instructions in-kernel)',
          alternativeChoice: 'ptrace adds 10,000+ ns due to 4 context switches',
          winner: 'primary'
        },
        {
          dimension: 'Cross-Kernel Portability',
          primaryChoice: 'Single binary runs everywhere via BTF & CO-RE',
          alternativeChoice: 'Must recompile LKM against exact kernel headers',
          winner: 'primary'
        },
        {
          dimension: 'Live Upgrade / Detach',
          primaryChoice: 'Atomic zero-downtime replacement via bpf_link',
          alternativeChoice: 'rmmod risks dangling pointers or locked references',
          winner: 'primary'
        }
      ],
      whenToUsePrimary: [
        'Observability, distributed tracing, latency histograms, and profiling in production.',
        'High-speed packet filtering (XDP), container networking (Cilium), and L4/L7 load balancing.',
        'Runtime security auditing and mandatory access enforcement (LSM).'
      ],
      whenToUseAlternative: [
        'Writing a brand-new hardware device driver (e.g., GPU or NVMe PCIe driver) that requires arbitrary DMA and interrupt handling.',
        'Implementing a complete filesystem from scratch.'
      ]
    },
    comprehensionCheck: {
      question: 'Why can an eBPF program safely run in production on a critical Kubernetes node where a Linux Kernel Module (LKM) might be banned?',
      options: [
        'eBPF programs run in a separate userspace container with restricted root privileges.',
        'The in-kernel Static Verifier proves prior to attachment that the program cannot loop infinitely, access out-of-bounds memory, or dereference null pointers.',
        'eBPF bytecode is interpreted line-by-line by a garbage-collected runtime that catches exceptions at runtime.',
        'eBPF programs are only allowed to read network packets and cannot inspect system calls.'
      ],
      correctIndex: 1,
      explanation:
        'The eBPF Verifier performs exhaustive static analysis on the program Control Flow Graph before JIT compilation, rejecting any program that could hang the CPU or corrupt kernel memory.'
    },
    relatedTutorialId: 'tut-beg-01-execve',
    simulatorPresetId: 'preset-syscall-execve'
  },
  {
    id: 'kprobes-vs-tracepoints',
    index: '02',
    title: 'Kprobes & Kretprobes vs. Static Tracepoints',
    subtitle: 'Dynamic function instrumentation vs. stable kernel ABI trace hooks',
    category: 'Kernel Hook Subsystems',
    readTime: '11 min read',
    minKernel: 'Linux 4.17+',
    summary:
      'Learn how to choose between dynamic Kprobes that can hook almost any kernel function and static Tracepoints maintained by kernel subsystem authors.',
    whatIsIt: {
      heading: 'What Are Kprobes and Tracepoints?',
      paragraphs: [
        'To observe what the Linux kernel is doing, your eBPF program needs an attachment point (hook). For kernel function and syscall tracing, the two foundational mechanisms are **Kprobes** (Kernel Probes) and **Tracepoints**.',
        'A **Kprobe** (`kprobe/function_name`) dynamically attaches to the entry of virtually *any* non-inlined function inside the Linux kernel image (`vmlinux`), while a **Kretprobe** attaches to the function return path—allowing you to measure exact execution duration and inspect return values.',
        'A **Tracepoint** (`tracepoint/category/name`), by contrast, is a static, explicitly defined hook point placed in the kernel source code by Linux kernel maintainers (such as `syscalls/sys_enter_openat` or `sched/sched_switch`).'
      ],
      keyTakeaways: [
        'Tracepoints provide a stable, documented struct layout (`/sys/kernel/debug/tracing/events/.../format`) that rarely changes across kernel versions.',
        'Kprobes can instrument 50,000+ internal kernel functions (like `tcp_v4_connect` or `vfs_read`) where no static tracepoint exists.',
        'Pairing a `kprobe` (entry timestamp saved in a BPF Hash Map keyed by TID) with a `kretprobe` (exit timestamp minus entry timestamp) is the standard pattern for kernel latency histograms.'
      ],
      mentalModelAnalogy:
        'Tracepoints are like official webhook endpoints documented in an API specification—stable and reliable. Kprobes are like attaching a debugger breakpoint to an internal private method—immensely powerful when you need internal state, but the method signature may change in the next release.'
    },
    howItWorks: {
      heading: 'How Kprobes & Tracepoints Work Under the Hood',
      paragraphs: [
        'When you attach a Kprobe to a kernel function like `tcp_v4_connect`, the kernel dynamically replaces the first instruction of that function (or uses `ftrace` NOP sleds at the function prologue) with a jump into a trampoline that invokes your JIT-compiled eBPF program, passing CPU registers inside `struct pt_regs *ctx`.',
        'Because `kprobe` receives raw CPU registers (`PT_REGS_PARM1(ctx)`, `PT_REGS_PARM2(ctx)`), libbpf provides the `BPF_KPROBE` macro so you can write typed C parameters cleanly. Tracepoints use static jump labels (`static_key`) that remain a 5-byte `NOP` instruction when disabled (zero overhead) and patch into a direct call when your eBPF program attaches.'
      ],
      lifecycleSteps: [
        {
          step: '01',
          actor: 'USERSPACE',
          title: 'Select Stable Tracepoint or Dynamic Kprobe',
          detail: 'Check if a tracepoint exists in /sys/kernel/tracing/available_events. If not, target the internal kernel function via kprobe/kretprobe.'
        },
        {
          step: '02',
          actor: 'SYSCALL',
          title: 'perf_event_open / bpf_link Attachment',
          detail: 'In Go cilium/ebpf, call link.Tracepoint("syscalls", "sys_enter_openat", prog, nil) or link.Kprobe("tcp_v4_connect", prog, nil).'
        },
        {
          step: '03',
          actor: 'KERNEL_HOOK',
          title: 'Ftrace / Static Key Trampoline Patching',
          detail: 'The kernel patches the 5-byte NOP instruction at the function entry into a direct call to the BPF trampoline.'
        },
        {
          step: '04',
          actor: 'BPF_MAP',
          title: 'Context Extraction & Telemetry Emission',
          detail: 'Your BPF program reads arguments via typed tracepoint structs or BPF_CORE_READ on struct pt_regs and emits metrics.'
        }
      ],
      codeLanguage: 'c',
      codeTitle: 'kprobe_tcp_connect.bpf.c — Typed Kprobe & Kretprobe Pairing',
      codeSnippet: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_connect_entry, struct sock *sk) {
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    bpf_printk("tcp_v4_connect called for destination port: %d\\n", __bpf_ntohs(dport));
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(trace_connect_exit, int ret) {
    if (ret != 0) {
        bpf_printk("tcp_v4_connect failed with error code: %d\\n", ret);
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`
    },
    whyUseInsteadOf: {
      heading: 'Why Do We Use Tracepoints Instead of Kprobes (And Vice Versa)?',
      primaryTech: 'Static Tracepoints (When Available)',
      alternativeTech: 'Dynamic Kprobes / Fentry',
      rationaleParagraphs: [
        'A golden rule of production eBPF engineering is: **Prefer Tracepoints first; drop down to Kprobes/Fentry when you need internal function arguments or latency boundaries not exposed by a tracepoint.**',
        'Because Linux kernel developers refactor internal C functions across releases (renaming functions, changing parameter order, or inlining functions), a Kprobe targeting an obscure helper may fail to attach on a newer kernel. Tracepoints are deliberately maintained as stable contracts.'
      ],
      comparisonTable: [
        {
          dimension: 'ABI Stability Across Kernels',
          primaryChoice: 'High — stable event format maintained by kernel devs',
          alternativeChoice: 'Medium/Low — internal functions can be renamed or inlined',
          winner: 'primary'
        },
        {
          dimension: 'Coverage Depth',
          primaryChoice: '~1,800 predefined kernel trace events',
          alternativeChoice: '50,000+ internal kernel symbols in /proc/kallsyms',
          winner: 'alternative'
        },
        {
          dimension: 'Entry + Exit Latency Pairing',
          primaryChoice: 'Only if explicit enter/exit tracepoints exist',
          alternativeChoice: 'Every kprobe has a matching kretprobe for duration math',
          winner: 'alternative'
        },
        {
          dimension: 'Modern Replacement (Linux 5.5+)',
          primaryChoice: 'Raw Tracepoints (raw_tp) avoid formatting overhead',
          alternativeChoice: 'fentry / fexit trampolines (10x faster than kretprobe)',
          winner: 'tie'
        }
      ],
      whenToUsePrimary: [
        'Tracing system calls (`syscalls/sys_enter_*`), process lifecycle (`sched/sched_process_exec`), or block I/O (`block/block_rq_issue`).',
        'Building long-lived fleet monitoring agents that must run unmodified across Ubuntu, RHEL, and Bottlerocket kernels.'
      ],
      whenToUseAlternative: [
        'Measuring exact function latency between entry (`kprobe`) and return (`kretprobe`).',
        'Inspecting internal kernel structs (`struct sock *`, `struct sk_buff *`) inside TCP/IP stack functions that lack tracepoints.'
      ]
    },
    comprehensionCheck: {
      question: 'What is the primary risk of relying exclusively on a Kprobe vs. a Static Tracepoint across different Linux kernel versions?',
      options: [
        'Kprobes cannot read BPF maps, whereas Tracepoints can.',
        'The target internal kernel function might be inlined by the compiler or have its signature changed in a newer kernel release.',
        'Kprobes only work on 32-bit x86 processors.',
        'Tracepoints run in userspace while Kprobes run in kernel space.'
      ],
      correctIndex: 1,
      explanation:
        'Internal kernel functions are not part of the stable userspace ABI; the compiler can inline them or kernel developers can change their arguments between releases.'
    },
    relatedTutorialId: 'tut-mid-01-tcp-latency',
    simulatorPresetId: 'preset-tcp-latency'
  },
  {
    id: 'xdp-vs-tc-networking',
    index: '03',
    title: 'XDP (eXpress Data Path) vs. Traffic Control (TC)',
    subtitle: 'Line-rate driver-level packet processing vs. sk_buff socket buffer hooks',
    category: 'Kernel Hook Subsystems',
    readTime: '14 min read',
    minKernel: 'Linux 4.18+ (TCX in 6.6+)',
    summary:
      'Master the Linux kernel networking datapath: understand exactly when a packet hits XDP at the NIC driver vs. TC after sk_buff allocation.',
    whatIsIt: {
      heading: 'What Are XDP and TC in the eBPF Networking Datapath?',
      paragraphs: [
        '**XDP (eXpress Data Path)** is the earliest possible hook point in the Linux networking stack. An XDP eBPF program executes inside the network interface card (NIC) driver the instant a packet arrives via DMA ring buffer—*before* the kernel allocates its heavy metadata structure (`struct sk_buff`) or parses L3/L4 headers.',
        '**TC (Traffic Control)** hooks execute slightly higher in the networking stack, right after the kernel has allocated the `struct sk_buff` (`__sk_buff` in eBPF). Unlike XDP, which strictly handles **Ingress** (incoming) packets, TC hooks can inspect and mutate both **Ingress and Egress** (outgoing) traffic.'
      ],
      keyTakeaways: [
        'XDP verdicts: `XDP_DROP` (instant drop at line rate, ~24M packets/sec per core), `XDP_PASS` (hand to normal kernel stack), `XDP_TX` (bounce back out same NIC), `XDP_REDIRECT` (bypass stack to another NIC or AF_XDP socket).',
        'XDP operates on a raw contiguous memory buffer (`ctx->data` to `ctx->data_end`), requiring explicit pointer arithmetic and bounds checks.',
        'TC operates on `struct __sk_buff`, offering rich metadata (packet mark, cgroup ID, socket association, tunnel info) and full Egress visibility.'
      ],
      mentalModelAnalogy:
        'XDP is the security bouncer standing on the sidewalk outside the building door: he can reject (`XDP_DROP`) or redirect visitors before they ever step inside or get a visitor badge printed. TC is the checkpoint at the lobby elevator bank: every visitor already has a printed badge (`sk_buff`) and can be inspected going both up (Ingress) and down (Egress).'
    },
    howItWorks: {
      heading: 'How Packet Bounds Checking & Verdict Routing Work',
      paragraphs: [
        'Because XDP accesses raw packet bytes directly in the NIC ring buffer, the eBPF Verifier enforces strict **Packet Bounds Checking**. Before reading any byte of an Ethernet (`struct ethhdr`), IPv4 (`struct iphdr`), or TCP (`struct tcphdr`) header, your C code must prove to the Verifier that the header pointer plus `sizeof(header)` does not exceed `ctx->data_end`.',
        'If you omit `if ((void *)(eth + 1) > data_end) return XDP_PASS;`, the Verifier immediately rejects the program with `invalid access to packet` because a malformed truncated packet on the wire could otherwise trick the kernel into reading out-of-bounds memory.'
      ],
      lifecycleSteps: [
        {
          step: '01',
          actor: 'KERNEL_HOOK',
          title: 'NIC RX Ring Buffer DMA Arrival',
          detail: 'Network card writes raw Ethernet frame into RX ring memory; driver NAPI poll invokes attached XDP program with struct xdp_md.'
        },
        {
          step: '02',
          actor: 'VERIFIER',
          title: 'Pointer Bounds Proof (data + offset <= data_end)',
          detail: 'Program parses Ethernet -> IPv4 -> TCP/UDP headers with strict bounds checks at each layer.'
        },
        {
          step: '03',
          actor: 'BPF_MAP',
          title: 'Blocklist Lookup / Conntrack Table Match',
          detail: 'Source IP is looked up in a BPF_MAP_TYPE_LPM_TRIE or BPF_MAP_TYPE_HASH in ~15 nanoseconds.'
        },
        {
          step: '04',
          actor: 'KERNEL_HOOK',
          title: 'Verdict Execution (XDP_DROP / XDP_PASS / TC)',
          detail: 'Malicious packets return XDP_DROP immediately (saving sk_buff allocation); legitimate packets return XDP_PASS and enter the TC Ingress hook.'
        }
      ],
      codeLanguage: 'c',
      codeTitle: 'xdp_firewall.bpf.c — Line-Rate IPv4 Packet Parser with Bounds Checks',
      codeSnippet: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

SEC("xdp")
int xdp_packet_filter(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol == IPPROTO_ICMP) {
        return XDP_DROP; // Drop ping floods at NIC driver level
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`
    },
    whyUseInsteadOf: {
      heading: 'Why Do We Use XDP Instead of TC or iptables/nftables?',
      primaryTech: 'XDP (eXpress Data Path)',
      alternativeTech: 'TC (Traffic Control) & iptables',
      rationaleParagraphs: [
        'Traditional Linux `iptables` evaluates rules sequentially in $O(N)$ list order *after* the kernel has already spent CPU cycles allocating `struct sk_buff`, setting up DMA mappings, and traversing the netfilter hook chain. During a 10Mpps DDoS SYN flood, `sk_buff` allocation alone exhausts CPU cores.',
        'XDP runs before `sk_buff` allocation, allowing a single CPU core to drop 20+ million malicious packets per second. However, XDP cannot see Egress traffic and lacks socket/cgroup metadata—which is why production Kubernetes CNIs like Cilium combine **XDP at the physical NIC** (for DDoS and Hairpin NodePort load balancing) with **TC on virtual `veth` interfaces** (for pod-to-pod policy and Egress).'
      ],
      comparisonTable: [
        {
          dimension: 'Max Drop Throughput (per core)',
          primaryChoice: '~24 Million pps (runs prior to sk_buff allocation)',
          alternativeChoice: 'TC: ~5M pps | iptables: <1M pps at scale',
          winner: 'primary'
        },
        {
          dimension: 'Traffic Direction',
          primaryChoice: 'Ingress (RX) only',
          alternativeChoice: 'Both Ingress (RX) and Egress (TX)',
          winner: 'alternative'
        },
        {
          dimension: 'Rich Kernel Metadata (cgroup, skb->mark)',
          primaryChoice: 'None — raw packet bytes only',
          alternativeChoice: 'Full __sk_buff metadata, socket UID, packet mark',
          winner: 'alternative'
        },
        {
          dimension: 'Hardware Offload Support',
          primaryChoice: 'Supported on SmartNICs (Netronome/Nvidia)',
          alternativeChoice: 'Flower/TC offload on select switches',
          winner: 'primary'
        }
      ],
      whenToUsePrimary: [
        'Volumetric DDoS mitigation, SYN flood scrubbing, and IP blocklisting at the edge.',
        'High-speed L4 load balancing (like Meta Katran and Cilium XDP Maglev) using `XDP_TX`.'
      ],
      whenToUseAlternative: [
        'Kubernetes Pod-to-Pod network policy enforcement where both Ingress and Egress traffic must be filtered.',
        'Traffic shaping, DSCP/QoS packet marking, or matching traffic by container cgroup identity.'
      ]
    },
    comprehensionCheck: {
      question: 'Why does the eBPF Verifier reject an XDP program if you read `eth->h_proto` before checking `if ((void *)(eth + 1) > data_end)`?',
      options: [
        'Because `eth->h_proto` is encrypted until `bpf_skb_pull_data` is called.',
        'Because `ctx->data` points to raw packet memory that could be shorter than `sizeof(struct ethhdr)`, risking an out-of-bounds kernel memory read.',
        'Because XDP programs are only allowed to read IPv6 headers.',
        'Because `data_end` is a userspace pointer.'
      ],
      correctIndex: 1,
      explanation:
        'Without verifying that `eth + 1 <= data_end`, a runt or malformed frame could cause the eBPF program to read past the end of the packet buffer into adjacent kernel memory.'
    },
    relatedTutorialId: 'tut-beg-02-xdp-counter',
    simulatorPresetId: 'preset-xdp-firewall'
  },
  {
    id: 'bpf-maps-and-percpu',
    index: '04',
    title: 'BPF Maps: Hash, Array, Per-CPU & LPM Trie',
    subtitle: 'High-concurrency key-value data structures bridging Kernel and Go Userspace',
    category: 'BPF Maps & Ring Buffers',
    readTime: '13 min read',
    minKernel: 'Linux 4.14+',
    summary:
      'Discover how eBPF programs persist state across invocations, share configuration with Go applications, and avoid CPU lock contention using Per-CPU maps.',
    whatIsIt: {
      heading: 'What Are BPF Maps?',
      paragraphs: [
        'Because an eBPF program executes only for the duration of a single event and has a strict 512-byte stack limit, it cannot store persistent global structures on its stack. **BPF Maps** are generic, high-performance key-value data stores residing in kernel memory that persist across program invocations.',
        'BPF Maps serve two critical roles: (1) **In-Kernel Scratchpad & Aggregation**, such as storing the start timestamp of a syscall in a `kprobe` and retrieving it in a `kretprobe`, or maintaining packet counters per IP address; and (2) **Bidirectional Kernel ↔ Userspace Bridge**, allowing your Go (`cilium/ebpf`) control plane to write dynamic firewall rules into the kernel or read aggregated metrics out.'
      ],
      keyTakeaways: [
        '`BPF_MAP_TYPE_HASH`: Hash table with arbitrary struct keys/values; auto-evicts oldest entries when `BPF_MAP_TYPE_LRU_HASH` is used.',
        '`BPF_MAP_TYPE_ARRAY`: Pre-allocated integer-indexed array ($O(1)$ lookup, fastest possible access, keys `0..max_entries-1`).',
        '`BPF_MAP_TYPE_PERCPU_HASH` & `BPF_MAP_TYPE_PERCPU_ARRAY`: Gives every logical CPU core its own private copy of each map value—eliminating atomic lock contention (`__sync_fetch_and_add`) on 64+ core servers!',
        '`BPF_MAP_TYPE_LPM_TRIE`: Longest Prefix Match trie designed specifically for CIDR subnet routing and IP blocklists (e.g., matching `10.244.0.0/16`).'
      ],
      mentalModelAnalogy:
        'Think of BPF Maps as an in-memory Redis instance embedded directly inside the Linux kernel address space—accessible in ~15 nanoseconds by kernel hooks and queryable via file descriptors from your Go binary.'
    },
    howItWorks: {
      heading: 'How Map Lookups, Pointer Null Checks, and Go Unmarshaling Work',
      paragraphs: [
        'In modern eBPF C programs, maps are declared using BTF-defined map macros (`struct { __uint(type, BPF_MAP_TYPE_HASH); ... } my_map SEC(".maps");`). Inside your eBPF hook, calling `bpf_map_lookup_elem(&my_map, &key)` returns a **direct kernel pointer** (`void *`) to the value inside the map—not a copy.',
        'Because the key might not exist in a Hash map, `bpf_map_lookup_elem` returns `NULL` on a miss. The eBPF Verifier marks the returned register as `map_value_or_null`. You **must** check `if (!val) return 0;` before dereferencing `val`, at which point the Verifier promotes the register type to a safe `map_value` pointer.'
      ],
      lifecycleSteps: [
        {
          step: '01',
          actor: 'USERSPACE',
          title: 'BTF Map Definition in ELF (.maps)',
          detail: 'C struct defines type, max_entries, __type(key, ...), and __type(value, ...) so bpf2go generates matching Go types.'
        },
        {
          step: '02',
          actor: 'VERIFIER',
          title: 'Null-Pointer Promotion Check',
          detail: 'Verifier tracks R0 = map_value_or_null after bpf_map_lookup_elem() and requires an explicit null check before read/write.'
        },
        {
          step: '03',
          actor: 'BPF_MAP',
          title: 'Lockless Per-CPU or Atomic Mutation',
          detail: 'Kernel updates the map value in-place via pointer or bpf_map_update_elem(&map, &key, &init_val, BPF_ANY).'
        },
        {
          step: '04',
          actor: 'USERSPACE',
          title: 'Go cilium/ebpf Iteration & Pinning',
          detail: 'Go calls objs.PktCountMap.Iterate() or objs.PktCountMap.Lookup(&key, &perCpuValues) to aggregate metrics across cores.'
        }
      ],
      codeLanguage: 'c',
      codeTitle: 'percpu_counter.bpf.c — Lockless Per-CPU Packet & Byte Accounting',
      codeSnippet: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct datarec {
    __u64 rx_packets;
    __u64 rx_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct datarec);
} xdp_stats_map SEC(".maps");

SEC("xdp")
int xdp_stats_count(struct xdp_md *ctx) {
    __u32 key = 0;
    struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
    if (!rec)
        return XDP_ABORTED; // Mandatory Verifier null-pointer check

    // No atomic lock needed! Each CPU core writes to its own slice
    rec->rx_packets++;
    rec->rx_bytes += (ctx->data_end - ctx->data);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`
    },
    whyUseInsteadOf: {
      heading: 'Why Use Per-CPU Maps & LRU Hash Maps Instead of Standard Hash Maps?',
      primaryTech: 'Per-CPU Maps & LRU Hash Maps',
      alternativeTech: 'Standard BPF_MAP_TYPE_HASH',
      rationaleParagraphs: [
        'On a modern 128-core server processing 20 million packets or syscalls per second, if all 128 cores simultaneously increment the same counter in a standard `BPF_MAP_TYPE_HASH` using `__sync_fetch_and_add`, CPU cache-line bouncing (MESI protocol invalidation) becomes a massive bottleneck.',
        'Furthermore, a standard `BPF_MAP_TYPE_HASH` stops accepting new keys once `max_entries` is reached (`-ENOSPC`), which can blind a connection tracker under ephemeral port churn. Using `BPF_MAP_TYPE_PERCPU_ARRAY` eliminates lock contention completely, while `BPF_MAP_TYPE_LRU_HASH` automatically evicts the least-recently-used key when full.'
      ],
      comparisonTable: [
        {
          dimension: 'Multi-Core Write Contention',
          primaryChoice: 'Zero lock contention — dedicated L1-cached slot per CPU',
          alternativeChoice: 'Requires atomic lock (__sync_fetch_and_add), cache-line bouncing',
          winner: 'primary'
        },
        {
          dimension: 'Behavior When Map is Full',
          primaryChoice: 'LRU_HASH automatically evicts oldest inactive entry',
          alternativeChoice: 'Standard HASH returns -ENOSPC and drops new updates',
          winner: 'primary'
        },
        {
          dimension: 'Kernel Memory Footprint',
          primaryChoice: 'Multiplied by number of CPU cores (N_CPUS * entry_size)',
          alternativeChoice: 'Single shared allocation across all cores',
          winner: 'alternative'
        },
        {
          dimension: 'Cross-CPU Read Consistency',
          primaryChoice: 'Userspace sums slice of values across all CPUs on read',
          alternativeChoice: 'Single immediate value read in kernel or userspace',
          winner: 'alternative'
        }
      ],
      whenToUsePrimary: [
        'High-frequency counters, bandwidth meters, and latency histograms (`BPF_MAP_TYPE_PERCPU_ARRAY`).',
        'Tracking active TCP connections or PID start times (`BPF_MAP_TYPE_LRU_HASH`).'
      ],
      whenToUseAlternative: [
        'Configuration tables written by Go userspace and read by the kernel (e.g., blocked IP list or policy rules).',
        'Correlating state across CPU migrations when a thread starts a syscall on CPU 0 and finishes on CPU 4.'
      ]
    },
    comprehensionCheck: {
      question: 'What happens if you call `struct val *v = bpf_map_lookup_elem(&my_map, &key);` and immediately write `v->count++;` without an `if (!v)` check?',
      options: [
        'The kernel automatically allocates a zeroed entry if the key is missing.',
        'The eBPF Verifier rejects the program at load time with an `R0 invalid mem access \'map_value_or_null\'` error.',
        'The program compiles and loads, but silently ignores the increment at runtime.',
        'Go `cilium/ebpf` automatically inserts the `if (!v)` check during ELF loading.'
      ],
      correctIndex: 1,
      explanation:
        'The Verifier tracks pointer nullability in register R0 (`map_value_or_null`) and refuses to load any program that dereferences a potentially NULL map lookup result.'
    },
    relatedTutorialId: 'tut-beg-03-bpf-maps',
    simulatorPresetId: 'preset-xdp-firewall'
  },
  {
    id: 'ringbuf-vs-perf-events',
    index: '05',
    title: 'BPF Ring Buffers vs. Perf Event Arrays',
    subtitle: 'Zero-copy, globally ordered event streaming from Kernel to Go',
    category: 'BPF Maps & Ring Buffers',
    readTime: '11 min read',
    minKernel: 'Linux 5.8+',
    summary:
      'Learn why BPF_MAP_TYPE_RINGBUF replaced Perf Event Arrays as the gold standard for streaming real-time events to userspace.',
    whatIsIt: {
      heading: 'What is the BPF Ring Buffer (`BPF_MAP_TYPE_RINGBUF`)?',
      paragraphs: [
        'While BPF Hash and Array maps are ideal for in-kernel counters and state lookups, security monitoring and distributed tracing tools often need to stream individual, discrete events (e.g., *"PID 4120 executed `/bin/bash` with args `-i` at timestamp T"*) to userspace.',
        'Introduced in Linux 5.8, **`BPF_MAP_TYPE_RINGBUF`** is a Multi-Producer, Single-Consumer (MPSC) circular queue shared across all CPU cores. It enables eBPF programs to reserve variable-length records directly in memory-mapped pages and commit them to userspace with zero extra memory copying.'
      ],
      keyTakeaways: [
        'Two-step zero-copy API: `bpf_ringbuf_reserve(&rb, sizeof(struct event), 0)` followed by `bpf_ringbuf_submit(e, 0)`.',
        'Strict global ordering across all CPU cores—events arrive in Go `ringbuf.NewReader()` in the exact chronological order they were committed.',
        'Memory-shared across all CPUs: a single 16MB Ring Buffer handles spikes on any core, unlike Perf Buffers which allocate separate buffers per core.'
      ],
      mentalModelAnalogy:
        'A Perf Event Array is like having 64 separate checkout lanes (one per CPU core) where 63 lanes sit empty while lane 1 overflows during a burst, and you have to manually sort receipts by timestamp afterward. A BPF Ring Buffer is a single, high-speed shared conveyor belt with atomic ticket numbers that preserves exact arrival order and shares capacity across all cores.'
    },
    howItWorks: {
      heading: 'How Reserve/Submit Zero-Copy Streaming Works with Go',
      paragraphs: [
        'With legacy `BPF_MAP_TYPE_PERF_EVENT_ARRAY`, your eBPF program first had to construct the event struct on its precious 512-byte stack (or a scratch Per-CPU array) and then copy all the bytes into the perf buffer via `bpf_perf_event_output()`.',
        'With `BPF_MAP_TYPE_RINGBUF`, calling `bpf_ringbuf_reserve()` returns a direct pointer into the ring buffer memory itself! Your eBPF program populates fields directly inside the ring buffer (bypassing the 512-byte stack limitation entirely) and calls `bpf_ringbuf_submit()` to wake up the Go `ringbuf.Reader` via epoll.'
      ],
      lifecycleSteps: [
        {
          step: '01',
          actor: 'KERNEL_HOOK',
          title: 'bpf_ringbuf_reserve() Allocation',
          detail: 'Atomically reserves sizeof(struct event) bytes in the shared circular buffer and returns a validated pointer to the eBPF program.'
        },
        {
          step: '02',
          actor: 'VERIFIER',
          title: 'Mandatory Submit or Discard Enforcement',
          detail: 'The eBPF Verifier tracks reference state: every code branch after reserve() MUST call either bpf_ringbuf_submit() or bpf_ringbuf_discard().'
        },
        {
          step: '03',
          actor: 'BPF_MAP',
          title: 'Adaptive Epoll Wakeup Notification',
          detail: 'Committed records increment the consumer position and trigger a wakeup for waiting userspace epoll readers.'
        },
        {
          step: '04',
          actor: 'USERSPACE',
          title: 'Go ringbuf.NewReader() Decoding',
          detail: 'Go reads raw record bytes and decodes them with binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &event).'
        }
      ],
      codeLanguage: 'c',
      codeTitle: 'ringbuf_exec_audit.bpf.c — Zero-Copy Reserve & Submit Pattern',
      codeSnippet: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct exec_event {
    __u32 pid;
    __u32 uid;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB shared circular buffer
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_exec(struct trace_event_raw_sys_enter *ctx) {
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0; // Buffer full; safely drop

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`
    },
    whyUseInsteadOf: {
      heading: 'Why Do We Use BPF Ring Buffers Instead of Perf Event Arrays (`BPF_MAP_TYPE_PERF_EVENT_ARRAY`)?',
      primaryTech: 'BPF_MAP_TYPE_RINGBUF (Linux 5.8+)',
      alternativeTech: 'BPF_MAP_TYPE_PERF_EVENT_ARRAY',
      rationaleParagraphs: [
        'Before Linux 5.8, `BPF_MAP_TYPE_PERF_EVENT_ARRAY` was the only way to stream events to userspace. However, it suffered from three major operational flaws: (1) It allocated separate buffers *per CPU core*, wasting huge amounts of RAM on 64–128 core cloud nodes while still dropping events if a single core experienced a burst; (2) Events arriving on different CPUs were read out-of-order in userspace; and (3) Every event required an extra memory copy from the eBPF stack.',
        '`BPF_MAP_TYPE_RINGBUF` solves all three issues simultaneously with higher throughput and lower memory usage.'
      ],
      comparisonTable: [
        {
          dimension: 'Memory Efficiency on 64-Core Node',
          primaryChoice: 'Single shared buffer pool across all 64 cores',
          alternativeChoice: '64 isolated per-CPU buffers (wastes memory, drops on single-core spikes)',
          winner: 'primary'
        },
        {
          dimension: 'Event Ordering Guarantee',
          primaryChoice: 'Strictly ordered across all CPUs out-of-the-box',
          alternativeChoice: 'Out-of-order across CPUs; requires userspace sorting window',
          winner: 'primary'
        },
        {
          dimension: 'Data Copy & 512B Stack Pressure',
          primaryChoice: 'Zero-copy in-place construction via bpf_ringbuf_reserve()',
          alternativeChoice: 'Must build struct on 512B stack/per-cpu map then copy',
          winner: 'primary'
        },
        {
          dimension: 'Legacy Kernel Support (< 5.8)',
          primaryChoice: 'Requires Linux 5.8 or newer',
          alternativeChoice: 'Supported on older Linux 4.4–5.7 kernels',
          winner: 'alternative'
        }
      ],
      whenToUsePrimary: [
        'All modern Linux 5.8+ observability, security auditing, and network event streaming pipelines.',
        'Emitting large structs (>512 bytes) directly from kernel space to Go `cilium/ebpf/ringbuf`.'
      ],
      whenToUseAlternative: [
        'Supporting legacy enterprise distributions running kernels older than Linux 5.8 without backported ringbuf support.'
      ]
    },
    comprehensionCheck: {
      question: 'What happens if your eBPF program calls `bpf_ringbuf_reserve()` to allocate an event pointer `e`, checks a condition, and returns `0` early without calling `bpf_ringbuf_submit(e, 0)` or `bpf_ringbuf_discard(e, 0)`?',
      options: [
        'The ring buffer garbage collector automatically reclaims the memory after 1 second.',
        'The eBPF Verifier rejects the program at load time because an unreleased reference (`Unreleased reference id=1`) would deadlock the ring buffer.',
        'The Go reader receives a partial zeroed struct.',
        'Only half the event is written to disk.'
      ],
      correctIndex: 1,
      explanation:
        'The eBPF Verifier performs strict reference tracking on pointers returned by `bpf_ringbuf_reserve()`. Every exit path after a successful non-null reservation MUST release the reference via either `bpf_ringbuf_submit()` or `bpf_ringbuf_discard()`.'
    },
    relatedTutorialId: 'tut-mid-02-ringbuf-events',
    simulatorPresetId: 'preset-syscall-execve'
  },
  {
    id: 'core-btf-vs-bcc',
    index: '06',
    title: 'BTF & CO-RE (Compile Once – Run Everywhere)',
    subtitle: 'How portable eBPF binaries adapt to any kernel layout without Clang on hosts',
    category: 'Verifier, JIT & CO-RE',
    readTime: '15 min read',
    minKernel: 'Linux 5.2+ (CONFIG_DEBUG_INFO_BTF=y)',
    summary:
      'Understand how BPF Type Format (BTF), vmlinux.h, and CO-RE field relocations eliminated the need to ship heavy LLVM/Clang compilers to production servers.',
    whatIsIt: {
      heading: 'What Are BTF and CO-RE?',
      paragraphs: [
        'One of the hardest problems in Linux systems programming is that internal kernel data structures (like `struct task_struct` or `struct sock`) change their field offsets across kernel versions and custom distro configurations. In Linux 5.4, `task->pid` might live at byte offset `0x490`; in Linux 6.1, a new security field added above it might shift `task->pid` to offset `0x4a8`.',
        '**BTF (BPF Type Format)** is a compact binary metadata format (~3MB) embedded directly inside modern Linux kernels at `/sys/kernel/btf/vmlinux` that describes every single struct, union, enum, and function signature in the running kernel.',
        '**CO-RE (Compile Once – Run Everywhere)** brings together kernel BTF, compiler relocation records emitted by Clang, and the Go `cilium/ebpf` loader so you can compile your eBPF `.o` binary **once** in CI/CD and run it on any Linux kernel version—automatically patching struct byte offsets at load time!'
      ],
      keyTakeaways: [
        '`bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h` generates a single self-contained header with every kernel struct—no `/lib/modules/.../build` headers needed.',
        '`BPF_CORE_READ(task, real_parent, pid)` records the symbolic field names in the ELF binary rather than hardcoding fragile byte offsets.',
        'When Go `cilium/ebpf` loads the ELF object on a target machine, it compares the binary BTF with the host `/sys/kernel/btf/vmlinux` and rewrites the instruction offsets before calling `bpf(BPF_PROG_LOAD)`.'
      ],
      mentalModelAnalogy:
        'Without CO-RE, reading a kernel struct is like giving directions by step count ("walk exactly 490 steps north")—if the building layout changes slightly, you walk into a wall. CO-RE is like giving directions by room label ("go to the room labeled `real_parent`, then open the drawer labeled `pid`"), and the loader looks up the floor plan (`vmlinux` BTF) upon arrival.'
    },
    howItWorks: {
      heading: 'How CO-RE Field Relocations Work at Load Time',
      paragraphs: [
        'When you use `BPF_CORE_READ(src, a, b)` or `__preserve_access_index` in your `.bpf.c` file, Clang emits special `.BTF.ext` relocation records inside the compiled `.o` file. These records capture the type name (`struct task_struct`) and field access string.',
        'When your Go binary runs in production, `cilium/ebpf` reads the embedded `.o` file, parses the host kernel `/sys/kernel/btf/vmlinux`, calculates the exact byte offset of `task_struct.real_parent` on *that specific host*, and patches the immediate offset inside the eBPF load instruction before sending it to the kernel Verifier.'
      ],
      lifecycleSteps: [
        {
          step: '01',
          actor: 'USERSPACE',
          title: 'Generate vmlinux.h & Compile with -g',
          detail: 'Clang compiles C code with -target bpf -g -O2, emitting .BTF and .BTF.ext CO-RE relocation tables into the ELF .o file.'
        },
        {
          step: '02',
          actor: 'USERSPACE',
          title: 'Host Kernel BTF Inspection (/sys/kernel/btf/vmlinux)',
          detail: 'Go cilium/ebpf loads the running host kernel BTF type graph in memory.'
        },
        {
          step: '03',
          actor: 'USERSPACE',
          title: 'Instruction Offset Relocation Patching',
          detail: 'cilium/ebpf matches struct task_struct field names and patches eBPF instruction offsets (e.g., 0x490 -> 0x4a8) in memory.'
        },
        {
          step: '04',
          actor: 'VERIFIER',
          title: 'BTF-Aware Verification',
          detail: 'The patched instructions are submitted via bpf(BPF_PROG_LOAD) and verified against the running kernel types.'
        }
      ],
      codeLanguage: 'c',
      codeTitle: 'core_task_lineage.bpf.c — Navigating Kernel Pointers Safely with BPF_CORE_READ',
      codeSnippet: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

SEC("tracepoint/sched/sched_process_exec")
int trace_lineage(struct trace_event_raw_sched_process_exec *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // Safely traverse task -> real_parent -> pid with CO-RE offset relocation!
    pid_t ppid = BPF_CORE_READ(task, real_parent, tgid);
    pid_t pid  = BPF_CORE_READ(task, tgid);

    bpf_printk("Process spawned: PID=%d by Parent PPID=%d\\n", pid, ppid);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`
    },
    whyUseInsteadOf: {
      heading: 'Why Do We Use CO-RE (`libbpf` / `cilium/ebpf`) Instead of BCC (BPF Compiler Collection)?',
      primaryTech: 'CO-RE (cilium/ebpf + BTF)',
      alternativeTech: 'Legacy BCC (Python + Runtime Clang)',
      rationaleParagraphs: [
        'First-generation eBPF tools used **BCC (BPF Compiler Collection)**, which solved kernel header differences by shipping the entire Clang/LLVM compiler toolchain inside your production container and compiling C code from source at startup against `/lib/modules/$(uname -r)/build` installed on every node.',
        'In modern cloud-native environments (distroless containers, Bottlerocket, Talos, GKE Container-Optimized OS), kernel headers are not installed on nodes, and running Clang at pod startup consumes 300MB+ of RAM and spikes CPU for several seconds. **CO-RE completely replaces runtime compilation** with a tiny, self-contained static Go binary (~10MB) that starts in milliseconds.'
      ],
      comparisonTable: [
        {
          dimension: 'Production Container Image Size',
          primaryChoice: '~10–25 MB static Go binary (zero compiler dependencies)',
          alternativeChoice: '400+ MB image containing LLVM, Clang, Python, and libc',
          winner: 'primary'
        },
        {
          dimension: 'Host Kernel Header Requirement',
          primaryChoice: 'None — uses built-in /sys/kernel/btf/vmlinux (~3MB)',
          alternativeChoice: 'Requires linux-headers-$(uname -r) installed on every host',
          winner: 'primary'
        },
        {
          dimension: 'Startup Time & Memory Spike',
          primaryChoice: '< 50ms startup, < 15MB RAM footprint',
          alternativeChoice: '3–10 seconds CPU/RAM spike compiling C code at startup',
          winner: 'primary'
        },
        {
          dimension: 'Ad-Hoc One-Liner Scripting',
          primaryChoice: 'Requires build step (go generate / clang)',
          alternativeChoice: 'bpftrace / BCC great for quick interactive SSH debugging',
          winner: 'alternative'
        }
      ],
      whenToUsePrimary: [
        'All production daemons, Kubernetes DaemonSets, security agents, and distribute-anywhere CLI tools.',
        'Any Go (`cilium/ebpf`) or Rust (`aya` / `libbpf-rs`) project.'
      ],
      whenToUseAlternative: [
        'Using `bpftrace` one-liners during an interactive incident response session on a single server.'
      ]
    },
    comprehensionCheck: {
      question: 'How does a CO-RE eBPF binary compiled on a developer laptop (running Linux 6.1) still read the correct `task->real_parent->tgid` field when deployed to a production server running Linux 5.15?',
      options: [
        'It downloads the Linux 5.15 source code from kernel.org at runtime and recompiles.',
        'The Go `cilium/ebpf` loader inspects the host `/sys/kernel/btf/vmlinux` metadata and relocates the instruction byte offsets before loading the program into the kernel.',
        '`struct task_struct` has never changed its memory layout since Linux 2.6.',
        'The kernel Verifier automatically converts C code from source.'
      ],
      correctIndex: 1,
      explanation:
        'CO-RE embeds BTF field relocation records in the ELF `.o` file; `cilium/ebpf` compares those records against the target host `/sys/kernel/btf/vmlinux` and patches the exact field offsets at load time.'
    },
    relatedTutorialId: 'tut-adv-01-core-btf',
    simulatorPresetId: 'preset-syscall-execve'
  },
  {
    id: 'ebpf-static-verifier-internals',
    index: '07',
    title: 'Inside the eBPF Verifier: Register Tracking & Safety Rules',
    subtitle: 'How the kernel mathematically proves your program is safe to execute',
    category: 'Verifier, JIT & CO-RE',
    readTime: '16 min read',
    minKernel: 'Linux 4.14+',
    summary:
      'Decode eBPF Verifier error logs like a seasoned kernel hacker: understand register types (R0–R10), pointer arithmetic rules, bounded loops, and reference tracking.',
    whatIsIt: {
      heading: 'What is the eBPF Static Verifier?',
      paragraphs: [
        'The **eBPF Verifier** (`kernel/bpf/verifier.c` in the Linux kernel tree) is the gatekeeper of kernel safety. Whenever a userspace process calls `bpf(BPF_PROG_LOAD)`, the Verifier performs a two-pass static analysis over the submitted eBPF bytecode before the program can ever be JIT-compiled or attached.',
        'First, it performs a depth-first search (DFS) on the Control Flow Graph (CFG) to forbid unreachable instructions and unbounded backward jumps. Second, it simulates the execution of **every possible instruction path**, tracking the exact data type, pointer bounds, alignment, and numeric min/max range of all 11 virtual registers (`R0` through `R10`) and every byte of the 512-byte stack.'
      ],
      keyTakeaways: [
        '`R0`: Holds return value from helper functions and the final exit code of the eBPF program.',
        '`R1–R5`: Scratch registers used to pass up to 5 arguments to BPF helper functions (clobbered after every `call` instruction!).',
        '`R6–R9`: Callee-saved registers preserved across BPF helper function calls.',
        '`R10`: Read-only frame pointer pointing to the top of the 512-byte eBPF stack (`fp-8`, `fp-16`, etc.).'
      ],
      mentalModelAnalogy:
        'The eBPF Verifier is like an ultra-strict Rust borrow checker combined with a symbolic execution engine running inside the kernel: it simulates every `if/else` branch with abstract register types (`ctx`, `pkt`, `map_value_or_null`, `scalar`) and rejects the program if even one theoretical path could touch invalid memory.'
    },
    howItWorks: {
      heading: 'How to Read Verifier State Logs & Fix Common Rejections',
      paragraphs: [
        'When the Verifier rejects your program, `cilium/ebpf` returns a `VerifierError` containing the kernel verifier log. Each line shows the instruction index, the bytecode operation, and the current tracked state of the registers—for example: `12: (79) r3 = *(u64 *)(r0 +0) ; R0_w=map_value_or_null(id=1,off=0,ks=4,vs=8)`.',
        'Here, `R0` has type `map_value_or_null` because it came from `bpf_map_lookup_elem()`. Because `r3 = *(u64 *)(r0 + 0)` attempts to dereference `R0` before checking `if (r0 == 0) goto exit`, the Verifier halts with `R0 invalid mem access \'map_value_or_null\'`.'
      ],
      lifecycleSteps: [
        {
          step: '01',
          actor: 'VERIFIER',
          title: 'Pass 1: Control Flow Graph (CFG) & Loop Check',
          detail: 'Ensures no unreachable instructions exist and that any loops are provably bounded within the 1 million verified instruction limit.'
        },
        {
          step: '02',
          actor: 'VERIFIER',
          title: 'Pass 2: Symbolic Register & Stack Simulation',
          detail: 'Walks every branch, tracking register states: PTR_TO_CTX, PTR_TO_PACKET, PTR_TO_MAP_VALUE_OR_NULL, SCALAR_VALUE(umin, umax).'
        },
        {
          step: '03',
          actor: 'VERIFIER',
          title: 'Helper Privilege & Reference Leak Check',
          detail: 'Verifies that all called helpers are permitted for the program type (e.g., XDP vs Kprobe) and all ringbuf/sk references are released.'
        },
        {
          step: '04',
          actor: 'VERIFIER',
          title: 'State Pruning & JIT Handoff',
          detail: 'Marks program VERIFIED SAFE and hands bytecode to the architecture JIT compiler.'
        }
      ],
      codeLanguage: 'c',
      codeTitle: 'verifier_safe_patterns.bpf.c — The 3 Golden Rules of Verifier Survival',
      codeSnippet: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// RULE 1: Always check packet pointer bounds before dereferencing in XDP/TC
// if ((void *)(hdr + 1) > data_end) return XDP_PASS;

// RULE 2: Always check map lookup pointers for NULL before use
// struct val *v = bpf_map_lookup_elem(&map, &key);
// if (!v) return 0;

// RULE 3: Use bpf_probe_read_kernel() / BPF_CORE_READ() for arbitrary kernel pointers
// Never dereference an untrusted task->mm->arg_start pointer with raw C *ptr!
SEC("kprobe/do_sys_openat2")
int safe_open_trace(struct pt_regs *ctx) {
    char filename[64];
    const char *user_ptr = (const char *)PT_REGS_PARM2(ctx);

    // Safely copy userspace string into stack buffer; handles page faults gracefully
    bpf_probe_read_user_str(&filename, sizeof(filename), user_ptr);
    bpf_printk("Opening file: %s\\n", filename);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`
    },
    whyUseInsteadOf: {
      heading: 'Why Does eBPF Enforce Static Verification Instead of Runtime Memory Sandboxing (Wasm / SFI)?',
      primaryTech: 'Compile/Load-Time Static Verification',
      alternativeTech: 'Runtime Bounds Checking (WebAssembly / SFI)',
      rationaleParagraphs: [
        'One might wonder why the Linux kernel doesn’t simply mask every memory access at runtime (like WebAssembly Software Fault Isolation does) instead of rejecting programs at load time via a strict Static Verifier.',
        'The reason is **zero runtime overhead and direct kernel pointer integration**. When an XDP program runs at 40Gbps (60 million packets per second, or 16 nanoseconds per packet), adding runtime bounds-masking instructions to every memory load would consume 25–40% of the CPU budget. By proving safety statically *once* at load time, the JIT-compiled eBPF code runs raw, unmasked native CPU instructions at the exact same speed as compiled kernel C code.'
      ],
      comparisonTable: [
        {
          dimension: 'Runtime Memory Access Overhead',
          primaryChoice: '0% overhead — compiles to direct native CPU load/store',
          alternativeChoice: '15–35% overhead from runtime bounds masking on every load',
          winner: 'primary'
        },
        {
          dimension: 'Zero-Copy Kernel Struct Access',
          primaryChoice: 'Directly reads live kernel structs via BTF pointers',
          alternativeChoice: 'Requires serializing/copying data into linear sandbox heap',
          winner: 'primary'
        },
        {
          dimension: 'Developer Learning Curve',
          primaryChoice: 'Steeper initially — must satisfy Verifier proofs',
          alternativeChoice: 'Easier — arbitrary loops and dynamic heaps allowed',
          winner: 'alternative'
        }
      ],
      whenToUsePrimary: [
        'All kernel-space networking, tracing, security, and scheduling logic.'
      ],
      whenToUseAlternative: [
        'Complex userspace plugin extensions (e.g., Envoy Wasm HTTP filters parsing large JSON payloads in userspace).'
      ]
    },
    comprehensionCheck: {
      question: 'In an eBPF verifier log, what does the error `R1_w=scalar(umin=0,umax=4294967295) R2=pkt_end() invalid access to packet, off=0 size=14` indicate?',
      options: [
        'Your program exceeded the 512-byte stack limit.',
        'You forgot to declare `char LICENSE[] SEC("license") = "GPL";`.',
        'You attempted to read 14 bytes of packet data without proving to the verifier that the packet pointer plus 14 is less than or equal to `ctx->data_end`.',
        'The network interface card is offline.'
      ],
      correctIndex: 2,
      explanation:
        'The verifier requires an explicit branch condition `if ((void *)(data + 14) > data_end) return XDP_PASS;` so it knows at least 14 bytes are safely readable in the packet buffer.'
    },
    relatedTutorialId: 'tut-beg-02-xdp-counter',
    simulatorPresetId: 'preset-xdp-firewall'
  },
  {
    id: 'uprobes-userspace-tracing',
    index: '08',
    title: 'Uprobes & Uretprobes: Tracing Userspace & TLS Without Restarting Apps',
    subtitle: 'Intercepting OpenSSL, Go, Node.js, and libc functions from the kernel',
    category: 'Kernel Hook Subsystems',
    readTime: '12 min read',
    minKernel: 'Linux 4.17+',
    summary:
      'Learn how eBPF attaches to functions inside userspace binaries and shared libraries (like libssl.so or bash) to capture plaintext TLS traffic or track memory leaks.',
    whatIsIt: {
      heading: 'What Are Uprobes and Uretprobes?',
      paragraphs: [
        'While Kprobes and Tracepoints instrument functions inside the Linux kernel, **Uprobes (User-space Probes)** and **Uretprobes** allow eBPF programs to attach to functions inside *userspace* executables and shared libraries (`.so` files)—without recompiling, restarting, or modifying the target application!',
        'When a Uprobe fires on a function like `SSL_write` in `libssl.so.3`, `readline` in `/bin/bash`, or `malloc` in `libc.so.6`, the CPU traps into kernel mode, runs your eBPF program with access to the userspace function arguments, and transparently resumes the application.'
      ],
      keyTakeaways: [
        'Plaintext TLS observability: hooking `SSL_write` and `SSL_read` captures HTTP/2 and gRPC payloads *before* encryption and *after* decryption—with zero CA certificate spoofing or sidecar proxies.',
        'Interactive shell auditing: hooking `/bin/bash:readline` via `uretprobe` captures every command typed by an interactive user even inside an encrypted SSH session.',
        'Attachment is inode-based: attaching a uprobe to `/lib/x86_64-linux-gnu/libc.so.6` automatically traces every process on the system sharing that library page cache.'
      ],
      mentalModelAnalogy:
        'If encrypted TLS traffic on the network wire (`XDP`/`TC`) is an armored truck carrying locked briefcases, a Uprobe on `SSL_write` stands inside the bank vault right next to the clerk putting documents into the briefcase before the lock is clicked shut.'
    },
    howItWorks: {
      heading: 'How Uprobe Breakpoint Traps & Symbol Resolution Work',
      paragraphs: [
        'When your Go `cilium/ebpf` loader calls `ex, _ := link.OpenExecutable("/usr/lib/libssl.so.3")` and `ex.Uprobe("SSL_write", prog, nil)`, the library parses the ELF symbol table (`.symtab` or `.dynsym`) of the binary to find the file offset of `SSL_write`.',
        'The kernel then replaces the instruction at that page-cache offset with a software trap instruction (`int3` / `0xcc` on x86_64). When any process executes that instruction, the CPU triggers a trap into the kernel, runs your eBPF program (which reads userspace memory using `bpf_probe_read_user()`), executes the displaced instruction out-of-line, and returns to userspace.'
      ],
      lifecycleSteps: [
        {
          step: '01',
          actor: 'USERSPACE',
          title: 'ELF Symbol Table Offset Resolution',
          detail: 'Go link.OpenExecutable("/lib/x86_64-linux-gnu/libssl.so.3") resolves the virtual offset of SSL_write.'
        },
        {
          step: '02',
          actor: 'KERNEL_HOOK',
          title: 'Page-Cache Breakpoint Injection (int3)',
          detail: 'Kernel patches the target instruction in the shared memory page cache with a trap instruction.'
        },
        {
          step: '03',
          actor: 'KERNEL_HOOK',
          title: 'Trap Entry & bpf_probe_read_user()',
          detail: 'When the app calls SSL_write(ssl, buf, num), the eBPF program reads the plaintext buffer from PT_REGS_PARM2(ctx).'
        },
        {
          step: '04',
          actor: 'BPF_MAP',
          title: 'RingBuffer Emission to Go Collector',
          detail: 'Plaintext payload and PID metadata are submitted to a BPF Ring Buffer for HTTP/SQL protocol parsing.'
        }
      ],
      codeLanguage: 'c',
      codeTitle: 'uprobe_ssl_sniff.bpf.c — Capturing Plaintext TLS Payloads Before Encryption',
      codeSnippet: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct ssl_data_event {
    __u32 pid;
    __u32 len;
    char buf[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} tls_events SEC(".maps");

// int SSL_write(SSL *ssl, const void *buf, int num);
SEC("uprobe/SSL_write")
int BPF_KPROBE(probe_ssl_write, void *ssl, const char *buf, int num) {
    if (num <= 0)
        return 0;

    struct ssl_data_event *e = bpf_ringbuf_reserve(&tls_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->len = num < 256 ? num : 256;
    bpf_probe_read_user(&e->buf, e->len, buf);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`
    },
    whyUseInsteadOf: {
      heading: 'Why Do We Use Uprobes Instead of Sidecar Proxies, LD_PRELOAD, or Code SDKs?',
      primaryTech: 'eBPF Uprobes',
      alternativeTech: 'MITM Sidecar Proxies & Language SDKs',
      rationaleParagraphs: [
        'Traditional APM tools require either modifying source code in every language (Go, Python, Rust, Java, C++) to import OpenTelemetry SDKs, or injecting `LD_PRELOAD` shared libraries (which fail on static binaries and require restarting processes), or deploying TLS-terminating MITM proxies that break mutual TLS (mTLS) and add network hops.',
        'Uprobes attach dynamically from outside the container without touching application configuration, certificates, or environment variables—and can be detached cleanly at any time.'
      ],
      comparisonTable: [
        {
          dimension: 'Zero-Restart Live Attachment',
          primaryChoice: 'Attach/detach to already-running processes instantaneously',
          alternativeChoice: 'LD_PRELOAD and SDKs require restarting every pod/process',
          winner: 'primary'
        },
        {
          dimension: 'TLS Inspection Without Breaking mTLS',
          primaryChoice: 'Reads plaintext inside process before encryption; preserves certs',
          alternativeChoice: 'MITM proxies break certificate pinning and add network hop',
          winner: 'primary'
        },
        {
          dimension: 'Per-Call CPU Overhead',
          primaryChoice: '~1,000–2,500 ns (CPU trap context switch from user to kernel)',
          alternativeChoice: 'In-process SDKs run in ~50–200 ns without kernel trap',
          winner: 'alternative'
        }
      ],
      whenToUsePrimary: [
        'Zero-code TLS/HTTP observability (`SSL_read` / `SSL_write` or Go `crypto/tls`).',
        'Auditing shell commands (`bash:readline`), database queries (`mysqld` dispatch_command), or profiling memory leaks.'
      ],
      whenToUseAlternative: [
        'Ultra-high-frequency inner loops called 10+ million times per second per thread (where the `int3` trap overhead would be noticeable; prefer kernel tracepoints or sampling profilers instead).'
      ]
    },
    comprehensionCheck: {
      question: 'Why must an eBPF Uprobe program use `bpf_probe_read_user()` instead of `bpf_probe_read_kernel()` when reading a string buffer passed to `SSL_write`?',
      options: [
        '`bpf_probe_read_user()` automatically decrypts AES-GCM ciphertext.',
        'The buffer pointer passed to `SSL_write` resides in the userspace virtual address space of the process, which requires separate fault-tolerant userspace page handling on architectures with SMAP/PAN.',
        '`bpf_probe_read_kernel()` only works inside XDP programs.',
        'Userspace strings are encoded in UTF-32.'
      ],
      correctIndex: 1,
      explanation:
        'Modern CPUs isolate kernel and userspace virtual address spaces (SMAP on x86, PAN on ARM64). `bpf_probe_read_user()` safely reads from userspace virtual addresses and gracefully handles unmapped/swapped-out pages by zeroing the destination buffer rather than crashing.'
    },
    relatedTutorialId: 'tut-adv-02-uprobe-tls',
    simulatorPresetId: 'preset-uprobe-ssl'
  },
  {
    id: 'bpf-lsm-runtime-security',
    index: '09',
    title: 'BPF LSM (Linux Security Modules) vs. Seccomp & Auditd',
    subtitle: 'Inline mandatory access control and container escape prevention',
    category: 'Kernel Hook Subsystems',
    readTime: '13 min read',
    minKernel: 'Linux 5.7+ (CONFIG_BPF_LSM=y)',
    summary:
      'Understand why observing an attack at the syscall boundary is vulnerable to TOCTOU race conditions, and how BPF LSM enforces policy directly on kernel objects.',
    whatIsIt: {
      heading: 'What is BPF LSM (KRSI)?',
      paragraphs: [
        'For years, security engineers used eBPF on syscall tracepoints (`sys_enter_openat`, `sys_enter_execve`) to detect malicious activity. However, syscall arguments are **raw userspace pointers**: between the moment your eBPF tracepoint reads a filename string from userspace memory and the moment the kernel actually opens the file, a malicious thread in the same process can overwrite that userspace string in memory—a classic **TOCTOU (Time-Of-Check to Time-Of-Use)** attack!',
        '**BPF LSM (Linux Security Modules)** attaches eBPF programs directly to the internal kernel security hooks (the exact same hooks used by SELinux and AppArmor, such as `lsm/file_open`, `lsm/bprm_check_security`, and `lsm/socket_connect`). At this point, the kernel has already copied and resolved the path into trusted, immutable kernel objects (`struct file *`, `struct inode *`), and returning `-EPERM` (`-1`) blocks the operation inline!'
      ],
      keyTakeaways: [
        'Immune to TOCTOU race conditions: operates on resolved kernel structures (`struct file *`, `struct linux_binprm *`, `struct sockaddr *`) instead of mutable userspace pointers.',
        'Inline blocking: returning `-EPERM` from a BPF LSM program immediately aborts the file open, binary execution, or outbound socket connection before damage occurs.',
        'Dynamic per-container policy: combines cgroup IDs and BPF maps so Kubernetes security agents (like Cilium Tetragon) can enforce fine-grained rules per Pod.'
      ],
      mentalModelAnalogy:
        'Checking a syscall (`sys_enter_openat`) is like checking a photocopy of a passport that the traveler is still holding in their hand and can swap out before walking through the gate. BPF LSM (`lsm/file_open`) inspects the verified biometric record inside the border officer’s secure terminal and controls the physical turnstile lock.'
    },
    howItWorks: {
      heading: 'How BPF LSM Hooks Inspect Kernel Objects & Return -EPERM',
      paragraphs: [
        'BPF LSM hooks use the modern `BPF_PROG` macro with BTF type awareness. For example, `SEC("lsm/file_open")` receives `struct file *file` directly as a typed BTF pointer, along with `int ret` (the return value of any previous LSM hook).',
        'If your eBPF program returns `0`, the operation is allowed. If it returns `-EPERM` (`-1`), the kernel immediately halts the operation and returns `Permission denied` to the calling process—with zero asynchronous race window.'
      ],
      lifecycleSteps: [
        {
          step: '01',
          actor: 'USERSPACE',
          title: 'Process Invokes openat("/etc/shadow")',
          detail: 'Process executes system call; kernel VFS layer resolves path into an in-kernel struct file and struct inode.'
        },
        {
          step: '02',
          actor: 'KERNEL_HOOK',
          title: 'security_file_open() LSM Hook Fires',
          detail: 'Kernel invokes attached BPF LSM program with resolved struct file * pointer before granting file descriptor.'
        },
        {
          step: '03',
          actor: 'BPF_MAP',
          title: 'Inode / Container Cgroup Policy Match',
          detail: 'BPF program checks file->f_inode->i_ino and process cgroup_id against a BPF policy map.'
        },
        {
          step: '04',
          actor: 'KERNEL_HOOK',
          title: 'Inline -EPERM Denial + Audit RingBuf Event',
          detail: 'Program emits a high-priority alert to the Ring Buffer and returns -1 (-EPERM), blocking the read inline.'
        }
      ],
      codeLanguage: 'c',
      codeTitle: 'lsm_shadow_protect.bpf.c — Inline TOCTOU-Proof File Access Prevention',
      codeSnippet: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1

SEC("lsm/file_open")
int BPF_PROG(restrict_sensitive_file, struct file *file, int ret) {
    if (ret != 0)
        return ret; // Respect denial from earlier LSM

    __u32 uid = bpf_get_current_uid_gid();
    unsigned long ino = BPF_CORE_READ(file, f_inode, i_ino);

    // Block non-root containers attempting to open restricted sensitive inode
    if (ino == 131074 && uid != 0) {
        bpf_printk("BPF LSM BLOCKED unauthorized access to sensitive inode %lu\\n", ino);
        return -EPERM;
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`
    },
    whyUseInsteadOf: {
      heading: 'Why Do We Use BPF LSM Instead of Syscall Tracepoints or Seccomp-BPF?',
      primaryTech: 'BPF LSM (Linux 5.7+)',
      alternativeTech: 'Syscall Tracepoints / Seccomp-BPF',
      rationaleParagraphs: [
        'Classic **Seccomp-BPF** (used by Docker) runs at the raw syscall boundary and **cannot dereference pointers at all**—so Seccomp can block `openat` entirely, but it cannot allow `openat("/app/config.json")` while blocking `openat("/etc/shadow")`!',
        'Meanwhile, **Syscall Tracepoints** can read the filename pointer via `bpf_probe_read_user_str`, but they cannot block the syscall (or if paired with `bpf_send_signal(SIGKILL)`, they remain vulnerable to TOCTOU pointer-swapping races and symlinks). **BPF LSM** inspects the resolved kernel object and blocks inline without killing the entire process unless desired.'
      ],
      comparisonTable: [
        {
          dimension: 'Immunity to TOCTOU & Symlink Tricks',
          primaryChoice: 'Complete — inspects resolved kernel struct file / inode',
          alternativeChoice: 'Vulnerable — reads raw userspace pointer before VFS resolution',
          winner: 'primary'
        },
        {
          dimension: 'Deep Argument Inspection (Paths, IPs)',
          primaryChoice: 'Full BTF pointer traversal across kernel structs',
          alternativeChoice: 'Seccomp-BPF cannot dereference any pointers',
          winner: 'primary'
        },
        {
          dimension: 'Inline Non-Fatal Denial (-EPERM)',
          primaryChoice: 'Returns -EPERM cleanly on single operation',
          alternativeChoice: 'Tracepoints are read-only (or must SIGKILL whole process)',
          winner: 'primary'
        }
      ],
      whenToUsePrimary: [
        'Blocking container escapes, sensitive file reads (`/etc/shadow`, Kubernetes service account tokens), or unauthorized outbound C2 connections.',
        'Implementing dynamic zero-trust runtime policies in Kubernetes.'
      ],
      whenToUseAlternative: [
        'Pure observability/metrics collection on kernels where `lsm=bpf` is not enabled in boot parameters.'
      ]
    },
    comprehensionCheck: {
      question: 'Why is checking a file path inside `tracepoint/syscalls/sys_enter_openat` vulnerable to a TOCTOU (Time-Of-Check to Time-Of-Use) bypass that `lsm/file_open` prevents?',
      options: [
        'Because `sys_enter_openat` only fires after the file has already been closed.',
        'Because `sys_enter_openat` reads the filename string from mutable userspace memory before the kernel copies and resolves it, allowing another thread to swap the string in between.',
        'Because tracepoints only inspect the first 4 characters of a filename.',
        'Because `lsm/file_open` encrypts all filenames on disk.'
      ],
      correctIndex: 1,
      explanation:
        'At the `sys_enter_openat` boundary, the filename still resides in userspace memory shared by all threads of that process. By the time `lsm/file_open` runs, the kernel VFS layer has already resolved the path into an immutable kernel `struct file` and `struct inode`.'
    },
    relatedTutorialId: 'tut-adv-03-lsm-security',
    simulatorPresetId: 'preset-lsm-security'
  },
  {
    id: 'go-cilium-ebpf-control-plane',
    index: '10',
    title: 'Go & cilium/ebpf: Building Cloud-Native Userspace Loaders',
    subtitle: 'How bpf2go, CollectionSpecs, Links, and RingBuf Readers work in Go',
    category: 'Go cilium/ebpf Control Plane',
    readTime: '14 min read',
    minKernel: 'Go 1.21+ / Linux 4.19+',
    summary:
      'Master the pure-Go eBPF library used by Cilium, Tetragon, and Cloudflare: generate Go bindings with bpf2go, manage bpf_link lifecycles, and decode binary events.',
    whatIsIt: {
      heading: 'What is `github.com/cilium/ebpf` and `bpf2go`?',
      paragraphs: [
        '`github.com/cilium/ebpf` is the industry-standard, pure-Go library for loading, verifying, pinning, and interacting with eBPF programs and maps. Unlike C wrappers that require `cgo` (which complicates cross-compilation and static container builds), `cilium/ebpf` is written in 100% pure Go—communicating directly with the Linux kernel via the `SYS_BPF` system call.',
        'It includes a code generator tool called **`bpf2go`**. By placing a single `//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf probe.bpf.c` directive in your `main.go`, running `go generate` automatically compiles your `.bpf.c` file with Clang, embeds the resulting ELF bytecode into your Go package using `//go:embed`, and generates strongly-typed Go structs for every BPF program, map, and C struct!'
      ],
      keyTakeaways: [
        '100% Pure Go (`CGO_ENABLED=0` compatible): produces a single static binary with embedded eBPF bytecode that runs in `FROM scratch` containers.',
        'Type-safe generated scaffolding: `loadBpfObjects(&objs, nil)` loads and verifies all maps and programs in one call.',
        'Safe lifecycle management with `github.com/cilium/ebpf/link`: when `defer l.Close()` runs (or if your Go process crashes), the kernel automatically detaches the eBPF hook cleanly unless explicitly pinned to `/sys/fs/bpf`.'
      ],
      mentalModelAnalogy:
        '`bpf2go` is to eBPF C code what `protoc` (gRPC Protobuf compiler) is to `.proto` files: you write the kernel contract in `.bpf.c`, and `bpf2go` generates clean, idiomatic, type-safe Go client structs so you never have to hardcode raw file descriptors or byte offsets.'
    },
    howItWorks: {
      heading: 'The 4-Step Go `cilium/ebpf` Lifecycle Pattern',
      paragraphs: [
        'Every production Go eBPF application follows a clean, deterministic four-step initialization sequence in `main.go`: (1) Remove `RLIMIT_MEMLOCK` on older kernels (`rlimit.RemoveMemlock()`), (2) Call the generated `loadBpfObjects(&objs, nil)` to create maps, perform CO-RE relocations, and verify programs, (3) Attach programs to kernel hooks via the `link` package (`link.AttachXDP`, `link.Kprobe`, `link.Tracepoint`, `link.AttachLSM`), and (4) Read telemetry in a loop via `ringbuf.NewReader(objs.Events)` or `time.Ticker` map polling.'
      ],
      lifecycleSteps: [
        {
          step: '01',
          actor: 'USERSPACE',
          title: 'go generate (bpf2go Code Generation)',
          detail: 'Compiles probe.bpf.c into bpf_bpfel.o and generates bpf_bpfel.go containing bpfObjects, bpfPrograms, and bpfMaps.'
        },
        {
          step: '02',
          actor: 'SYSCALL',
          title: 'loadBpfObjects(&objs, nil)',
          detail: 'Parses embedded ELF, applies BTF CO-RE relocations against /sys/kernel/btf/vmlinux, creates maps, and loads programs.'
        },
        {
          step: '03',
          actor: 'KERNEL_HOOK',
          title: 'link.Tracepoint / link.Kprobe / link.AttachXDP',
          detail: 'Attaches the verified *ebpf.Program to the target kernel hook and returns a link.Link handle.'
        },
        {
          step: '04',
          actor: 'USERSPACE',
          title: 'Graceful Context Cancellation & Cleanup',
          detail: 'Listens for SIGINT/SIGTERM, closes the ringbuf.Reader, and defers objs.Close() and link.Close().'
        }
      ],
      codeLanguage: 'go',
      codeTitle: 'main.go — Canonical Production Go Loader with cilium/ebpf',
      codeSnippet: `package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type exec_event bpf exec_audit.bpf.c

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExec, nil)
	if err != nil {
		log.Fatalf("attaching tracepoint: %v", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %v", err)
	}
	defer rd.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		rd.Close()
	}()

	log.Println("Waiting for execve events...")
	var event bpfExecEvent
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &event); err == nil {
			log.Printf("PID=%d UID=%d COMM=%s", event.Pid, event.Uid, string(event.Comm[:]))
		}
	}
}`
    },
    whyUseInsteadOf: {
      heading: 'Why Do We Use Pure-Go `cilium/ebpf` Instead of CGO `libbpfgo` or Python BCC?',
      primaryTech: 'Pure-Go cilium/ebpf + bpf2go',
      alternativeTech: 'CGO Wrappers (libbpfgo) or Python BCC',
      rationaleParagraphs: [
        'In the Go ecosystem, importing a library that uses `cgo` (`import "C"`) links your binary dynamically against the host `glibc` and `libbpf.so`. That means a binary built on Ubuntu 24.04 (`glibc 2.39`) will crash on Debian or Alpine (`musl`) unless you maintain complex Docker cross-compilation toolchains.',
        'Because `cilium/ebpf` implements ELF parsing, BTF CO-RE relocation, and `bpf()` syscalls in **100% pure Go**, you can build with `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build` on macOS or Linux and deploy a single static binary to any Linux host in the world.'
      ],
      comparisonTable: [
        {
          dimension: 'Static Binary Portability (CGO_ENABLED=0)',
          primaryChoice: '100% Pure Go — zero dynamic C library dependencies',
          alternativeChoice: 'Requires CGO, host glibc matching, and libelf/zlib',
          winner: 'primary'
        },
        {
          dimension: 'Code Generation & Struct Sync',
          primaryChoice: 'bpf2go auto-generates Go structs from BTF types (-type)',
          alternativeChoice: 'Manual C-to-Go struct padding and alignment maintenance',
          winner: 'primary'
        },
        {
          dimension: 'Kubernetes Ecosystem Integration',
          primaryChoice: 'Native integration with client-go, Prometheus, OpenTelemetry',
          alternativeChoice: 'Harder to embed in cloud-native Go operators',
          winner: 'primary'
        }
      ],
      whenToUsePrimary: [
        'Building cloud-native Kubernetes agents, CNI plugins, security daemons, and CLI observability tools in Go.'
      ],
      whenToUseAlternative: [
        'Writing embedded systems utilities in pure C/Rust where a Go runtime is not desired.'
      ]
    },
    comprehensionCheck: {
      question: 'What does passing `-type exec_event` to the `//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type exec_event bpf program.bpf.c` command accomplish?',
      options: [
        'It filters out all kernel events except `exec_event` inside the Linux kernel.',
        'It inspects the BTF debug info in the compiled `.o` file and automatically generates a memory-aligned Go struct (`type bpfExecEvent struct`) matching the C `struct exec_event`.',
        'It converts Go code into C code.',
        'It enables `cgo` compilation.'
      ],
      correctIndex: 1,
      explanation:
        'The `-type` flag instructs `bpf2go` to inspect the BTF metadata of the C struct and emit an exact, byte-aligned Go struct definition so `binary.Read` or map lookups work without manual padding errors.'
    },
    relatedTutorialId: 'tut-beg-01-execve',
    simulatorPresetId: 'preset-syscall-execve'
  },
  {
    id: 'tail-calls-vs-subprograms',
    index: '11',
    title: 'BPF Tail Calls vs. BPF-to-BPF Subprograms',
    subtitle: 'Composing complex multi-stage pipelines without hitting the 512-byte stack or verifier limits',
    category: 'Verifier, JIT & CO-RE',
    readTime: '11 min read',
    minKernel: 'Linux 4.16+ (Tail Call + Subprog in 5.10+)',
    summary:
      'Learn how large eBPF projects like Cilium and Katran chain up to 33 independent eBPF programs together via BPF_MAP_TYPE_PROG_ARRAY and bpf_tail_call().',
    whatIsIt: {
      heading: 'What Are BPF Tail Calls and BPF Subprograms?',
      paragraphs: [
        'When building production firewalls, load balancers, or deep protocol parsers in eBPF, placing all parsing and policy logic inside a single function eventually hits either the **512-byte stack limit** or the **1,000,000 verified instruction complexity cap**.',
        'Linux provides two mechanisms to modularize eBPF code: (1) **BPF Tail Calls (`bpf_tail_call`)**, which jump from one independent eBPF program into another program stored in a `BPF_MAP_TYPE_PROG_ARRAY` without returning to the caller, and (2) **BPF-to-BPF Subprograms**, which are regular non-inlined C functions that push a stack frame and return to the caller.'
      ],
      keyTakeaways: [
        'A successful `bpf_tail_call(ctx, &prog_array, idx)` replaces the current execution frame—acting like `execve()` for eBPF programs.',
        'Up to 33 tail calls can be chained sequentially, giving each stage its own fresh 1,000,000-instruction verifier budget and 512-byte stack.',
        'Because stack variables disappear across a tail call, stages share state using a 1-entry `BPF_MAP_TYPE_PERCPU_ARRAY` scratch buffer.'
      ],
      mentalModelAnalogy:
        'A BPF Subprogram is like calling a colleague on the phone and waiting for their answer before continuing your checklist. A BPF Tail Call is like handing the entire clipboard to the next specialist on an assembly line—you are completely done, and they get a fresh desk (`512B stack`) to finish the job.'
    },
    howItWorks: {
      heading: 'How `BPF_MAP_TYPE_PROG_ARRAY` Dispatching Works',
      paragraphs: [
        'In C, you define a `BPF_MAP_TYPE_PROG_ARRAY` map. In Go (`cilium/ebpf`), after loading your collection of eBPF programs, you populate slots of that map with the file descriptors of target programs (`objs.ProgArray.Put(uint32(1), objs.ParseTcp)`).',
        'When `bpf_tail_call(ctx, &jmp_table, 1)` executes in the kernel, the JIT compiler executes a direct native jump to the target program. If slot `1` is empty, `bpf_tail_call` is a no-op and execution falls through to the next line.'
      ],
      lifecycleSteps: [
        {
          step: '01',
          actor: 'USERSPACE',
          title: 'Populate BPF_MAP_TYPE_PROG_ARRAY in Go',
          detail: 'Go loader inserts target *ebpf.Program descriptors into the program array map by index key.'
        },
        {
          step: '02',
          actor: 'KERNEL_HOOK',
          title: 'Stage 1: L2/L3 Parser & Per-CPU Context Save',
          detail: 'Entry XDP program parses Ethernet/IP headers, stores offsets in a Per-CPU scratch map, and calls bpf_tail_call().'
        },
        {
          step: '03',
          actor: 'KERNEL_HOOK',
          title: 'Zero-Overhead Direct Jump to Stage 2',
          detail: 'Execution jumps directly to the Stage 2 JITed program, reusing the stack frame without returning.'
        },
        {
          step: '04',
          actor: 'USERSPACE',
          title: 'Atomic Feature Hot-Swapping',
          detail: 'Go can atomically update a slot in PROG_ARRAY at runtime to upgrade a parser stage with zero packet loss.'
        }
      ],
      codeLanguage: 'c',
      codeTitle: 'xdp_tail_call_pipeline.bpf.c — Multi-Stage Protocol Dispatcher',
      codeSnippet: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u32);
} jmp_table SEC(".maps");

SEC("xdp")
int xdp_entry_dispatcher(struct xdp_md *ctx) {
    __u32 tcp_stage_idx = 1;
    // Jump to TCP handler program registered at index 1
    bpf_tail_call(ctx, &jmp_table, tcp_stage_idx);

    // Execution only reaches here if slot 1 is empty or tail call limit (33) exceeded
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`
    },
    whyUseInsteadOf: {
      heading: 'Why Use BPF Tail Calls Instead of BPF Subprograms (or `__always_inline`)?',
      primaryTech: 'BPF Tail Calls (BPF_MAP_TYPE_PROG_ARRAY)',
      alternativeTech: 'BPF Subprograms / __always_inline Functions',
      rationaleParagraphs: [
        'While regular C functions (BPF Subprograms) are convenient for small reusable helpers that return values, the Verifier still analyzes the entire call tree under a single 1,000,000-instruction budget and restricts the combined stack depth across all nested function frames to 512 bytes total.',
        'Tail Calls verify each program independently and allow your Go control plane to dynamically rewire the execution pipeline at runtime simply by updating map entries.'
      ],
      comparisonTable: [
        {
          dimension: 'Verifier Complexity Budget',
          primaryChoice: 'Verified independently (up to 33 × 1M instructions)',
          alternativeChoice: 'Shares caller single 1M instruction verification limit',
          winner: 'primary'
        },
        {
          dimension: 'Runtime Hot-Swapping of Logic',
          primaryChoice: 'Swap individual stages live via BPF map update from Go',
          alternativeChoice: 'Static call graph compiled at build time',
          winner: 'primary'
        },
        {
          dimension: 'Returning Values to Caller',
          primaryChoice: 'Does not return to caller (one-way jump)',
          alternativeChoice: 'Returns values naturally like standard C functions',
          winner: 'alternative'
        }
      ],
      whenToUsePrimary: [
        'Multi-stage XDP/TC pipelines (L2 -> L3 -> L4 -> Policy -> NAT) and dynamic protocol parsers.'
      ],
      whenToUseAlternative: [
        'Small utility functions (checksum calculation, IPv4 header validation) that must return a result to the caller.'
      ]
    },
    comprehensionCheck: {
      question: 'Why can you NOT pass a pointer to a local stack variable from Program A to Program B across a `bpf_tail_call()`?',
      options: [
        'Because Program B runs in userspace.',
        'Because a tail call unwinds/replaces Program A’s stack frame with Program B’s fresh stack frame; state must be passed via a Per-CPU BPF map or packet metadata.',
        'Because tail calls only work on 32-bit integers.',
        'Because `bpf_tail_call` encrypts the stack.'
      ],
      correctIndex: 1,
      explanation:
        'A tail call replaces the current execution frame without returning, so local stack variables from the caller are discarded. Programs share state across tail calls via a 1-entry `BPF_MAP_TYPE_PERCPU_ARRAY` or `bpf_xdp_adjust_meta`.'
    },
    relatedTutorialId: 'tut-adv-05-tail-calls',
    simulatorPresetId: 'preset-xdp-firewall'
  },
  {
    id: 'sockops-sk-msg-service-mesh',
    index: '12',
    title: 'Socket Acceleration: Sockops & SK_MSG Service Mesh Bypass',
    subtitle: 'Short-circuiting the TCP/IP stack for ultra-low-latency pod and sidecar communication',
    category: 'Kernel Hook Subsystems',
    readTime: '13 min read',
    minKernel: 'Linux 4.19+',
    summary:
      'Discover how eBPF splices socket buffers directly in memory using BPF_MAP_TYPE_SOCKHASH, eliminating TCP/IP loopback overhead for local microservices.',
    whatIsIt: {
      heading: 'What Are `sockops` and `sk_msg` Programs?',
      paragraphs: [
        'When two containers on the same host—or an application container and its local proxy—communicate over TCP, the Linux kernel normally runs the payload through TCP segmentation, IP routing, iptables netfilter hooks, and virtual ethernet (`veth`) queues twice.',
        'By combining **`BPF_PROG_TYPE_SOCK_OPS`** (which tracks TCP socket state transitions like 3-way handshake completion) with **`BPF_PROG_TYPE_SK_MSG`** and a **`BPF_MAP_TYPE_SOCKHASH`** map, eBPF intercepts `sendmsg()` at the top of the socket layer and copies the payload bytes directly into the destination socket’s receive queue—completely bypassing the TCP/IP stack!'
      ],
      keyTakeaways: [
        '`sockops` attaches to a cgroup and listens for `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB` and `BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB`.',
        'Established local sockets are stored in a `BPF_MAP_TYPE_SOCKHASH` keyed by the 4-tuple `(src_ip, dst_ip, src_port, dst_port)`.',
        '`sk_msg` intercepts every `sendmsg()` call and invokes `bpf_msg_redirect_hash(msg, &sock_map, &peer_key, BPF_F_INGRESS)` for ~50% lower latency.'
      ],
      mentalModelAnalogy:
        'Standard loopback TCP is like mailing a letter to your next-door neighbor by dropping it at the central post office so a mail truck can drive it back to your street. `sk_msg` + `SOCKHASH` hands the letter directly across the fence.'
    },
    howItWorks: {
      heading: 'How `sockops` Populates `SOCKHASH` and `sk_msg` Redirects Payloads',
      paragraphs: [
        'As soon as a TCP connection completes its SYN / SYN-ACK / ACK handshake, the kernel fires the cgroup `sockops` hook. Your `sockops` program constructs the 4-tuple key for that socket and calls `bpf_sock_hash_update(skops, &sock_ops_map, &key, BPF_ANY)`.',
        'From that moment on, whenever the application writes data to that socket descriptor, the `sk_msg` program attached to `sock_ops_map` runs immediately, looks up the peer socket in `sock_ops_map`, and teleports the message directly into the peer’s ingress queue.'
      ],
      lifecycleSteps: [
        {
          step: '01',
          actor: 'KERNEL_HOOK',
          title: 'TCP Handshake Establishes (sockops Callback)',
          detail: 'Kernel triggers BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB and PASSIVE_ESTABLISHED_CB on the cgroup.'
        },
        {
          step: '02',
          actor: 'BPF_MAP',
          title: 'Register Socket in BPF_MAP_TYPE_SOCKHASH',
          detail: 'bpf_sock_hash_update() records the kernel struct sock pointer keyed by its IPv4 4-tuple.'
        },
        {
          step: '03',
          actor: 'KERNEL_HOOK',
          title: 'Application Calls write() / sendmsg()',
          detail: 'Attached sk_msg program intercepts the outgoing message buffer before TCP header construction.'
        },
        {
          step: '04',
          actor: 'BPF_MAP',
          title: 'Direct Socket Queue Splice (bpf_msg_redirect_hash)',
          detail: 'Payload is copied directly into the peer socket receive buffer, skipping TCP/IP and veth layers.'
        }
      ],
      codeLanguage: 'c',
      codeTitle: 'sockops_bypass.bpf.c — Short-Circuiting Local TCP Sockets via SOCKHASH',
      codeSnippet: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct sock_key {
    __u32 sip4;
    __u32 dip4;
    __u32 sport;
    __u32 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65535);
    __type(key, struct sock_key);
    __type(value, __u32);
} sock_ops_map SEC(".maps");

SEC("sk_msg")
int bpf_tcp_bypass(struct sk_msg_md *msg) {
    struct sock_key peer = {
        .sip4  = msg->remote_ip4,
        .dip4  = msg->local_ip4,
        .sport = __bpf_htonl(msg->remote_port) >> 16,
        .dport = msg->local_port,
    };
    bpf_msg_redirect_hash(msg, &sock_ops_map, &peer, BPF_F_INGRESS);
    return SK_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`
    },
    whyUseInsteadOf: {
      heading: 'Why Use eBPF `sockops`/`sk_msg` Instead of iptables REDIRECT or Standard Loopback?',
      primaryTech: 'eBPF Sockops + SK_MSG',
      alternativeTech: 'iptables REDIRECT / Standard TCP Loopback',
      rationaleParagraphs: [
        'In Kubernetes service meshes, routing traffic between an application container and a proxy via `iptables -j REDIRECT` incurs noticeable latency and CPU overhead at high request rates because every packet still traverses the TCP/IP and loopback queues.',
        'With `sockops` and `sk_msg`, applications continue using standard POSIX TCP sockets transparently while achieving near-shared-memory throughput whenever the peer is on the same node.'
      ],
      comparisonTable: [
        {
          dimension: 'Same-Node Socket Latency',
          primaryChoice: '~2–4 µs (direct socket buffer splice)',
          alternativeChoice: '~15–30 µs (full TCP/IP + netfilter + loopback stack)',
          winner: 'primary'
        },
        {
          dimension: 'Application Code Changes Required',
          primaryChoice: 'Zero — completely transparent to standard TCP sockets',
          alternativeChoice: 'Zero (or requires rewriting apps to use Unix Domain Sockets)',
          winner: 'primary'
        },
        {
          dimension: 'Cross-Node Traffic Support',
          primaryChoice: 'Local node sockets only (falls back to normal TCP across nodes)',
          alternativeChoice: 'Works identically for local and remote nodes',
          winner: 'tie'
        }
      ],
      whenToUsePrimary: [
        'Accelerating Kubernetes pod-to-pod and pod-to-proxy traffic on the same node.'
      ],
      whenToUseAlternative: [
        'Traffic leaving the physical host over the external network (where XDP and TC accelerate the path).'
      ]
    },
    comprehensionCheck: {
      question: 'What happens if `bpf_msg_redirect_hash(msg, &sock_ops_map, &peer, BPF_F_INGRESS)` does NOT find the peer socket in `sock_ops_map` (because the destination IP is on a remote server)?',
      options: [
        'The connection crashes with a segmentation fault.',
        'The helper does nothing, and returning `SK_PASS` seamlessly hands the message down to the normal Linux TCP/IP stack for remote network transmission.',
        'The packet is dropped permanently.',
        'The kernel blocks the process forever.'
      ],
      correctIndex: 1,
      explanation:
        'If the destination socket is not in `sock_ops_map`, `bpf_msg_redirect_hash` fails gracefully and `SK_PASS` sends the data through the standard TCP/IP stack to the remote machine.'
    },
    relatedTutorialId: 'tut-adv-04-sockops-mesh',
    simulatorPresetId: 'preset-tcp-latency'
  }
];

