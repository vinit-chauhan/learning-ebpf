# KernelPulse: Interactive eBPF Learning Studio & Kernel Event Simulator

KernelPulse is an interactive learning environment and simulated Linux kernel laboratory designed to take engineers from foundational eBPF mental models to writing production-grade cloud-native observability, networking, and security programs using C (kernel-side) and Go with `cilium/ebpf` (userspace).

## User Review & Critical Decisions

> [!IMPORTANT]
> The following architectural and curriculum decisions incorporate your confirmed preferences from our planning discussion:

- **Primary Userspace Loader Stack (`Go + cilium/ebpf`)**: All tutorials, interactive labs, and project templates default to modern **C (`vmlinux.h` / CO-RE BPF helpers)** paired with **Go (`cilium/ebpf` and `bpf2go`)** for userspace compilation, map pinning, ring buffer consumption, and lifecycle attachment. A secondary reference toggle is also included for C (`libbpf`) comparison when inspecting low-level syscalls.
- **Full Simulated eBPF Runtime**: The interactive workspace includes an in-browser **eBPF Static Verifier Engine** (diagnosing unbounded loops, uninitialized registers, null map pointer dereferences, and stack frame limits), an interactive **BPF Maps & RingBuffer Inspector** (Hash, Per-CPU Array, RingBuf, LPM Trie), and a **Live Kernel Event Pipeline** where users can inject synthetic workloads (HTTP requests, SYN floods, `execve` bursts, memory allocations, TCP retransmits) and observe packet/syscall traversal in real time.
- **Comprehensive Real-World Project Templates**: Includes complete, modifiable starter architectures across all three priority domains:
  1. *Cloud-Native Networking*: Cilium-style XDP High-Speed Packet Filter & L4 Load Balancer
  2. *Runtime Security Auditing*: Falco/Tetragon-style Privileged Syscall & File Integrity Monitor (`LSM` + `tracepoint/syscalls/sys_enter_execve`)
  3. *Performance Engineering*: TCP Connection Latency Histogram (`kprobe`/`kretprobe`), Off-CPU Scheduler Profiler (`sched_switch`), and Heap Allocation Leak Tracker (`uprobe`).

---

## 1. Overview & Core Concept

- **What It Does**: Combines a structured, progressive eBPF curriculum (Beginner, Intermediate, Advanced) with a hands-on visual kernel sandbox. Learners can explore how eBPF programs traverse from userspace Go loaders through the `bpf()` syscall, pass static verification and JIT compilation, attach to kernel hook points (XDP, TC, kprobes, tracepoints, uprobes, LSM), and stream structured telemetry back to Go routines via BPF Maps and Ring Buffers.
- **Target Audience / Persona**: Systems engineers, cloud-native/Kubernetes developers, SREs, and security engineers who want an intuitive, visual way to master eBPF without needing to provision custom Linux VMs or risk crashing a local kernel while learning verifier constraints.
- **Key Value**: Bridges the gap between static documentation and real kernel behavior by making invisible kernel constructs—such as register state tracking inside the eBPF Verifier, per-CPU map mutations, and hook execution order—directly visible and interactive.

---

## 2. User Experience & Visual Design

### Key User Flows

1. **Concept & Architecture Explorer (`Concepts & Flows`)**:
   - Users explore the interactive **Linux Kernel vs. User Space Architecture Canvas**.
   - Clicking any subsystem node (**`bpf()` Syscall**, **eBPF Verifier**, **JIT Compiler**, **Hook Points: XDP / TC / Kprobe / Tracepoint / Uprobe / LSM**, **BPF Maps & Ring Buffers**, **Go `cilium/ebpf` Loader**) highlights its data pathways, shows exact memory/execution constraints, and animates a step-by-step packet or syscall walkthrough.
2. **Progressive Tracing Curriculum (`Tutorials: Beginner → Mid-Level → Advanced`)**:
   - Users select a skill tier and step through guided, interactive labs:
     - **Beginner**: *01. Hello World Syscall Tracer (`tracepoint/syscalls/sys_enter_execve`)*, *02. High-Speed Packet Counter with XDP (`XDP_PASS` / `XDP_DROP`)*, *03. Sharing State with BPF Hash Maps & Go (`cilium/ebpf.Map`)*.
     - **Mid-Level**: *04. TCP Handshake Latency Histogram (`kprobe/tcp_v4_connect` & `kretprobe`)*, *05. Streaming High-Volume Telemetry with `BPF_MAP_TYPE_RINGBUF`*, *06. Traffic Control (`tc`) Egress Rate Limiting & QoS Marking*.
     - **Advanced**: *07. CO-RE (Compile Once – Run Everywhere) & `BPF_CORE_READ` Navigation*, *08. Userspace TLS/HTTP Plaintext Interception (`uprobe/SSL_write`)*, *09. Container Escape & File Access Prevention with BPF LSM Hooks*.
   - Each tutorial features step-by-step interactive checkpoints, bidirectional highlighting between C/Go code lines and kernel diagram nodes, and a "Load in Simulator" action.
3. **Interactive eBPF Simulator & Playground (`Kernel Simulator`)**:
   - **Two-Zone Sandbox Layout**:
     - *Left / Top Stage (65% width)*: Live **Animated Kernel Event Pipeline** + **Dual-Pane Code Editor** (Kernel C code `.bpf.c` alongside Userspace Go `main.go` using `cilium/ebpf`) with interactive line annotations and bug-injection toggles to test how the verifier catches unsafe code.
     - *Right / Bottom Control & Telemetry Deck (35% width)*: **Workload Traffic Generator** (trigger HTTP bursts, SSH brute-force attempts, SYN floods, `fork`/`exec` trees, or `malloc` spikes), **eBPF Verifier Output Log** (showing register bounds `R0–R10`, instruction count, and pass/fail diagnostics), and live **BPF Map & RingBuffer Inspector** with tabular hex/struct decoding and latency histograms.
4. **Real-World Project Templates (`Project Templates`)**:
   - Filterable catalog across **Cloud-Native Networking**, **Runtime Security**, and **Performance Engineering**.
   - Each template provides a complete multi-file architecture viewer (`bpf/program.c`, `main.go`, `Makefile`, `Dockerfile`), an architecture data-flow diagram, production deployment checklist, and one-click launch into the live Kernel Simulator with pre-configured traffic scenarios.

### Visual Identity & Theme

- **Aesthetic Direction**: High-precision systems engineering workbench paired with an interactive educational sandbox—clean dark slate geometry, crisp technical diagrams, and high-contrast semantic signal paths without decorative clutter.
- **Color Palette & 60-30-10 Discipline**:
  - **60% Dominant Canvas (`--background`)**: Deep carbon slate (`#0B0F17`) for the main workspace canvas, reducing eye strain during code and trace inspection.
  - **30% Structural Surfaces (`--surface`)**: Elevated slate panels (`#111827`) with subtle 1px hairline borders (`#1E293B`), crisp primary text (`#F8FAFC`), and muted secondary prose (`#94A3B8`).
  - **10% Semantic Focal Accents**:
    - *Kernel Space / eBPF Execution*: Electric Cyan (`#0EA5E9`) paired with explicit `[KERNEL]` or `● VERIFIED` text labels.
    - *User Space / Go `cilium/ebpf`*: Vibrant Amber (`#F59E0B`) paired with `[USERSPACE]` labels.
    - *Pass / `XDP_PASS` / Safe Verification*: Emerald (`#10B981`) with `✓ PASS` label.
    - *Drop / Alert / `XDP_DROP` / Verifier Rejection*: Coral Crimson (`#EF4444`) with `✕ DROP / REJECT` label.
- **Typography & Hierarchy (2+1 Font Rule)**:
  - *Display & Section Headings*: `Outfit` (SemiBold 600, tight tracking, `text-wrap: balance`).
  - *Body & Pedagogical Prose*: `Plus Jakarta Sans` (Regular 400 / Medium 500, 15px–16px, generous 1.65 line-height for readability).
  - *Code, Registers, Hex & Telemetry*: `JetBrains Mono` with strict `font-variant-numeric: tabular-nums` so all packet counters, nanosecond latency histograms, memory addresses, and PIDs align vertically without jitter.
- **Top Bar Contract & Component Discipline**:
  - **Strict 3-Zone Top Bar**: Zone 1: Single-line brand wordmark (`KernelPulse`); Zone 2: 4 concise single-line navigation links (`Concepts & Flows`, `Tutorials`, `Kernel Simulator`, `Project Templates`); Zone 3: 1 primary action button (`Launch Simulator` / `Run Verifier & Attach`).
  - **Zero-Pill Metadata**: Tutorial difficulty tiers, hook types, and kernel version requirements are rendered as clean, unboxed inline text separated by middle dots (`Beginner · Tracepoint · Go cilium/ebpf · 10 min`) rather than pill badges.
  - **Single-Elevation Depth**: Flat slate surfaces separated by 1px borders (`border-slate-800`) and generous padding; no nested card sandwiches or thick left accent borders.

---

## 3. Key Product Decisions & Trade-Offs

- **Decision 1: Deterministic In-Browser eBPF Verifier & Event Engine vs. Static Code Snippets**
  - *Chosen Approach*: Build a deterministic client-side eBPF simulation engine that parses code mutations (including deliberate bug toggles such as removing a `if (data + sizeof(struct ethhdr) > data_end)` packet bounds check or omitting a null-check after `bpf_map_lookup_elem`) and generates authentic Linux verifier register state traces (`R1=ctx()`, `R2=pkt_end()`, `invalid access to packet, off=14 size=20`).
  - *Why*: Beginning and mid-level eBPF developers struggle most with understanding why the kernel verifier rejects their programs. Experiencing real verifier errors and fixing them interactively builds immediate muscle memory.
  - *Alternatives Considered*: Static pre-recorded screenshots of terminal output, which fail to let learners experiment with failure modes or adjust synthetic workloads.

- **Decision 2: Go (`cilium/ebpf`) as the First-Class Userspace Language**
  - *Chosen Approach*: Every kernel C program is paired side-by-side with idiomatic Go code using `github.com/cilium/ebpf`, `ebpf/link`, and `ebpf/ringbuf`, showing how `bpf2go` generates Go structs and how Go channels consume kernel events.
  - *Why*: Directly aligns with your cloud-native focus (Kubernetes, Cilium, Tetragon, Pixie) where Go is the industry standard for control-plane loaders.

- **Decision 3: Local Persistence for Curriculum Progress & Custom Sandbox Snapshots**
  - *Chosen Approach*: Persist completed tutorial checkpoints, quiz/verifier challenge completions, and user-modified playground code in `localStorage` with a one-click reset option.
  - *Why*: Ensures zero-configuration instant startup while preserving the learner's progress across sessions.

---

## 4. Technical Architecture & Data Strategy

### Architecture & Component Diagram

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│                         Top Navigation Bar (3-Zone Contract)                         │
│   [KernelPulse]        [Concepts · Tutorials · Simulator · Templates]   [Run Probe]  │
└──────────────────────────────────────────┬───────────────────────────────────────────┘
                                           │
        ┌──────────────────────────────────┼───────────────────────────────────┐
        ▼                                  ▼                                   ▼
┌───────────────────────┐      ┌────────────────────────┐      ┌───────────────────────┐
│   Concepts & Flows    │      │  Step-by-Step Labs     │      │   Project Templates   │
│  Interactive Explorer │      │ (Beginner/Mid/Advanced)│      │   (Network/Sec/Perf)  │
├───────────────────────┤      ├────────────────────────┤      ├───────────────────────┤
│ • User/Kernel Split   │      │ • Skill Tier Switcher  │      │ • Domain Filter Bar   │
│ • Hook Point Pipeline │─────▶│ • Guided Checkpoints   │─────▶│ • Multi-File Viewer   │
│ • Helper & Map Matrix │      │ • C + Go Code Pairings │      │   (.bpf.c + main.go)  │
│ • Step Flow Animator  │      │ • Verifier Challenges  │      │ • "Open in Simulator" │
└───────────────────────┘      └───────────┬────────────┘      └───────────┬───────────┘
                                           │                               │
                                           └───────────────┬───────────────┘
                                                           ▼
┌──────────────────────────────────────────────────────────────────────────────────────┐
│                   Two-Zone Interactive eBPF Kernel Simulator                         │
├──────────────────────────────────────────┬───────────────────────────────────────────┤
│   Left Stage (65%): Code & Visual Flow   │  Right Deck (35%): Control & Telemetry    │
│ ┌──────────────────────────────────────┐ │ ┌───────────────────────────────────────┐ │
│ │ Live Kernel Event Pipeline Canvas    │ │ │ Synthetic Workload Generator          │ │
│ │ [NIC/Syscall]─▶[Hook]─▶[Map/RingBuf] │ │ │ (HTTP, SYN Flood, Execve, Malloc)     │ │
│ └──────────────────────────────────────┘ │ └───────────────────────────────────────┘ │
│ ┌──────────────────────────────────────┐ │ ┌───────────────────────────────────────┐ │
│ │ Dual Code Editor & Bug Toggle Studio │ │ │ eBPF Static Verifier Diagnostic Log   │ │
│ │ • Kernel C (.bpf.c)  • Go (cilium)   │ │ │ (Register State R0-R10 & Safety Pass) │ │
│ │ • Interactive Line-to-Flow Binding   │ │ └───────────────────────────────────────┘ │
│ │ • Safety Check Toggles (Bounds/Null) │ │ ┌───────────────────────────────────────┐ │
│ └──────────────────────────────────────┘ │ │ Live BPF Maps & RingBuffer Inspector  │ │
│                                          │ │ (Hash Table, Latency Histogram, Logs) │ │
│                                          │ └───────────────────────────────────────┘ │
└──────────────────────────────────────────┴───────────────────────────────────────────┘
```

### Data Model & State

- **Curriculum & Tutorial Store**:
  - Contains structured lessons across three difficulty levels (`beginner`, `intermediate`, `advanced`).
  - Each lesson includes conceptual overview, hook lifecycle diagrams, annotated C kernel code, annotated Go (`cilium/ebpf`) userspace code, line-by-line cross-references, and an interactive Verifier Challenge (where learners toggle or fix a bug to make verification pass).
- **Simulator Runtime State**:
  - `activeProgram`: Currently loaded eBPF program definition, hook attachment point (`XDP`, `TC`, `kprobe`, `kretprobe`, `tracepoint`, `uprobe`, `lsm`), and active safety check flags (`packetBoundsCheck`, `nullMapPointerCheck`, `boundedLoopCheck`, `stackSizeLimitCheck`).
  - `verifierState`: Computed verification log lines, register states (`R0` through `R10`), instruction count, stack bytes used (`max 512 bytes`), and status (`VERIFIED_SAFE` vs. `REJECTED_UNSAFE`).
  - `kernelEventStream`: Real-time ring buffer and perf event queue populated by either the automated workload generator or manual single-step event triggers, tracking packet verdicts (`XDP_PASS`, `XDP_DROP`, `XDP_TX`), syscall arguments, PID/COMM metadata, and execution latency in nanoseconds.
  - `bpfMapEntries`: Live key-value state for simulated `BPF_MAP_TYPE_HASH`, `BPF_MAP_TYPE_PERCPU_ARRAY`, and latency histogram buckets (`log2` microsecond slots).
- **Project Templates Catalog**:
  - 6 comprehensive real-world templates spanning Networking (XDP L4 DDoS Scrubber, Cilium-style Socket Load Balancer), Security (Falco-style `execve` + File Open Auditor, BPF LSM Container Breakout Blocker), and Performance (TCP RTT & Retransmit Tracer, Off-CPU Flame/Histogram & Memory Leak Profiler).

### Interactive Component & State Mapping

- **Concept Flow Animator**: Clicking any stage in the eBPF lifecycle (`Go Loader` → `bpf(BPF_PROG_LOAD)` → `Verifier` → `JIT` → `Kernel Hook` → `BPF Map` → `Go RingBuf Reader`) steps the visual state machine forward or backward and updates the technical inspector panel with exact struct definitions and register conventions.
- **Interactive Verifier Safety Toggles**: In the Simulator and Tutorials, toggling safety switches (e.g., *"Omit `data + nh_off > data_end` check"* or *"Dereference map pointer without `if (!val) return 0;`"* ) dynamically mutates the C code in the editor, re-runs the simulated verifier, highlights the offending C line and bytecode instruction in crimson, and blocks kernel attachment until fixed.
- **Workload Generator & Playback Controls**: Users can toggle continuous event streaming (`Play` / `Pause`), step through a single kernel event frame-by-frame (`Step Event`), adjust packet/syscall rate sliders (`10 ev/s` to `1,000 ev/s`), or inject specific anomaly bursts (`Inject SYN Flood`, `Simulate Unauthorized /etc/shadow Read`, `Trigger TCP Retransmit Spike`) and watch the BPF maps and Go userspace output update immediately.
