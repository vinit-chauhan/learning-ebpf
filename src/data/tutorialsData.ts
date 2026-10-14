import { TutorialLesson } from '../types/ebpf';

export const TUTORIAL_LESSONS: TutorialLesson[] = [
  // ==========================================
  // BEGINNER TIER (5 Tutorials)
  // ==========================================
  {
    id: 'tut-beg-01-execve',
    index: '01',
    title: 'Hello Kernel: Tracing Process Execution with Tracepoints',
    tier: 'beginner',
    hookType: 'tracepoint',
    duration: '12 min',
    minKernel: 'Linux 4.18+',
    summary:
      'Write your first kernel eBPF program attached to syscalls/sys_enter_execve and load it from Go using cilium/ebpf and bpf2go.',
    learningObjectives: [
      'Understand the SEC("tracepoint/syscalls/sys_enter_execve") section macro.',
      'Extract PID and process command name using bpf_get_current_pid_tgid() and bpf_get_current_comm().',
      'Compile and embed the eBPF object into a Go binary using bpf2go and link.Tracepoint().'
    ],
    conceptGuide: {
      whatIsTitle: 'What is a Syscall Tracepoint?',
      whatIsContent:
        'Whenever any Linux process (like bash, docker, or systemd) launches a new executable program, it invokes the execve() system call. The Linux kernel exposes a static hook right at the entry of this system call named tracepoint/syscalls/sys_enter_execve.',
      howItWorksTitle: 'How bpf_get_current_pid_tgid() Works',
      howItWorksContent:
        'Inside the kernel, bpf_get_current_pid_tgid() returns a single 64-bit unsigned integer packing two 32-bit values: the upper 32 bits (>> 32) contain the Thread Group ID (which userspace calls the Process ID / PID), and the lower 32 bits contain the kernel Thread ID (TID).',
      whyUseInsteadTitle: 'Why Use a Tracepoint Instead of Kprobe or ptrace (strace)?',
      whyUseInsteadContent:
        'Using strace (ptrace) pauses the target application twice per syscall, slowing processes down by up to 40x. Using a raw kprobe on __x64_sys_execve is fast, but the symbol name is architecture-specific. The static tracepoint syscalls/sys_enter_execve is both fast (~30ns) and portable across x86_64 and ARM64.',
      comparisonHighlight: {
        chosenApproach: 'tracepoint/syscalls/sys_enter_execve',
        alternativeApproach: 'kprobe/__x64_sys_execve or strace',
        overheadDelta: '~35ns in-kernel vs ~15,000ns ptrace stop',
        stabilityNote: 'Stable tracepoint ABI across kernel upgrades and CPU architectures.'
      }
    },
    cFileName: 'execve_trace.bpf.c',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    __u32 uid = bpf_get_current_uid_gid();
    char comm[16];

    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("execve: pid=%d uid=%d comm=%s\\n", pid, uid, comm);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`,
    goFileName: 'main.go',
    goCode: `package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf execve_trace.bpf.c

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading eBPF objects: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
	if err != nil {
		log.Fatalf("attaching tracepoint: %v", err)
	}
	defer tp.Close()

	log.Println("Attached to sys_enter_execve! Inspect /sys/kernel/debug/tracing/trace_pipe")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}`,
    steps: [
      {
        stepNumber: 1,
        title: 'Declare the Tracepoint Section & Context',
        explanation:
          'The SEC("tracepoint/syscalls/sys_enter_execve") macro places the function into a dedicated ELF section so cilium/ebpf knows its program type (BPF_PROG_TYPE_TRACEPOINT).',
        activePipelineNode: 'userspace',
        cHighlightLines: [5, 6],
        goHighlightLines: [13, 13],
        keyInsight: 'vmlinux.h provides struct trace_event_raw_sys_enter without needing external kernel headers.'
      },
      {
        stepNumber: 2,
        title: 'Load & Verify Objects in Go',
        explanation:
          'In Go, rlimit.RemoveMemlock() lifts legacy memory lock caps, and loadBpfObjects(&objs, nil) invokes the bpf(BPF_PROG_LOAD) syscall to run the in-kernel Static Verifier.',
        activePipelineNode: 'verifier',
        cHighlightLines: [16, 17],
        goHighlightLines: [16, 24],
        keyInsight: 'Because bpf_printk is a GPL-only helper, omitting SEC("license") = "GPL" causes the Verifier to reject the load.'
      },
      {
        stepNumber: 3,
        title: 'Wire the Kernel Tracepoint via bpf_link',
        explanation:
          'link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil) activates the static jump label in the kernel syscall path.',
        activePipelineNode: 'hook',
        cHighlightLines: [7, 14],
        goHighlightLines: [26, 30],
        keyInsight: 'defer tp.Close() guarantees the tracepoint detaches cleanly when the Go process receives SIGINT/SIGTERM.'
      }
    ],
    verifierChallenge: {
      title: 'Fix the GPL Helper License Rejection',
      prompt:
        'When calling BPF helpers like bpf_printk(), the kernel Verifier validates the ELF license section. Inspect why the buggy snippet fails verification.',
      buggySnippet: `SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    bpf_printk("execve triggered\\n");
    return 0;
}
// Missing SEC("license") declaration!`,
      fixedSnippet: `SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    bpf_printk("execve triggered\\n");
    return 0;
}
char LICENSE[] SEC("license") = "Dual BSD/GPL";`,
      verifierErrorOutput: `load program: permission denied:
cannot call GPL-restricted function from non-GPL compatible program
processed 4 insns (limit 1000000)`,
      verifierPassOutput: `Verification succeeded!
0: (18) r1 = 0x7420657663657865
2: (85) call bpf_trace_printk#6
3: (b7) r0 = 0
4: (95) exit
safe — 5 instructions verified (stack depth 16B)`,
      explanation:
        'Many tracing helpers (bpf_printk, bpf_probe_read_kernel, BPF LSM hooks) are marked GPL-only in the kernel helper proto table and require char LICENSE[] SEC("license") = "GPL" or "Dual BSD/GPL".'
    },
    simulatorPresetId: 'preset-syscall-execve'
  },
  {
    id: 'tut-beg-02-xdp-counter',
    index: '02',
    title: 'High-Speed Packet Filtering with XDP (XDP_PASS & XDP_DROP)',
    tier: 'beginner',
    hookType: 'XDP',
    duration: '15 min',
    minKernel: 'Linux 4.18+',
    summary:
      'Parse raw Ethernet and IPv4 headers at the NIC driver ring buffer level and drop unwanted packets before sk_buff allocation.',
    learningObjectives: [
      'Understand struct xdp_md and direct packet pointers (ctx->data and ctx->data_end).',
      'Satisfy the eBPF Verifier packet bounds check: if ((void *)(hdr + 1) > data_end).',
      'Attach an XDP program to a network interface in Go using link.AttachXDP().'
    ],
    conceptGuide: {
      whatIsTitle: 'What is XDP (eXpress Data Path)?',
      whatIsContent:
        'XDP is an eBPF hook that runs inside the network driver RX poll loop as soon as a packet frame arrives from the NIC hardware—before the Linux kernel allocates a socket buffer (sk_buff) or enters the TCP/IP stack.',
      howItWorksTitle: 'How XDP Pointer Arithmetic & Verdicts Work',
      howItWorksContent:
        'ctx->data points to byte 0 of the Ethernet frame, and ctx->data_end points to the end of the packet. By casting data to struct ethhdr * and checking that (void *)(eth + 1) <= data_end, you can inspect the EtherType and IPv4 protocol in ~15 nanoseconds and return XDP_DROP or XDP_PASS.',
      whyUseInsteadTitle: 'Why Use XDP Instead of iptables or Socket Filters?',
      whyUseInsteadContent:
        'iptables runs deep inside the L3 network stack after the kernel has already allocated sk_buff memory for every packet. Under a 10Mpps SYN flood, sk_buff allocation saturates CPU cores. XDP drops malicious packets in place inside the NIC ring buffer at 24M+ packets/sec per core.',
      comparisonHighlight: {
        chosenApproach: 'XDP (NIC Driver Ring Hook)',
        alternativeApproach: 'iptables / Netfilter Chains',
        overheadDelta: '24M pps/core (XDP_DROP) vs <1.5M pps/core (iptables)',
        stabilityNote: 'Requires explicit packet bounds checks at every header layer.'
      }
    },
    cFileName: 'xdp_filter.bpf.c',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

SEC("xdp")
int xdp_icmp_blocker(struct xdp_md *ctx) {
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
        bpf_printk("XDP_DROP: blocked ICMP packet from %pI4\\n", &ip->saddr);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`,
    goFileName: 'main.go',
    goCode: `package main

import (
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf xdp_filter.bpf.c

func main() {
	iface, err := net.InterfaceByName("eth0")
	if err != nil {
		log.Fatalf("lookup network iface eth0: %v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpIcmpBlocker,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %v", err)
	}
	defer l.Close()

	log.Printf("XDP filter attached to %s (index %d)", iface.Name, iface.Index)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
}`,
    steps: [
      {
        stepNumber: 1,
        title: 'Extract Packet Start & End Pointers',
        explanation:
          'ctx->data and ctx->data_end are 32-bit offsets in struct xdp_md that the Verifier rewrites into real 64-bit kernel pointers (PTR_TO_PACKET and PTR_TO_PACKET_END).',
        activePipelineNode: 'hook',
        cHighlightLines: [10, 12],
        goHighlightLines: [15, 18],
        keyInsight: 'Always cast via (void *)(long)ctx->data to avoid compiler pointer-size warnings on 32-bit u32 fields.'
      },
      {
        stepNumber: 2,
        title: 'Prove Ethernet & IPv4 Bounds to the Verifier',
        explanation:
          'Before reading eth->h_proto or ip->protocol, we prove that eth + 1 (14 bytes) and ip + 1 (34 bytes) do not exceed data_end.',
        activePipelineNode: 'verifier',
        cHighlightLines: [13, 22],
        goHighlightLines: [20, 24],
        keyInsight: 'Pointer arithmetic eth + 1 advances the pointer by sizeof(struct ethhdr) (14 bytes).'
      },
      {
        stepNumber: 3,
        title: 'Return XDP_DROP or XDP_PASS & Attach to NIC',
        explanation:
          'Returning XDP_DROP recycles the RX descriptor ring slot immediately. In Go, link.AttachXDP binds the program to eth0.',
        activePipelineNode: 'userspace',
        cHighlightLines: [24, 29],
        goHighlightLines: [26, 33],
        keyInsight: 'When l.Close() runs on shutdown, the NIC transparently reverts to normal kernel packet processing.'
      }
    ],
    verifierChallenge: {
      title: 'Fix the Missing IPv4 Header Bounds Check',
      prompt:
        'The Verifier tracks how many bytes of the packet have been proven safe. Here, eth + 1 was checked (14 bytes), but ip->protocol reads byte offset 23 without checking ip + 1 > data_end.',
      buggySnippet: `struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end)
    return XDP_PASS;

struct iphdr *ip = (void *)(eth + 1);
// BUG: Missing bounds check for struct iphdr before reading ip->protocol!
if (ip->protocol == IPPROTO_ICMP)
    return XDP_DROP;`,
      fixedSnippet: `struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end)
    return XDP_PASS;

struct iphdr *ip = (void *)(eth + 1);
if ((void *)(ip + 1) > data_end)
    return XDP_PASS;

if (ip->protocol == IPPROTO_ICMP)
    return XDP_DROP;`,
      verifierErrorOutput: `invalid access to packet, off=23 size=1, R2(id=0,off=14,r=14)
R2 offset is outside of the packet
processed 11 insns (limit 1000000)`,
      verifierPassOutput: `R2_w=pkt(id=0,off=14,r=34,imm=0) R3=pkt_end()
12: (71) r4 = *(u8 *)(r2 +9) ;reads ip->protocol safely within r=34
safe — 18 instructions verified`,
      explanation:
        'Notice r=14 in the error log: the verifier knew only 14 bytes (Ethernet header) were safe. Adding if ((void *)(ip + 1) > data_end) updates the safe packet range to r=34, making offset 23 legal.'
    },
    simulatorPresetId: 'preset-xdp-firewall'
  },
  {
    id: 'tut-beg-03-bpf-maps',
    index: '03',
    title: 'Sharing State Between Kernel & Go with BPF Hash Maps',
    tier: 'beginner',
    hookType: 'XDP',
    duration: '16 min',
    minKernel: 'Linux 4.18+',
    summary:
      'Maintain a per-source-IP packet counter in a BPF_MAP_TYPE_HASH inside the kernel and iterate over live entries in Go.',
    learningObjectives: [
      'Declare a BTF-style BPF_MAP_TYPE_HASH using __uint and __type macros.',
      'Look up, initialize, and atomically increment map entries in C.',
      'Iterate over live map keys and values in Go using objs.IpStats.Iterate().'
    ],
    conceptGuide: {
      whatIsTitle: 'What is a BPF Hash Map (BPF_MAP_TYPE_HASH)?',
      whatIsContent:
        'A BPF Hash Map is an in-kernel key-value dictionary accessible by both your eBPF C program and your Go userspace process. Keys and values can be arbitrary primitive types or C structs.',
      howItWorksTitle: 'How bpf_map_lookup_elem() & Null Promotion Work',
      howItWorksContent:
        'Calling bpf_map_lookup_elem(&map, &key) hashes the key and returns a direct kernel pointer to the value in RAM, or NULL if the key is not yet in the map. If NULL, you call bpf_map_update_elem(&map, &key, &init_val, BPF_ANY) to insert it; otherwise you increment the value in place.',
      whyUseInsteadTitle: 'Why Aggregate in a BPF Map Instead of Emitting Every Event to Userspace?',
      whyUseInsteadContent:
        'If a server receives 5 million packets per second, sending 5 million individual event notifications to userspace would saturate the memory bus and Go runtime. Aggregating counts inside a BPF Map in kernel space means Go only reads the summary table once per second.',
      comparisonHighlight: {
        chosenApproach: 'In-Kernel Aggregation (BPF_MAP_TYPE_HASH)',
        alternativeApproach: 'Streaming Every Packet Event to Userspace',
        overheadDelta: '99.98% reduction in userspace CPU & memory bandwidth',
        stabilityNote: 'Always check map lookup pointers for NULL before dereferencing.'
      }
    },
    cFileName: 'ip_counter.bpf.c',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // IPv4 Source Address
    __type(value, __u64); // Packet Counter
} ip_pkt_count SEC(".maps");

SEC("xdp")
int count_src_ip(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != __bpf_htons(0x0800))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u64 *count = bpf_map_lookup_elem(&ip_pkt_count, &src_ip);
    if (!count) {
        __u64 init_val = 1;
        bpf_map_update_elem(&ip_pkt_count, &src_ip, &init_val, BPF_ANY);
    } else {
        __sync_fetch_and_add(count, 1);
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`,
    goFileName: 'main.go',
    goCode: `package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf ip_counter.bpf.c

func main() {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		var key uint32
		var count uint64
		iter := objs.IpPktCount.Iterate()
		for iter.Next(&key, &count) {
			ip := make(net.IP, 4)
			binary.LittleEndian.PutUint32(ip, key)
			fmt.Printf("Source IP %-15s : %d packets\\n", ip.String(), count)
		}
	}
}`,
    steps: [
      {
        stepNumber: 1,
        title: 'Define the BTF-Typed Hash Map in .maps',
        explanation:
          'The SEC(".maps") struct uses __uint and __type macros so bpf2go creates objs.IpPktCount with automatic key/value size validation.',
        activePipelineNode: 'map',
        cHighlightLines: [6, 11],
        goHighlightLines: [14, 18],
        keyInsight: 'max_entries caps kernel memory allocation unconditionally so an eBPF map can never exhaust host RAM.'
      },
      {
        stepNumber: 2,
        title: 'Lookup, Null-Check, and Atomic Increment',
        explanation:
          'bpf_map_lookup_elem returns NULL if src_ip is unseen. If present, __sync_fetch_and_add increments the 64-bit counter safely across CPUs.',
        activePipelineNode: 'verifier',
        cHighlightLines: [28, 35],
        goHighlightLines: [20, 22],
        keyInsight: 'Without if (!count), the Verifier halts with R0 invalid mem access "map_value_or_null".'
      },
      {
        stepNumber: 3,
        title: 'Iterate Over Map Entries in Go',
        explanation:
          'objs.IpPktCount.Iterate() walks the kernel hash table using BPF_MAP_GET_NEXT_KEY syscalls and unmarshals each IPv4 key and packet count.',
        activePipelineNode: 'userspace',
        cHighlightLines: [36, 37],
        goHighlightLines: [24, 31],
        keyInsight: 'Go can also write into the same map via objs.IpPktCount.Put() to dynamically configure blocklists.'
      }
    ],
    verifierChallenge: {
      title: 'Fix the Unchecked Map Lookup Pointer Dereference',
      prompt:
        'bpf_map_lookup_elem() returns a nullable pointer (map_value_or_null). Compare the rejected code against the verified version.',
      buggySnippet: `__u32 src_ip = ip->saddr;
__u64 *count = bpf_map_lookup_elem(&ip_pkt_count, &src_ip);
// BUG: Dereferencing count without checking if (!count) first!
__sync_fetch_and_add(count, 1);`,
      fixedSnippet: `__u32 src_ip = ip->saddr;
__u64 *count = bpf_map_lookup_elem(&ip_pkt_count, &src_ip);
if (!count)
    return XDP_PASS;
__sync_fetch_and_add(count, 1);`,
      verifierErrorOutput: `18: (85) call bpf_map_lookup_elem#1
19: (b7) r1 = 1
20: (db) lock *(u64 *)(r0 +0) += r1
R0 invalid mem access 'map_value_or_null'`,
      verifierPassOutput: `18: (85) call bpf_map_lookup_elem#1
19: (15) if r0 == 0x0 goto pc+2
20: (b7) r1 = 1
21: (db) lock *(u64 *)(r0 +0) += r1 ; R0=map_value(id=0,off=0,ks=4,vs=8)
safe — 23 instructions verified`,
      explanation:
        'Instruction 19 (if r0 == 0x0) proves to the Verifier that on line 21, R0 cannot be NULL, promoting its type from map_value_or_null to map_value.'
    },
    simulatorPresetId: 'preset-xdp-firewall'
  },
  {
    id: 'tut-beg-04-percpu-array',
    index: '04',
    title: 'Lock-Free High-Throughput Metrics with Per-CPU Arrays',
    tier: 'beginner',
    hookType: 'XDP',
    duration: '14 min',
    minKernel: 'Linux 4.18+',
    summary:
      'Eliminate multi-core atomic lock contention on 64+ core servers by using BPF_MAP_TYPE_PERCPU_ARRAY and summing per-core slices in Go.',
    learningObjectives: [
      'Understand why atomic instructions cause L1/L2 CPU cache-line bouncing at high event rates.',
      'Use BPF_MAP_TYPE_PERCPU_ARRAY for lock-free per-core packet and byte counters.',
      'Unmarshal per-CPU value slices in Go using []DataRec with cilium/ebpf.'
    ],
    conceptGuide: {
      whatIsTitle: 'What is BPF_MAP_TYPE_PERCPU_ARRAY?',
      whatIsContent:
        'A Per-CPU Array allocates N separate copies of every array element—one dedicated slot for each logical CPU core on the server. When CPU #3 looks up key 0, it receives a pointer to CPU #3’s private memory slot.',
      howItWorksTitle: 'How Per-CPU Slices Eliminate Spinlocks & Atomic Operations',
      howItWorksContent:
        'Because eBPF programs run with kernel preemption disabled on the current CPU core, no other thread or core can concurrently touch the current CPU’s slot. You can update multiple struct fields (packets++, bytes += len) directly without atomic instructions or spinlocks!',
      whyUseInsteadTitle: 'Why Use Per-CPU Arrays Instead of Standard Arrays with Atomic Add?',
      whyUseInsteadContent:
        'When 64 CPU cores execute __sync_fetch_and_add on the same memory address 20 million times per second, the CPU interconnect spends most of its time invalidating L1 cache lines across sockets. Per-CPU maps keep every write inside the local CPU’s L1 cache.',
      comparisonHighlight: {
        chosenApproach: 'BPF_MAP_TYPE_PERCPU_ARRAY',
        alternativeApproach: 'BPF_MAP_TYPE_ARRAY + __sync_fetch_and_add',
        overheadDelta: '4.5x higher multi-core throughput on 64-core nodes',
        stabilityNote: 'Go Lookup() receives a slice []Value of length runtime.NumCPU().'
      }
    },
    cFileName: 'percpu_stats.bpf.c',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct datarec {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4); // Indexed by XDP verdict (0..3)
    __type(key, __u32);
    __type(value, struct datarec);
} xdp_stats SEC(".maps");

SEC("xdp")
int xdp_account_traffic(struct xdp_md *ctx) {
    __u32 key = XDP_PASS;
    struct datarec *rec = bpf_map_lookup_elem(&xdp_stats, &key);
    if (!rec)
        return XDP_ABORTED;

    // 100% Lock-Free! Updates current CPU core's private struct slice
    rec->packets += 1;
    rec->bytes   += (ctx->data_end - ctx->data);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`,
    goFileName: 'main.go',
    goCode: `package main

import (
	"fmt"
	"log"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type datarec bpf percpu_stats.bpf.c

func main() {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	key := uint32(2) // XDP_PASS
	var perCPU []bpfDatarec

	// cilium/ebpf automatically populates one bpfDatarec per CPU core
	if err := objs.XdpStats.Lookup(&key, &perCPU); err != nil {
		log.Fatalf("per-cpu lookup: %v", err)
	}

	var totalPkts, totalBytes uint64
	for cpu, rec := range perCPU {
		totalPkts += rec.Packets
		totalBytes += rec.Bytes
		fmt.Printf("CPU %02d -> %d pkts (%d bytes)\\n", cpu, rec.Packets, rec.Bytes)
	}
	fmt.Printf("TOTAL  -> %d pkts (%d bytes)\\n", totalPkts, totalBytes)
}`,
    steps: [
      {
        stepNumber: 1,
        title: 'Declare BPF_MAP_TYPE_PERCPU_ARRAY with Struct Value',
        explanation:
          'Each key (0..3) in xdp_stats is automatically replicated across all logical CPUs by the kernel at map creation time.',
        activePipelineNode: 'map',
        cHighlightLines: [5, 15],
        goHighlightLines: [8, 8],
        keyInsight: 'Passing -type datarec to bpf2go generates the Go struct bpfDatarec automatically.'
      },
      {
        stepNumber: 2,
        title: 'Perform Lockless Multi-Field Updates in Kernel',
        explanation:
          'Because rec points exclusively to the executing CPU core’s slice, both rec->packets and rec->bytes can be incremented without spinlocks.',
        activePipelineNode: 'hook',
        cHighlightLines: [19, 27],
        goHighlightLines: [17, 23],
        keyInsight: 'Even for BPF_MAP_TYPE_ARRAY (where keys 0..N-1 always exist), the Verifier still requires if (!rec) before dereferencing.'
      },
      {
        stepNumber: 3,
        title: 'Aggregate the Per-CPU Slice in Go',
        explanation:
          'Passing a Go slice (&perCPU) to objs.XdpStats.Lookup() retrieves all CPU slots in a single syscall so Go can sum them.',
        activePipelineNode: 'userspace',
        cHighlightLines: [28, 29],
        goHighlightLines: [25, 31],
        keyInsight: 'Per-CPU arrays are also used as 1-element scratch buffers when an eBPF program needs a temporary struct larger than the 512-byte stack.'
      }
    ],
    verifierChallenge: {
      title: 'Why Even Pre-Allocated Arrays Require a NULL Check',
      prompt:
        'Even though BPF_MAP_TYPE_PERCPU_ARRAY pre-allocates indices 0..3, bpf_map_lookup_elem() can still return NULL if key >= 4.',
      buggySnippet: `__u32 key = XDP_PASS;
struct datarec *rec = bpf_map_lookup_elem(&xdp_stats, &key);
rec->packets += 1; // Verifier rejects: rec might be NULL!`,
      fixedSnippet: `__u32 key = XDP_PASS;
struct datarec *rec = bpf_map_lookup_elem(&xdp_stats, &key);
if (!rec)
    return XDP_ABORTED;
rec->packets += 1;`,
      verifierErrorOutput: `6: (85) call bpf_map_lookup_elem#1
7: (79) r1 = *(u64 *)(r0 +0)
R0 invalid mem access 'map_value_or_null'`,
      verifierPassOutput: `6: (85) call bpf_map_lookup_elem#1
7: (15) if r0 == 0x0 goto pc+5
8: (79) r1 = *(u64 *)(r0 +0) ; R0=map_value(id=0,off=0,ks=4,vs=16)
safe — 14 instructions verified`,
      explanation:
        'bpf_map_lookup_elem always returns PTR_TO_MAP_VALUE_OR_NULL in register R0 regardless of map type, so an explicit if (!rec) branch is always mandatory.'
    },
    simulatorPresetId: 'preset-xdp-firewall'
  },
  {
    id: 'tut-beg-05-uid-pid-filtering',
    index: '05',
    title: 'Context-Aware Filtering with Kernel Constants & Global Variables',
    tier: 'beginner',
    hookType: 'tracepoint',
    duration: '15 min',
    minKernel: 'Linux 5.2+',
    summary:
      'Parameterize your eBPF probes from Go using volatile const global variables (RewriteConstants) to filter events in-kernel by UID or target PID.',
    learningObjectives: [
      'Declare volatile const global variables in C (.rodata section) for JIT-time constant folding.',
      'Use spec.RewriteConstants() in Go cilium/ebpf before loading the program into the kernel.',
      'Filter out noisy processes inside the kernel before emitting telemetry.'
    ],
    conceptGuide: {
      whatIsTitle: 'What are eBPF Read-Only Global Variables (.rodata)?',
      whatIsContent:
        'Modern eBPF (Linux 5.2+) supports global variables in C. By declaring volatile const __u32 target_uid = 0;, Clang places the variable in the ELF .rodata section. Your Go loader can overwrite target_uid with a user-supplied CLI flag right before calling loadBpfObjects!',
      howItWorksTitle: 'How JIT Constant Folding Optimizes .rodata Variables',
      howItWorksContent:
        'Once your Go program calls spec.RewriteConstants() and loads the program into the kernel, the kernel freezes the .rodata map as read-only. The eBPF Verifier and JIT compiler treat target_uid as a compile-time immediate constant—eliminating map lookup overhead and even pruning dead branches!',
      whyUseInsteadTitle: 'Why Use .rodata RewriteConstants Instead of a Config BPF Hash Map?',
      whyUseInsteadContent:
        'Looking up a configuration parameter in a BPF Hash Map on every syscall costs ~15–25ns and a helper call. A .rodata constant is baked directly into the JIT machine instruction immediate operand (0ns lookup overhead).',
      comparisonHighlight: {
        chosenApproach: 'volatile const + spec.RewriteConstants()',
        alternativeApproach: 'Config Lookup in BPF_MAP_TYPE_ARRAY',
        overheadDelta: '0ns (JIT immediate instruction) vs ~20ns helper call',
        stabilityNote: 'Use volatile const in C so Clang does not optimize the variable away before Go rewrites it.'
      }
    },
    cFileName: 'uid_filter.bpf.c',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// Rewritten from Go via spec.RewriteConstants before verification!
volatile const __u32 target_uid = 0;
volatile const bool filter_enabled = false;

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_filtered_exec(struct trace_event_raw_sys_enter *ctx) {
    __u32 uid = bpf_get_current_uid_gid();

    if (filter_enabled && uid != target_uid) {
        return 0; // Filtered out in-kernel in ~3 nanoseconds!
    }

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("Audited UID %d executed command (PID %d)\\n", uid, pid);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`,
    goFileName: 'main.go',
    goCode: `package main

import (
	"log"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf uid_filter.bpf.c

func main() {
	spec, err := loadBpf()
	if err != nil {
		log.Fatal(err)
	}

	// Inject configuration constants directly into .rodata before loading!
	err = spec.RewriteConstants(map[string]interface{}{
		"target_uid":     uint32(1000),
		"filter_enabled": true,
	})
	if err != nil {
		log.Fatalf("rewriting constants: %v", err)
	}

	var objs bpfObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()
	log.Println("Loaded eBPF probe specialized for UID 1000!")
}`,
    steps: [
      {
        stepNumber: 1,
        title: 'Declare volatile const Globals in C',
        explanation:
          'Marking target_uid as volatile const places it in .rodata and prevents Clang from constant-folding the default 0 at C compile time.',
        activePipelineNode: 'userspace',
        cHighlightLines: [5, 7],
        goHighlightLines: [10, 13],
        keyInsight: 'If you forget the volatile keyword in C, Clang optimizes away target_uid and RewriteConstants fails!'
      },
      {
        stepNumber: 2,
        title: 'Rewrite Constants in Go CollectionSpec',
        explanation:
          'Instead of calling loadBpfObjects directly, call loadBpf() to get the CollectionSpec, invoke spec.RewriteConstants(), and then call spec.LoadAndAssign(&objs, nil).',
        activePipelineNode: 'syscall',
        cHighlightLines: [10, 15],
        goHighlightLines: [15, 27],
        keyInsight: 'The Verifier knows the exact rewritten value of filter_enabled and dead-code-eliminates untaken branches.'
      }
    ],
    verifierChallenge: {
      title: 'Why volatile is Required on C Global Constants',
      prompt:
        'See what happens if you declare const __u32 target_uid = 0; without the volatile keyword.',
      buggySnippet: `// BUG: Without volatile, Clang inlines 0 at compile time!
const __u32 target_uid = 0;`,
      fixedSnippet: `// CORRECT: volatile forces Clang to emit a .rodata relocation symbol
volatile const __u32 target_uid = 0;`,
      verifierErrorOutput: `rewriting constants: variable "target_uid": not found in .rodata section (optimized out by Clang -O2)`,
      verifierPassOutput: `.rodata symbol "target_uid" relocated to 1000 (0x3e8)
Frozen .rodata map verified safe — 9 instructions`,
      explanation:
        'Clang compiles eBPF with -O2 optimization. Without volatile, Clang sees const target_uid = 0 and replaces all uses of target_uid with literal 0, stripping the symbol from .rodata.'
    },
    simulatorPresetId: 'preset-syscall-execve'
  },

  // ==========================================
  // INTERMEDIATE TIER (5 Tutorials)
  // ==========================================
  {
    id: 'tut-mid-01-tcp-latency',
    index: '06',
    title: 'Measuring TCP Handshake Latency with Kprobes & Kretprobes',
    tier: 'intermediate',
    hookType: 'kprobe',
    duration: '20 min',
    minKernel: 'Linux 4.19+',
    summary:
      'Correlate function entry and exit timestamps across kprobe/tcp_v4_connect and kretprobe/tcp_v4_connect to measure connection setup latency.',
    learningObjectives: [
      'Use BPF_KPROBE and BPF_KRETPROBE macros for clean parameter access.',
      'Record bpf_ktime_get_ns() in a BPF Hash Map keyed by Thread ID (TID) on entry.',
      'Compute elapsed nanoseconds on exit and clean up map entries with bpf_map_delete_elem().'
    ],
    conceptGuide: {
      whatIsTitle: 'What is the Entry/Exit Map Correlation Pattern?',
      whatIsContent:
        'A kprobe fires when a kernel function begins, and a kretprobe fires when that function returns. Because they are two separate eBPF program invocations, they share state by storing the entry timestamp (bpf_ktime_get_ns()) in a BPF Hash Map keyed by the current Thread ID (tid).',
      howItWorksTitle: 'How TID Keying Works Across Function Calls',
      howItWorksContent:
        'When thread TID 8421 enters tcp_v4_connect(struct sock *sk), the kprobe saves start_ts[8421] = bpf_ktime_get_ns(). When tcp_v4_connect finishes on TID 8421, the kretprobe looks up start_ts[8421], calculates delta_ns = now - start_ts, and deletes key 8421.',
      whyUseInsteadTitle: 'Why Key by TID (Lower 32 bits) Instead of PID (Upper 32 bits)?',
      whyUseInsteadContent:
        'In multi-threaded programs (like Go, Java, or Envoy), dozens of threads share the same Process ID (PID / TGID) and can call tcp_v4_connect simultaneously on different CPUs! Keying by PID would overwrite concurrent calls; keying by Thread ID (TID) isolates each thread.',
      comparisonHighlight: {
        chosenApproach: 'TID-Keyed Hash Map + kprobe/kretprobe',
        alternativeApproach: 'External pcap SYN / SYN-ACK correlation',
        overheadDelta: 'Direct socket struct & PID context with zero packet capture',
        stabilityNote: 'Always call bpf_map_delete_elem() in the kretprobe so the map never fills up.'
      }
    },
    cFileName: 'tcp_latency.bpf.c',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // Thread ID (TID)
    __type(value, __u64); // Entry timestamp (ns)
} start_ns SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kp_tcp_connect, struct sock *sk) {
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 ts  = bpf_ktime_get_ns();

    bpf_map_update_elem(&start_ns, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(kret_tcp_connect, int ret) {
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 *tsp = bpf_map_lookup_elem(&start_ns, &tid);
    if (!tsp)
        return 0;

    __u64 delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
    bpf_map_delete_elem(&start_ns, &tid);

    if (ret == 0) {
        bpf_printk("tcp_v4_connect latency: %llu us (tid=%d)\\n", delta_us, tid);
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`,
    goFileName: 'main.go',
    goCode: `package main

import (
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf tcp_latency.bpf.c

func main() {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	kp, err := link.Kprobe("tcp_v4_connect", objs.KpTcpConnect, nil)
	if err != nil {
		log.Fatalf("attaching kprobe: %v", err)
	}
	defer kp.Close()

	kretp, err := link.Kretprobe("tcp_v4_connect", objs.KretTcpConnect, nil)
	if err != nil {
		log.Fatalf("attaching kretprobe: %v", err)
	}
	defer kretp.Close()

	log.Println("Tracing tcp_v4_connect latency...")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
}`,
    steps: [
      {
        stepNumber: 1,
        title: 'Record Monotonic Nanosecond Timestamp on Entry',
        explanation:
          'Inside kp_tcp_connect, we grab the lower 32 bits of bpf_get_current_pid_tgid() (the unique kernel TID) and store bpf_ktime_get_ns() in start_ns.',
        activePipelineNode: 'hook',
        cHighlightLines: [14, 21],
        goHighlightLines: [20, 24],
        keyInsight: 'bpf_ktime_get_ns() uses the fast monotonic clock (CLOCK_MONOTONIC) immune to NTP wall-clock jumps.'
      },
      {
        stepNumber: 2,
        title: 'Calculate Duration & Delete Key on Return',
        explanation:
          'When tcp_v4_connect returns, kret_tcp_connect looks up the saved timestamp by TID, computes the elapsed microseconds, and deletes the map entry.',
        activePipelineNode: 'map',
        cHighlightLines: [23, 36],
        goHighlightLines: [26, 30],
        keyInsight: 'Forgetting bpf_map_delete_elem(&start_ns, &tid) leaks map entries until max_entries (10240) is exhausted!'
      }
    ],
    verifierChallenge: {
      title: 'Fix the Stack Pointer Address Requirement on Map Lookup',
      prompt:
        'bpf_map_lookup_elem(&map, &key) requires a pointer to an initialized stack variable for the second argument, never a raw scalar integer.',
      buggySnippet: `__u32 tid = (__u32)bpf_get_current_pid_tgid();
// BUG: Passing scalar tid by value instead of stack pointer &tid!
__u64 *tsp = bpf_map_lookup_elem(&start_ns, (void *)(long)tid);`,
      fixedSnippet: `__u32 tid = (__u32)bpf_get_current_pid_tgid();
__u64 *tsp = bpf_map_lookup_elem(&start_ns, &tid);`,
      verifierErrorOutput: `R2 type=scalar expected=fp, pkt, map_key, map_value
processed 5 insns (limit 1000000)`,
      verifierPassOutput: `4: (63) *(u32 *)(r10 -4) = r0 ; stores tid at fp-4
5: (bf) r2 = r10
6: (07) r2 += -4 ; R2=fp-4
7: (85) call bpf_map_lookup_elem#1
safe — 19 instructions verified`,
      explanation:
        'BPF map helpers read key bytes from memory via a pointer (such as fp-4 on the R10 stack). Passing a scalar register as R2 triggers "R2 type=scalar expected=fp".'
    },
    simulatorPresetId: 'preset-tcp-latency'
  },
  {
    id: 'tut-mid-02-ringbuf-events',
    index: '07',
    title: 'Zero-Copy Event Streaming with BPF Ring Buffers',
    tier: 'intermediate',
    hookType: 'tracepoint',
    duration: '18 min',
    minKernel: 'Linux 5.8+',
    summary:
      'Stream structured C telemetry records directly into a Go goroutine using BPF_MAP_TYPE_RINGBUF and github.com/cilium/ebpf/ringbuf.',
    learningObjectives: [
      'Reserve event space directly in the ring buffer via bpf_ringbuf_reserve().',
      'Guarantee every code path calls bpf_ringbuf_submit() or bpf_ringbuf_discard().',
      'Decode binary little-endian records in Go using bpf2go -type struct generation.'
    ],
    conceptGuide: {
      whatIsTitle: 'What is Zero-Copy RingBuffer Streaming?',
      whatIsContent:
        'Instead of building an event struct on the tiny 512-byte eBPF stack and copying it into a per-CPU perf buffer, bpf_ringbuf_reserve() allocates space directly inside the shared ring buffer memory page.',
      howItWorksTitle: 'How the Verifier Enforces Reference Release on RingBuffer Pointers',
      howItWorksContent:
        'When bpf_ringbuf_reserve() returns a non-null pointer, the Verifier attaches a reference ID (ref_obj_id=1) to that pointer. Your program is forbidden from returning until it releases that reference via either bpf_ringbuf_submit(e, 0) or bpf_ringbuf_discard(e, 0).',
      whyUseInsteadTitle: 'Why Use RingBuf Reserve/Submit Instead of bpf_ringbuf_output()?',
      whyUseInsteadContent:
        'bpf_ringbuf_output() requires you to first allocate the struct on the 512-byte eBPF stack and then copy it. bpf_ringbuf_reserve() writes directly into the ring buffer with zero copy and supports structs much larger than 512 bytes!',
      comparisonHighlight: {
        chosenApproach: 'bpf_ringbuf_reserve() + bpf_ringbuf_submit()',
        alternativeApproach: 'bpf_perf_event_output()',
        overheadDelta: 'Zero extra copy; bypasses 512-byte stack ceiling',
        stabilityNote: 'Size of BPF_MAP_TYPE_RINGBUF max_entries must be a power-of-2 multiple of page size (4096).'
      }
    },
    cFileName: 'ringbuf_stream.bpf.c',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct process_event {
    __u32 pid;
    __u32 uid;
    __u64 timestamp_ns;
    char comm[16];
};
const struct process_event *unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB ring buffer
} events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct process_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid();
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`,
    goFileName: 'main.go',
    goCode: `package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type process_event bpf ringbuf_stream.bpf.c

func main() {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleExec, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	var evt bpfProcessEvent
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &evt); err == nil {
			fmt.Printf("[%d] PID=%d UID=%d COMM=%s\\n", evt.TimestampNs, evt.Pid, evt.Uid, string(evt.Comm[:]))
		}
	}
}`,
    steps: [
      {
        stepNumber: 1,
        title: 'Export C Struct Type to BTF for bpf2go',
        explanation:
          'Declaring const struct process_event *unused ensures Clang preserves the struct definition in the ELF BTF section so bpf2go -type process_event can generate bpfProcessEvent.',
        activePipelineNode: 'userspace',
        cHighlightLines: [5, 11],
        goHighlightLines: [14, 14],
        keyInsight: 'Never manually duplicate C structs in Go; let bpf2go generate them from BTF to guarantee exact padding.'
      },
      {
        stepNumber: 2,
        title: 'Reserve & Submit in BPF_MAP_TYPE_RINGBUF',
        explanation:
          'bpf_ringbuf_reserve allocates sizeof(*e) bytes in the shared circular buffer, and bpf_ringbuf_submit commits the record and wakes the Go reader.',
        activePipelineNode: 'ringbuf',
        cHighlightLines: [22, 31],
        goHighlightLines: [29, 33],
        keyInsight: 'If you abort after reserving e, you must call bpf_ringbuf_discard(e, 0) before returning.'
      },
      {
        stepNumber: 3,
        title: 'Consume Ordered Events in Go',
        explanation:
          'rd.Read() blocks efficiently on epoll until new events are committed, returning raw bytes that unmarshal directly into bpfProcessEvent.',
        activePipelineNode: 'userspace',
        cHighlightLines: [31, 33],
        goHighlightLines: [35, 47],
        keyInsight: 'Calling rd.Close() from a signal handler unblocks rd.Read() with ringbuf.ErrClosed for clean shutdown.'
      }
    ],
    verifierChallenge: {
      title: 'Fix the Leaked RingBuffer Reference on Early Return',
      prompt:
        'If your program reserves a ring buffer slot and then decides not to emit the event (e.g., UID == 0), returning without discarding leaks the lock!',
      buggySnippet: `struct process_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
if (!e)
    return 0;
if (bpf_get_current_uid_gid() == 0)
    return 0; // BUG: Early return without bpf_ringbuf_discard(e, 0)!
bpf_ringbuf_submit(e, 0);`,
      fixedSnippet: `struct process_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
if (!e)
    return 0;
if (bpf_get_current_uid_gid() == 0) {
    bpf_ringbuf_discard(e, 0);
    return 0;
}
bpf_ringbuf_submit(e, 0);`,
      verifierErrorOutput: `14: (b7) r0 = 0
15: (95) exit
Unreleased reference id=1 alloc_insn=6`,
      verifierPassOutput: `13: (85) call bpf_ringbuf_discard#133
14: (b7) r0 = 0
15: (95) exit
safe — all references released on all paths`,
      explanation:
        'An uncommitted reservation in a ring buffer blocks the consumer pointer until submitted or discarded. The Verifier tracks alloc_insn references to guarantee every exit path releases the reservation.'
    },
    simulatorPresetId: 'preset-syscall-execve'
  },
  {
    id: 'tut-mid-03-tc-egress-qos',
    index: '08',
    title: 'Traffic Control (TC) Classifier: Egress Packet Marking & Filtering',
    tier: 'intermediate',
    hookType: 'TC',
    duration: '18 min',
    minKernel: 'Linux 5.10+ (TCX in 6.6+)',
    summary:
      'Inspect and classify outbound (Egress) container traffic using eBPF Traffic Control (struct __sk_buff) and TC_ACT_OK / TC_ACT_SHOT verdicts.',
    learningObjectives: [
      'Understand the difference between struct xdp_md (Ingress raw frame) and struct __sk_buff (Ingress & Egress socket buffer).',
      'Use TC verdicts: TC_ACT_OK (0) to allow and TC_ACT_SHOT (2) to drop packets.',
      'Attach a TC program using cilium/ebpf link.AttachTCX (Linux 6.6+) or netlink qdisc.'
    ],
    conceptGuide: {
      whatIsTitle: 'What is the eBPF Traffic Control (TC) Hook?',
      whatIsContent:
        'Unlike XDP (which only runs on incoming NIC packets), TC runs right after struct sk_buff creation on both Ingress and Egress paths. It is the workhorse behind Kubernetes Pod networking in Cilium.',
      howItWorksTitle: 'How __sk_buff Metadata and TCX Work',
      howItWorksContent:
        'Inside a TC eBPF program, struct __sk_buff *skb gives you both direct packet pointers (skb->data and skb->data_end) AND rich kernel metadata: skb->len, skb->mark, skb->priority, skb->ifindex, and socket UID/cgroup.',
      whyUseInsteadTitle: 'Why Use TC Instead of XDP for Container Egress & Policy?',
      whyUseInsteadContent:
        'When a container sends an outbound connection (Egress), XDP never runs because XDP is strictly an RX driver hook. TC intercepts both Egress and Ingress on virtual ethernet (veth) devices and knows which cgroup/socket originated the packet.',
      comparisonHighlight: {
        chosenApproach: 'eBPF TC (tcx / clsact)',
        alternativeApproach: 'XDP (Ingress Only)',
        overheadDelta: 'Full Egress + Ingress visibility with sk_buff metadata',
        stabilityNote: 'Linux 6.6+ introduced link.AttachTCX for clean fd-based attachment just like XDP.'
      }
    },
    cFileName: 'tc_egress.bpf.c',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK   0
#define TC_ACT_SHOT 2
#define ETH_P_IP    0x0800

SEC("tc")
int tc_egress_guard(struct __sk_buff *skb) {
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != __bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // Mark high-priority telemetry packets with DSCP/fwmark
    skb->mark = 0x42;

    // Block unauthorized outbound Telnet (TCP port 23)
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        if (tcp->dest == __bpf_htons(23))
            return TC_ACT_SHOT; // Drop packet cleanly in TC layer
    }
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`,
    goFileName: 'main.go',
    goCode: `package main

import (
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf tc_egress.bpf.c

func main() {
	iface, err := net.InterfaceByName("eth0")
	if err != nil {
		log.Fatal(err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	// Attach to TC Egress path using modern TCX link (Linux 6.6+)
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.TcEgressGuard,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Fatalf("attaching TCX egress: %v", err)
	}
	defer l.Close()
	log.Println("TC Egress guard active on eth0!")
}`,
    steps: [
      {
        stepNumber: 1,
        title: 'Parse Packet Headers via struct __sk_buff',
        explanation:
          'Just like XDP, TC provides direct packet access via skb->data and skb->data_end, requiring bounds checks before dereferencing L2/L3/L4 headers.',
        activePipelineNode: 'hook',
        cHighlightLines: [11, 24],
        goHighlightLines: [14, 22],
        keyInsight: 'Always return TC_ACT_OK (0) rather than XDP_PASS (2)—note that in TC, 2 is TC_ACT_SHOT (DROP)!'
      },
      {
        stepNumber: 2,
        title: 'Mutate skb->mark & Enforce Egress Port Policy',
        explanation:
          'We stamp skb->mark = 0x42 for downstream routing policies and return TC_ACT_SHOT if outbound TCP destination port is 23 (Telnet).',
        activePipelineNode: 'verifier',
        cHighlightLines: [26, 37],
        goHighlightLines: [25, 34],
        keyInsight: 'Returning XDP_PASS (value 2) by mistake inside a TC program will drop every packet because TC_ACT_SHOT == 2!'
      }
    ],
    verifierChallenge: {
      title: 'Fix the Missing TCP Header Bounds Check',
      prompt:
        'After verifying struct iphdr, reading tcp->dest requires proving that (void *)(tcp + 1) <= data_end.',
      buggySnippet: `struct tcphdr *tcp = (void *)(ip + 1);
// BUG: Reading tcp->dest without verifying tcp + 1 <= data_end
if (tcp->dest == __bpf_htons(23))
    return TC_ACT_SHOT;`,
      fixedSnippet: `struct tcphdr *tcp = (void *)(ip + 1);
if ((void *)(tcp + 1) > data_end)
    return TC_ACT_OK;
if (tcp->dest == __bpf_htons(23))
    return TC_ACT_SHOT;`,
      verifierErrorOutput: `invalid access to packet, off=36 size=2, R3(id=0,off=34,r=34)
R3 offset is outside of the packet`,
      verifierPassOutput: `R3_w=pkt(id=0,off=34,r=54,imm=0)
24: (69) r1 = *(u16 *)(r3 +2) ; safely reads tcp->dest within r=54
safe — 28 instructions verified`,
      explanation:
        'Each protocol header layer (Ethernet 14B -> IPv4 20B -> TCP 20B) requires its own bounds check against data_end before any field in that header is read.'
    },
    simulatorPresetId: 'preset-xdp-firewall'
  },
  {
    id: 'tut-mid-04-openat-file-audit',
    index: '09',
    title: 'Auditing Sensitive File Opens & Reading Userspace Strings Safely',
    tier: 'intermediate',
    hookType: 'tracepoint',
    duration: '16 min',
    minKernel: 'Linux 5.8+',
    summary:
      'Trace openat() syscalls and safely copy null-terminated file paths from userspace virtual memory using bpf_probe_read_user_str().',
    learningObjectives: [
      'Understand why eBPF cannot directly dereference userspace pointers (char *filename).',
      'Use bpf_probe_read_user_str() to copy userspace strings safely into a Ring Buffer event.',
      'Detect processes attempting to read sensitive files like /etc/shadow or .env.'
    ],
    conceptGuide: {
      whatIsTitle: 'Why Can’t eBPF Dereference Userspace Pointers Directly?',
      whatIsContent:
        'When an application calls openat(dfd, "/etc/shadow", flags), the string "/etc/shadow" lives in userspace virtual memory. User memory might be unmapped, paged out to swap, or protected by CPU Supervisor Mode Access Prevention (SMAP).',
      howItWorksTitle: 'How bpf_probe_read_user_str() Handles Page Faults Safely',
      howItWorksContent:
        'bpf_probe_read_user_str(dst, size, unsafe_user_ptr) disables page-fault panics, copies up to size bytes until a null terminator is reached, guarantees null termination, and returns a negative error code cleanly if the page is unmapped.',
      whyUseInsteadTitle: 'Why Use bpf_probe_read_user_str() Instead of bpf_probe_read_kernel_str()?',
      whyUseInsteadContent:
        'On ARM64 and modern x86_64 CPUs with strict address-space separation, calling bpf_probe_read_kernel_str() on a userspace address always fails with -EFAULT.',
      comparisonHighlight: {
        chosenApproach: 'bpf_probe_read_user_str()',
        alternativeApproach: 'Raw pointer dereference or bpf_probe_read_kernel()',
        overheadDelta: 'Fault-safe copy with automatic NUL termination',
        stabilityNote: 'Always check the return value of bpf_probe_read_user_str() if you need string length.'
      }
    },
    cFileName: 'file_open_audit.bpf.c',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct open_event {
    __u32 pid;
    __u32 uid;
    char comm[16];
    char filename[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} file_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    struct open_event *e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // args[1] of openat(int dfd, const char *filename, int flags) is a userspace pointer
    const char *user_filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), user_filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`,
    goFileName: 'main.go',
    goCode: `package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type open_event bpf file_open_audit.bpf.c

func main() {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceOpenat, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.FileEvents)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	var evt bpfOpenEvent
	for {
		rec, err := rd.Read()
		if err != nil {
			break
		}
		_ = binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &evt)
		fmt.Printf("PID %d (%s) opened: %s\\n",
			evt.Pid,
			unix.ByteSliceToString(evt.Comm[:]),
			unix.ByteSliceToString(evt.Filename[:]),
		)
	}
}`,
    steps: [
      {
        stepNumber: 1,
        title: 'Extract Userspace Pointer from Tracepoint Args',
        explanation:
          'In sys_enter_openat, ctx->args[0] is dirfd and ctx->args[1] is const char __user *filename.',
        activePipelineNode: 'hook',
        cHighlightLines: [27, 29],
        goHighlightLines: [23, 27],
        keyInsight: 'Never dereference user_filename[0] directly; the Verifier views ctx->args[1] as an untrusted scalar.'
      },
      {
        stepNumber: 2,
        title: 'Copy String Safely into RingBuffer Slot',
        explanation:
          'bpf_probe_read_user_str copies the userspace path directly into e->filename inside the ring buffer.',
        activePipelineNode: 'ringbuf',
        cHighlightLines: [19, 32],
        goHighlightLines: [36, 47],
        keyInsight: 'unix.ByteSliceToString trims the C null-terminated byte array cleanly in Go.'
      }
    ],
    verifierChallenge: {
      title: 'Fix the Direct Userspace Pointer Dereference',
      prompt:
        'Attempting to read user_filename[0] directly in C without bpf_probe_read_user_str() causes an immediate Verifier error.',
      buggySnippet: `const char *user_filename = (const char *)ctx->args[1];
// BUG: Direct dereference of untrusted userspace pointer!
if (user_filename[0] == '/') {
    e->filename[0] = '/';
}`,
      fixedSnippet: `const char *user_filename = (const char *)ctx->args[1];
bpf_probe_read_user_str(&e->filename, sizeof(e->filename), user_filename);`,
      verifierErrorOutput: `R1=scalar() expected=fp, pkt, map_value
R1 invalid mem access 'scalar'`,
      verifierPassOutput: `18: (85) call bpf_probe_read_user_str#114
safe — 24 instructions verified`,
      explanation:
        'ctx->args[1] is typed as a raw SCALAR_VALUE by the verifier. Only bpf_probe_read_user() and bpf_probe_read_user_str() are allowed to copy from arbitrary userspace memory addresses.'
    },
    simulatorPresetId: 'preset-syscall-execve'
  },
  {
    id: 'tut-mid-05-latency-histograms',
    index: '10',
    title: 'Building Log2 Latency Histograms for Kernel & I/O Profiling',
    tier: 'intermediate',
    hookType: 'tracepoint',
    duration: '17 min',
    minKernel: 'Linux 4.19+',
    summary:
      'Summarize millions of latency measurements into a compact 64-bucket power-of-2 histogram inside the kernel using Per-CPU arrays.',
    learningObjectives: [
      'Compute log2 bucket indices inside eBPF using bounded bit-shifting.',
      'Store latency distribution buckets in a BPF_MAP_TYPE_PERCPU_ARRAY.',
      'Render p50, p95, and p99 latency histograms in Go with near-zero kernel overhead.'
    ],
    conceptGuide: {
      whatIsTitle: 'What is an In-Kernel Log2 Histogram?',
      whatIsContent:
        'Instead of streaming millions of individual latency timestamps to userspace, an in-kernel Log2 Histogram maps any latency duration (from 1 microsecond to 10 seconds) into one of 32 power-of-2 buckets (e.g., [1–2µs], [2–4µs], [4–8µs], ..., [1–2s]) right inside the kernel.',
      howItWorksTitle: 'How Bounded Bit-Shift Log2 Calculation Works in eBPF',
      howItWorksContent:
        'By repeatedly shifting the microsecond delta right (delta >>= 1) in a bounded loop (capped at 32 iterations so the Verifier proves termination), we compute the exact log2 bucket index and increment that bucket in a Per-CPU array.',
      whyUseInsteadTitle: 'Why Compute Histograms in Kernel Space Instead of Userspace?',
      whyUseInsteadContent:
        'Streaming 500,000 disk I/O or database query events per second to userspace just to calculate percentiles wastes gigabytes of ring buffer traffic. A 32-bucket Per-CPU histogram uses just 256 bytes per core regardless of event volume!',
      comparisonHighlight: {
        chosenApproach: 'In-Kernel Log2 Per-CPU Histogram (32 buckets)',
        alternativeApproach: 'Raw Timestamp Streaming to Userspace',
        overheadDelta: 'Fixed 256 bytes/core memory vs unbounded event stream',
        stabilityNote: 'Always bound bit-shift loops with a constant ceiling (i < 32) for the Verifier.'
      }
    },
    cFileName: 'io_histogram.bpf.c',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define MAX_SLOTS 32

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} latency_hist SEC(".maps");

static __always_inline __u32 log2_bucket(__u64 val_us) {
    __u32 slot = 0;
    #pragma unroll
    for (int i = 0; i < 31; i++) {
        if (val_us <= 1)
            break;
        val_us >>= 1;
        slot++;
    }
    return slot;
}

SEC("tracepoint/syscalls/sys_exit_read")
int record_read_latency(struct trace_event_raw_sys_exit *ctx) {
    // Example: bucket a measured microsecond duration into log2 slot
    __u64 simulated_delta_us = 42;
    __u32 slot = log2_bucket(simulated_delta_us);
    if (slot >= MAX_SLOTS)
        slot = MAX_SLOTS - 1;

    __u64 *count = bpf_map_lookup_elem(&latency_hist, &slot);
    if (count)
        *count += 1;
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`,
    goFileName: 'main.go',
    goCode: `package main

import (
	"fmt"
	"log"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf io_histogram.bpf.c

func main() {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	for slot := uint32(0); slot < 16; slot++ {
		var perCPU []uint64
		if err := objs.LatencyHist.Lookup(&slot, &perCPU); err != nil {
			continue
		}
		var sum uint64
		for _, v := range perCPU {
			sum += v
		}
		low := uint64(1) << slot
		high := (uint64(1) << (slot + 1)) - 1
		fmt.Printf("[%4d - %4d us] : %d\\n", low, high, sum)
	}
}`,
    steps: [
      {
        stepNumber: 1,
        title: 'Compute Log2 Bucket with a Verifier-Safe Bounded Loop',
        explanation:
          'Because i < 31 has a compile-time constant bound, the Verifier proves that log2_bucket() always terminates in at most 31 steps.',
        activePipelineNode: 'verifier',
        cHighlightLines: [14, 24],
        goHighlightLines: [11, 15],
        keyInsight: 'Unbounded while (val_us > 1) loops without a fixed counter ceiling risk hitting the 1M instruction limit.'
      },
      {
        stepNumber: 2,
        title: 'Increment the Per-CPU Histogram Bucket',
        explanation:
          'Clamping slot < MAX_SLOTS and incrementing *count updates the latency distribution in ~12 nanoseconds.',
        activePipelineNode: 'map',
        cHighlightLines: [29, 36],
        goHighlightLines: [17, 29],
        keyInsight: 'This exact log2 histogram algorithm powers BCC/bpftrace power-of-2 histograms in production.'
      }
    ],
    verifierChallenge: {
      title: 'Fix the Unbounded Loop Verifier Rejection',
      prompt:
        'See why an unbounded while (val > 1) loop with an unknown runtime scalar fails verification on older kernels or complex functions.',
      buggySnippet: `// BUG: Unbounded while loop with no fixed iteration cap!
while (val_us != 0) {
    slot++;
    // Forgot to shift val_us >>= 1 -> Infinite Loop!
}`,
      fixedSnippet: `for (int i = 0; i < 31; i++) {
    if (val_us <= 1)
        break;
    val_us >>= 1;
    slot++;
}`,
      verifierErrorOutput: `back-edge from insn 14 to 11
infinite loop detected at insn 14 (or 1000000 insns limit exceeded)`,
      verifierPassOutput: `Bounded loop verified (max 31 iterations)
safe — 48 instructions verified`,
      explanation:
        'The eBPF Verifier must prove that every loop terminates within the instruction limit. Using a fixed counter bound (for (int i = 0; i < 31; i++)) or bpf_loop() guarantees termination.'
    },
    simulatorPresetId: 'preset-tcp-latency'
  },

  // ==========================================
  // ADVANCED TIER (5 Tutorials)
  // ==========================================
  {
    id: 'tut-adv-01-core-btf',
    index: '11',
    title: 'CO-RE & BTF: Navigating Deep Kernel Structs with BPF_CORE_READ',
    tier: 'advanced',
    hookType: 'kprobe',
    duration: '22 min',
    minKernel: 'Linux 5.4+ (BTF enabled)',
    summary:
      'Traverse multi-level kernel pointers (task->nsproxy->uts_ns->name.nodename) portably across any Linux distro to identify container hostnames.',
    learningObjectives: [
      'Chain multi-pointer dereferences in a single call with BPF_CORE_READ(task, a, b, c).',
      'Inspect container namespace IDs and cgroup metadata for Kubernetes enrichment.',
      'Understand how cilium/ebpf patches BTF field relocations at load time.'
    ],
    conceptGuide: {
      whatIsTitle: 'What Does BPF_CORE_READ() Do Under the Hood?',
      whatIsContent:
        'In standard kernel C, you might write task->nsproxy->uts_ns->name.nodename. In eBPF, you cannot directly dereference arbitrary kernel pointers chained together without calling bpf_probe_read_kernel() at every step—AND the byte offsets of nsproxy and uts_ns change across kernel versions! BPF_CORE_READ(task, nsproxy, uts_ns, name.nodename) expands into chained bpf_probe_read_kernel() calls with automatic BTF CO-RE offset relocations.',
      howItWorksTitle: 'How Container Hostnames & PID Namespaces Live in task_struct',
      howItWorksContent:
        'Every container on a Kubernetes node has its own UTS namespace (storing the Pod/Container hostname) and PID namespace (where the container’s root process sees itself as PID 1, even though its host PID is e.g. 29412). Navigating task->nsproxy lets your eBPF probe log both the Host PID and the Container’s internal PID/Hostname!',
      whyUseInsteadTitle: 'Why Read Container Metadata from task_struct in Kernel Instead of Querying Docker API Later?',
      whyUseInsteadContent:
        'Short-lived processes (like a 5ms shell command in a container escape attempt) often exit before a userspace Go daemon can query /proc/<pid>/cgroup or the container runtime API! Reading task_struct inside the kernel captures the container identity synchronously while the process is still alive.',
      comparisonHighlight: {
        chosenApproach: 'In-Kernel BPF_CORE_READ(task, nsproxy, ...)',
        alternativeApproach: 'Asynchronous Userspace /proc/<pid> Lookup',
        overheadDelta: '100% accuracy on short-lived (<5ms) processes',
        stabilityNote: 'Relocated automatically against /sys/kernel/btf/vmlinux by cilium/ebpf.'
      }
    },
    cFileName: 'core_container_id.bpf.c',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct container_exec_evt {
    __u32 host_pid;
    __u32 parent_pid;
    __u64 cgroup_id;
    char nodename[64];
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int trace_container_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct container_exec_evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    e->host_pid   = BPF_CORE_READ(task, tgid);
    e->parent_pid = BPF_CORE_READ(task, real_parent, tgid);
    e->cgroup_id  = bpf_get_current_cgroup_id();

    // Traverse task -> nsproxy -> uts_ns -> name.nodename (Container/Pod Hostname!)
    BPF_CORE_READ_STR_INTO(&e->nodename, task, nsproxy, uts_ns, name.nodename);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`,
    goFileName: 'main.go',
    goCode: `package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type container_exec_evt bpf core_container_id.bpf.c

func main() {
	var objs bpfObjects
	// loadBpfObjects automatically performs BTF CO-RE field relocations!
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("CO-RE load failed: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("sched", "sched_process_exec", objs.TraceContainerExec, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	var evt bpfContainerExecEvt
	for {
		rec, err := rd.Read()
		if err != nil {
			break
		}
		_ = binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &evt)
		fmt.Printf("[Pod/Node: %s] Cgroup=%d PPID=%d -> PID=%d (%s)\\n",
			unix.ByteSliceToString(evt.Nodename[:]),
			evt.CgroupId, evt.ParentPid, evt.HostPid,
			unix.ByteSliceToString(evt.Comm[:]),
		)
	}
}`,
    steps: [
      {
        stepNumber: 1,
        title: 'Acquire Current task_struct Pointer',
        explanation:
          'bpf_get_current_task() returns a pointer to the running process’s struct task_struct in kernel memory.',
        activePipelineNode: 'hook',
        cHighlightLines: [25, 29],
        goHighlightLines: [18, 22],
        keyInsight: 'Combined with bpf_get_current_cgroup_id(), you can map any kernel event directly to a Kubernetes Pod UID.'
      },
      {
        stepNumber: 2,
        title: 'Multi-Hop Pointer Traversal with BPF_CORE_READ_STR_INTO',
        explanation:
          'BPF_CORE_READ_STR_INTO safely chases task -> nsproxy -> uts_ns -> name.nodename and copies the container hostname into the ring buffer.',
        activePipelineNode: 'ringbuf',
        cHighlightLines: [31, 36],
        goHighlightLines: [36, 49],
        keyInsight: 'Each arrow hop in BPF_CORE_READ emits a relocation record that cilium/ebpf patches against /sys/kernel/btf/vmlinux.'
      }
    ],
    verifierChallenge: {
      title: 'Fix Raw C Arrow Dereference on Untrusted task_struct Pointer',
      prompt:
        'Using raw C pointer dereferencing (task->real_parent->tgid) on a non-BTF pointer without BPF_CORE_READ fails verification or breaks across kernel versions.',
      buggySnippet: `struct task_struct *task = (struct task_struct *)bpf_get_current_task();
// BUG: Raw C pointer dereference without bpf_probe_read_kernel / BPF_CORE_READ!
e->parent_pid = task->real_parent->tgid;`,
      fixedSnippet: `struct task_struct *task = (struct task_struct *)bpf_get_current_task();
e->parent_pid = BPF_CORE_READ(task, real_parent, tgid);`,
      verifierErrorOutput: `R1=scalar() invalid mem access 'scalar' (must use bpf_probe_read_kernel or BPF_CORE_READ)`,
      verifierPassOutput: `CO-RE relocation: struct task_struct::real_parent patched to offset 1248
CO-RE relocation: struct task_struct::tgid patched to offset 1236
safe — 31 instructions verified`,
      explanation:
        'bpf_get_current_task() returns an integer scalar address. BPF_CORE_READ wraps bpf_probe_read_kernel() for each pointer hop and records BTF field relocations.'
    },
    simulatorPresetId: 'preset-syscall-execve'
  },
  {
    id: 'tut-adv-02-uprobe-tls',
    index: '12',
    title: 'Intercepting Encrypted OpenSSL/TLS Plaintext with Uprobes',
    tier: 'advanced',
    hookType: 'uprobe',
    duration: '24 min',
    minKernel: 'Linux 4.19+',
    summary:
      'Attach eBPF Uprobes to SSL_write and SSL_read in libssl.so to inspect HTTP/1.1, HTTP/2, and API traffic in plaintext without proxy certs.',
    learningObjectives: [
      'Open shared library ELF binaries in Go via link.OpenExecutable("/usr/lib/.../libssl.so.3").',
      'Attach Uprobe to SSL_write(SSL *ssl, const void *buf, int num) and read the userspace plaintext buffer.',
      'Bitmask buffer lengths (len & (MAX_BUF - 1)) to satisfy the eBPF Verifier.'
    ],
    conceptGuide: {
      whatIsTitle: 'How Does Uprobe TLS Interception Work?',
      whatIsContent:
        'When curl, Python, Node.js, or NGINX sends an HTTPS request, it passes the unencrypted HTTP string to OpenSSL’s SSL_write(ssl, buf, num) function in userspace. By attaching a Uprobe to SSL_write, your eBPF program reads buf right before OpenSSL encrypts it!',
      howItWorksTitle: 'How the Verifier Checks Dynamic Length Reads in bpf_probe_read_user()',
      howItWorksContent:
        'The third argument to bpf_probe_read_user(dst, len, src) is the byte count to copy into dst. The Verifier MUST prove that 0 <= len <= sizeof(dst). Applying a bitwise mask (len &= 0xFF) proves to the Verifier that len can never exceed 255 bytes.',
      whyUseInsteadTitle: 'Why Use eBPF Uprobes Instead of a MITM TLS Proxy?',
      whyUseInsteadContent:
        'A MITM proxy requires installing custom root CA certificates into every container, breaks certificate pinning and mTLS, and adds a network hop. Uprobes require zero certificate changes and work passively from outside the process.',
      comparisonHighlight: {
        chosenApproach: 'eBPF Uprobe on libssl.so (SSL_write / SSL_read)',
        alternativeApproach: 'MITM TLS Proxy or tcpdump with SSLKEYLOGFILE',
        overheadDelta: 'Zero certificate changes; works on live production pods',
        stabilityNote: 'Bitmask dynamic read lengths so the Verifier knows the destination buffer cannot overflow.'
      }
    },
    cFileName: 'uprobe_tls.bpf.c',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_PAYLOAD 256

struct tls_event {
    __u32 pid;
    __u32 bytes_len;
    char comm[16];
    char payload[MAX_PAYLOAD];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} tls_rb SEC(".maps");

SEC("uprobe/SSL_write")
int BPF_KPROBE(uprobe_ssl_write, void *ssl, const char *buf, int num) {
    if (num <= 0)
        return 0;

    struct tls_event *e = bpf_ringbuf_reserve(&tls_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->bytes_len = (__u32)num;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Clamp & bitmask length so Verifier proves read_len <= MAX_PAYLOAD (256)
    __u32 read_len = (__u32)num;
    if (read_len > MAX_PAYLOAD)
        read_len = MAX_PAYLOAD;
    bpf_probe_read_user(&e->payload, read_len & (MAX_PAYLOAD - 1), buf);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`,
    goFileName: 'main.go',
    goCode: `package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type tls_event bpf uprobe_tls.bpf.c

func main() {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	ex, err := link.OpenExecutable("/usr/lib/x86_64-linux-gnu/libssl.so.3")
	if err != nil {
		log.Fatalf("opening libssl.so.3: %v", err)
	}

	up, err := ex.Uprobe("SSL_write", objs.UprobeSslWrite, nil)
	if err != nil {
		log.Fatalf("attaching uprobe: %v", err)
	}
	defer up.Close()

	rd, err := ringbuf.NewReader(objs.TlsRb)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	var evt bpfTlsEvent
	for {
		rec, err := rd.Read()
		if err != nil {
			break
		}
		_ = binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &evt)
		fmt.Printf("[TLS Plaintext] PID=%d (%s): %s\\n", evt.Pid, evt.Comm, string(evt.Payload[:]))
	}
}`,
    steps: [
      {
        stepNumber: 1,
        title: 'Intercept SSL_write Userspace Arguments',
        explanation:
          'BPF_KPROBE(uprobe_ssl_write, void *ssl, const char *buf, int num) extracts the three arguments passed to SSL_write from the CPU registers.',
        activePipelineNode: 'hook',
        cHighlightLines: [20, 24],
        goHighlightLines: [22, 31],
        keyInsight: 'buf points to the unencrypted cleartext HTTP/gRPC payload in the calling process memory.'
      },
      {
        stepNumber: 2,
        title: 'Bitmask Read Size & Copy from Userspace',
        explanation:
          'read_len & (MAX_PAYLOAD - 1) proves to the Verifier that the size argument to bpf_probe_read_user cannot overflow e->payload[256].',
        activePipelineNode: 'verifier',
        cHighlightLines: [33, 39],
        goHighlightLines: [39, 48],
        keyInsight: 'Bitmasking with (power_of_2 - 1) is the canonical eBPF idiom for bounding variable-length memory reads.'
      }
    ],
    verifierChallenge: {
      title: 'Fix the Unbounded Variable-Length Buffer Overflow Rejection',
      prompt:
        'Passing an untrusted userspace int num directly as the size parameter to bpf_probe_read_user(&e->payload, num, buf) fails verification because num could exceed 256 bytes!',
      buggySnippet: `// BUG: num comes from userspace and could be 16384, overflowing e->payload[256]!
bpf_probe_read_user(&e->payload, num, buf);`,
      fixedSnippet: `__u32 read_len = (__u32)num & (MAX_PAYLOAD - 1);
bpf_probe_read_user(&e->payload, read_len, buf);`,
      verifierErrorOutput: `R2 min value is negative, either use unsigned or 'var &= const'
or R2 max value (4294967295) is outside of allocated memory range [0, 256]`,
      verifierPassOutput: `19: (54) w2 &= 255 ; R2_w=scalar(umin=0,umax=255)
20: (85) call bpf_probe_read_user#112
safe — destination buffer size (256) >= max read size (255)`,
      explanation:
        'The Verifier error message literally hints at the fix: "either use unsigned or var &= const". Masking with 255 forces umin=0 and umax=255.'
    },
    simulatorPresetId: 'preset-uprobe-ssl'
  },
  {
    id: 'tut-adv-03-lsm-security',
    index: '13',
    title: 'Blocking Container Breakouts Inline with BPF LSM',
    tier: 'advanced',
    hookType: 'lsm',
    duration: '20 min',
    minKernel: 'Linux 5.7+ (lsm=bpf)',
    summary:
      'Attach to Linux Security Module hooks (lsm/file_open & lsm/bprm_check_security) to block unauthorized file access or binary execution inline with -EPERM.',
    learningObjectives: [
      'Write a BTF-enabled BPF_PROG(lsm_hook, ...) security enforcement program.',
      'Understand why BPF LSM eliminates TOCTOU (Time-of-Check to Time-of-Use) pointer races.',
      'Attach LSM hooks in Go using link.AttachLSM(link.LSMOptions{Program: ...}).'
    ],
    conceptGuide: {
      whatIsTitle: 'What Makes BPF LSM Different from Tracepoints?',
      whatIsContent:
        'Tracepoints are read-only observers—they cannot change the return value of a system call. BPF LSM hooks run directly inside the kernel’s mandatory access control gatekeepers and return an integer verdict: 0 to allow, or -EPERM (-1) to block the action immediately.',
      howItWorksTitle: 'How lsm/file_open Inspects Immutable Kernel Structs',
      howItWorksContent:
        'When lsm/file_open fires, the kernel passes struct file *file directly. Using BPF_CORE_READ(file, f_inode, i_ino), you inspect the resolved kernel inode rather than an unverified userspace string pointer.',
      whyUseInsteadTitle: 'Why Use BPF LSM Return -EPERM Instead of bpf_send_signal(SIGKILL)?',
      whyUseInsteadContent:
        'Killing a process with SIGKILL from a tracepoint is asynchronous (the first few packets or bytes might already escape before the signal is delivered) and crashes the whole service. BPF LSM returns -EPERM synchronously on that single operation.',
      comparisonHighlight: {
        chosenApproach: 'BPF LSM Inline Enforcement (return -EPERM)',
        alternativeApproach: 'Tracepoint + bpf_send_signal(SIGKILL)',
        overheadDelta: 'Synchronous zero-window prevention; TOCTOU-immune',
        stabilityNote: 'Always check if (ret != 0) return ret; first so you never override an earlier LSM denial.'
      }
    },
    cFileName: 'lsm_enforcer.bpf.c',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);   // Protected Inode Number
    __type(value, __u32); // Allowed UID
} protected_inodes SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(enforce_file_guard, struct file *file, int ret) {
    // Respect denial from any previous LSM hook in the chain
    if (ret != 0)
        return ret;

    __u64 ino = BPF_CORE_READ(file, f_inode, i_ino);
    __u32 *allowed_uid = bpf_map_lookup_elem(&protected_inodes, &ino);
    if (!allowed_uid)
        return 0; // Not a protected inode; allow

    __u32 current_uid = bpf_get_current_uid_gid();
    if (current_uid != *allowed_uid) {
        bpf_printk("BPF LSM DENIED UID %d opening protected inode %llu\\n", current_uid, ino);
        return -EPERM;
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";`,
    goFileName: 'main.go',
    goCode: `package main

import (
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf lsm_enforcer.bpf.c

func main() {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	// Protect /etc/shadow inode (e.g. 131074) so only root (UID 0) can open it
	shadowInode := uint64(131074)
	rootUID := uint32(0)
	if err := objs.ProtectedInodes.Put(&shadowInode, &rootUID); err != nil {
		log.Fatal(err)
	}

	lsmLink, err := link.AttachLSM(link.LSMOptions{
		Program: objs.EnforceFileGuard,
	})
	if err != nil {
		log.Fatalf("attaching BPF LSM: %v", err)
	}
	defer lsmLink.Close()

	log.Println("BPF LSM mandatory access control active!")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
}`,
    steps: [
      {
        stepNumber: 1,
        title: 'Declare SEC("lsm/file_open") with BPF_PROG',
        explanation:
          'BPF_PROG unpacks typed BTF parameters for the security_file_open kernel hook, including the chained ret parameter.',
        activePipelineNode: 'hook',
        cHighlightLines: [16, 20],
        goHighlightLines: [27, 33],
        keyInsight: 'Always check if (ret != 0) return ret; so your program cannot accidentally turn an earlier denial into an allow.'
      },
      {
        stepNumber: 2,
        title: 'Match Resolved Inode Against Policy Map & Return -EPERM',
        explanation:
          'We read file->f_inode->i_ino, check protected_inodes, and return -EPERM (-1) if current_uid does not match.',
        activePipelineNode: 'map',
        cHighlightLines: [22, 33],
        goHighlightLines: [20, 25],
        keyInsight: 'Because checking by inode number operates after VFS resolution, attackers cannot bypass the rule using hardlinks or symlinks!'
      }
    ],
    verifierChallenge: {
      title: 'Understand BTF Pointer Direct Access in LSM / Fentry',
      prompt:
        'In BTF-enabled hooks (LSM, fentry, fexit), the Verifier knows the exact BTF type of struct file *file, allowing direct pointer reads or BPF_CORE_READ.',
      buggySnippet: `SEC("lsm/file_open")
int BPF_PROG(enforce_file_guard, struct file *file, int ret) {
    // BUG: Returning +EPERM (+1) instead of negative -EPERM (-1)!
    return EPERM;
}`,
      fixedSnippet: `SEC("lsm/file_open")
int BPF_PROG(enforce_file_guard, struct file *file, int ret) {
    if (ret != 0)
        return ret;
    return -EPERM;
}`,
      verifierErrorOutput: `Verifier check: LSM return value must be <= 0 (0 = allow, negative errno = deny)`,
      verifierPassOutput: `R0_w=scalar(smin=-1,smax=0)
safe — valid LSM errno return range verified`,
      explanation:
        'Linux kernel LSM hooks follow negative errno conventions (0 for allow, -EPERM / -EACCES for deny).'
    },
    simulatorPresetId: 'preset-lsm-security'
  },
  {
    id: 'tut-adv-04-sockops-mesh',
    index: '14',
    title: 'Service Mesh TCP Bypass with Sockops & SK_MSG Redirection',
    tier: 'advanced',
    hookType: 'TC',
    duration: '25 min',
    minKernel: 'Linux 4.19+',
    summary:
      'Accelerate local pod-to-pod and sidecar proxy communication by splicing TCP sockets directly via BPF_MAP_TYPE_SOCKHASH.',
    learningObjectives: [
      'Track established TCP connections in a cgroup using SEC("sockops").',
      'Register active sockets inside a BPF_MAP_TYPE_SOCKHASH map.',
      'Redirect sendmsg() payloads directly into peer socket receive queues with SEC("sk_msg").'
    ],
    conceptGuide: {
      whatIsTitle: 'What is eBPF Socket Layer Redirection?',
      whatIsContent:
        'When two local sockets (e.g., an application container and its local proxy or another pod on the same node) exchange data over TCP, sockops + sk_msg short-circuits the entire TCP/IP and veth network stack by copying data directly between socket queues.',
      howItWorksTitle: 'How sockops & sk_msg Cooperate via BPF_MAP_TYPE_SOCKHASH',
      howItWorksContent:
        'The sockops program hooks TCP connection establishment and stores each socket in a SOCKHASH map keyed by its IPv4 4-tuple. Whenever sendmsg() is called on a registered socket, the sk_msg program looks up the destination 4-tuple in SOCKHASH and calls bpf_msg_redirect_hash(..., BPF_F_INGRESS).',
      whyUseInsteadTitle: 'Why Use SK_MSG Instead of iptables REDIRECT in Service Meshes?',
      whyUseInsteadContent:
        'iptables REDIRECT forces every proxy hop through TCP segmentation, IP routing, and loopback queues. SK_MSG splices socket buffers at the top of the VFS/socket layer, cutting local latency in half.',
      comparisonHighlight: {
        chosenApproach: 'BPF_PROG_TYPE_SOCK_OPS + SK_MSG + SOCKHASH',
        alternativeApproach: 'iptables -t nat -j REDIRECT',
        overheadDelta: '~55% lower latency on local pod/proxy hops',
        stabilityNote: 'Automatically falls back to normal TCP stack via SK_PASS if peer is on a remote node.'
      }
    },
    cFileName: 'sockops_bypass.bpf.c',
    cCode: `//go:build ignore
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

SEC("sockops")
int bpf_sockmap_track(struct bpf_sock_ops *skops) {
    if (skops->family != 2) // AF_INET
        return 0;

    if (skops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB ||
        skops->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        struct sock_key key = {
            .sip4  = skops->local_ip4,
            .dip4  = skops->remote_ip4,
            .sport = skops->local_port,
            .dport = __bpf_ntohl(skops->remote_port),
        };
        bpf_sock_hash_update(skops, &sock_ops_map, &key, BPF_ANY);
    }
    return 0;
}

SEC("sk_msg")
int bpf_tcp_redir(struct sk_msg_md *msg) {
    struct sock_key peer = {
        .sip4  = msg->remote_ip4,
        .dip4  = msg->local_ip4,
        .sport = __bpf_ntohl(msg->remote_port),
        .dport = msg->local_port,
    };
    bpf_msg_redirect_hash(msg, &sock_ops_map, &peer, BPF_F_INGRESS);
    return SK_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`,
    goFileName: 'main.go',
    goCode: `package main

import (
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf sockops_bypass.bpf.c

func main() {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	// 1. Attach sockops tracker to root cgroup v2
	cg, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupSockOps,
		Program: objs.BpfSockmapTrack,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer cg.Close()

	// 2. Attach sk_msg redirector directly to the SOCKHASH map
	err = link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  objs.SockOpsMap.FD(),
		Program: objs.BpfTcpRedir,
		Attach:  ebpf.AttachSkMsgVerdict,
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Socket-level TCP bypass active!")
}`,
    steps: [
      {
        stepNumber: 1,
        title: 'Register Established TCP Sockets in SOCKHASH',
        explanation:
          'When a TCP handshake finishes (ACTIVE or PASSIVE ESTABLISHED_CB), bpf_sock_hash_update inserts the socket reference into sock_ops_map.',
        activePipelineNode: 'map',
        cHighlightLines: [20, 36],
        goHighlightLines: [19, 28],
        keyInsight: 'Note that skops->remote_port is in network byte order (big-endian) while local_port is host byte order!'
      },
      {
        stepNumber: 2,
        title: 'Splice Payload Directly to Peer Socket Queue',
        explanation:
          'bpf_tcp_redir reverses the 4-tuple to find the peer socket and calls bpf_msg_redirect_hash with BPF_F_INGRESS.',
        activePipelineNode: 'hook',
        cHighlightLines: [38, 48],
        goHighlightLines: [30, 39],
        keyInsight: 'If the destination IP is on another machine, peer is not in sock_ops_map and SK_PASS sends it over normal TCP.'
      }
    ],
    verifierChallenge: {
      title: 'Fix the Helper Program-Type Permission Error',
      prompt:
        'Each BPF program type only allows specific helpers. Calling bpf_sock_hash_update() inside an sk_msg program is rejected by the Verifier.',
      buggySnippet: `SEC("sk_msg")
int bpf_tcp_redir(struct sk_msg_md *msg) {
    // BUG: bpf_sock_hash_update is only valid in sockops, not sk_msg!
    bpf_sock_hash_update((void *)msg, &sock_ops_map, &peer, BPF_ANY);
    return SK_PASS;
}`,
      fixedSnippet: `SEC("sk_msg")
int bpf_tcp_redir(struct sk_msg_md *msg) {
    bpf_msg_redirect_hash(msg, &sock_ops_map, &peer, BPF_F_INGRESS);
    return SK_PASS;
}`,
      verifierErrorOutput: `program of this type cannot use helper bpf_sock_hash_update#53`,
      verifierPassOutput: `12: (85) call bpf_msg_redirect_hash#60
13: (b7) r0 = 1 ; SK_PASS
safe — helper allowed for BPF_PROG_TYPE_SK_MSG`,
      explanation:
        'The Verifier checks every helper call against the allowed helper table for your SEC() program type.'
    },
    simulatorPresetId: 'preset-tcp-latency'
  },
  {
    id: 'tut-adv-05-tail-calls',
    index: '15',
    title: 'Chaining Programs with BPF Tail Calls & Per-CPU Context Passing',
    tier: 'advanced',
    hookType: 'XDP',
    duration: '20 min',
    minKernel: 'Linux 5.4+',
    summary:
      'Break complex packet processing pipelines into modular stages chained with BPF_MAP_TYPE_PROG_ARRAY and bpf_tail_call().',
    learningObjectives: [
      'Register multiple XDP programs inside a BPF_MAP_TYPE_PROG_ARRAY jump table from Go.',
      'Pass parsed L3/L4 packet state between tail-called stages using a 1-entry Per-CPU Array.',
      'Atomically hot-swap pipeline stages from Go without detaching the root XDP hook.'
    ],
    conceptGuide: {
      whatIsTitle: 'Why Do Production eBPF Engines Use Tail Calls?',
      whatIsContent:
        'A production firewall + load balancer + telemetry agent can easily exceed tens of thousands of instructions. By splitting the pipeline into Stage 0 (L2/L3 Parser), Stage 1 (TCP DDoS Filter), and Stage 2 (UDP Load Balancer), each stage is verified independently and gets a fresh 512-byte stack.',
      howItWorksTitle: 'How State Is Passed Across a Tail Call',
      howItWorksContent:
        'Because bpf_tail_call() discards the current stack frame when jumping to the next program, Stage 0 writes parsed offsets (like l4_offset and src_ip) into a 1-element BPF_MAP_TYPE_PERCPU_ARRAY before calling bpf_tail_call(), and Stage 1 reads that same Per-CPU slot immediately.',
      whyUseInsteadTitle: 'Why Use a Per-CPU Scratch Map Instead of a Standard Hash Map Across Tail Calls?',
      whyUseInsteadContent:
        'A tail call is guaranteed to execute synchronously on the exact same CPU core with preemption disabled! Therefore, key 0 of a Per-CPU Array is 100% isolated to the current packet being processed.',
      comparisonHighlight: {
        chosenApproach: 'BPF_MAP_TYPE_PROG_ARRAY + Per-CPU Scratch Context',
        alternativeApproach: 'Monolithic Single-Function XDP Program',
        overheadDelta: 'Up to 33 chained stages × 1M instructions; zero-downtime stage upgrades',
        stabilityNote: 'All programs in a PROG_ARRAY must have the exact same program type (e.g., all XDP).'
      }
    },
    cFileName: 'tail_call_pipeline.bpf.c',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct pkt_scratch {
    __u32 src_ip;
    __u16 l4_offset;
    __u8  protocol;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pkt_scratch);
} scratch_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32);
} jmp_table SEC(".maps");

SEC("xdp")
int xdp_stage0_ingress(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != __bpf_htons(0x0800))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 zero = 0;
    struct pkt_scratch *sc = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!sc)
        return XDP_ABORTED;

    sc->src_ip    = ip->saddr;
    sc->protocol  = ip->protocol;
    sc->l4_offset = sizeof(struct ethhdr) + sizeof(struct iphdr);

    // Tail-call jump to Stage 1 (index 1 in jmp_table)
    bpf_tail_call(ctx, &jmp_table, 1);
    return XDP_PASS;
}

SEC("xdp")
int xdp_stage1_policy(struct xdp_md *ctx) {
    __u32 zero = 0;
    struct pkt_scratch *sc = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!sc)
        return XDP_ABORTED;

    bpf_printk("Stage 1 policy inspected proto=%d from %pI4\\n", sc->protocol, &sc->src_ip);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`,
    goFileName: 'main.go',
    goCode: `package main

import (
	"log"
	"net"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf tail_call_pipeline.bpf.c

func main() {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	// Wire Stage 1 program FD into slot 1 of the PROG_ARRAY jump table!
	stage1Index := uint32(1)
	if err := objs.JmpTable.Put(&stage1Index, objs.XdpStage1Policy); err != nil {
		log.Fatalf("populating tail call table: %v", err)
	}

	iface, _ := net.InterfaceByName("eth0")
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpStage0Ingress,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	log.Println("Multi-stage XDP tail-call pipeline active!")
}`,
    steps: [
      {
        stepNumber: 1,
        title: 'Store Parsed L3 State in Per-CPU Scratch Map',
        explanation:
          'Stage 0 parses Ethernet and IPv4 headers and saves src_ip and l4_offset in key 0 of the Per-CPU scratch_map.',
        activePipelineNode: 'map',
        cHighlightLines: [41, 48],
        goHighlightLines: [13, 18],
        keyInsight: 'Because preemption is disabled during XDP execution, key 0 of scratch_map is guaranteed to belong to this packet.'
      },
      {
        stepNumber: 2,
        title: 'Jump to Stage 1 via bpf_tail_call()',
        explanation:
          'In Go, objs.JmpTable.Put(&stage1Index, objs.XdpStage1Policy) registers Stage 1 at slot 1. In C, bpf_tail_call(ctx, &jmp_table, 1) jumps directly to Stage 1.',
        activePipelineNode: 'hook',
        cHighlightLines: [50, 63],
        goHighlightLines: [20, 24],
        keyInsight: 'You can hot-swap objs.JmpTable.Put(&stage1Index, newProgram) at runtime with zero dropped packets!'
      }
    ],
    verifierChallenge: {
      title: 'Fix Program Type Mismatch in BPF_MAP_TYPE_PROG_ARRAY',
      prompt:
        'All programs inserted into a PROG_ARRAY and called via bpf_tail_call() must match the caller’s program type (e.g., XDP cannot tail-call into a kprobe).',
      buggySnippet: `// Caller is SEC("xdp"), but target is SEC("kprobe/tcp_connect")!
objs.JmpTable.Put(uint32(1), objs.KpTcpConnect)`,
      fixedSnippet: `// Both caller and target are SEC("xdp") (BPF_PROG_TYPE_XDP)
objs.JmpTable.Put(uint32(1), objs.XdpStage1Policy)`,
      verifierErrorOutput: `tail_call: prog_type mismatch: expected BPF_PROG_TYPE_XDP, got BPF_PROG_TYPE_KPROBE`,
      verifierPassOutput: `PROG_ARRAY slot[1] updated with XDP program fd=7
safe — tail call target type & attach_type verified`,
      explanation:
        'Because the context pointer R1 (struct xdp_md *) is passed directly to the tail-called program, both programs must share the exact same program type.'
    },
    simulatorPresetId: 'preset-xdp-firewall'
  },
  {
    id: 'tut-beg-06-openat-unlink',
    index: '16',
    title: 'Tracing File Opens & Deletions (sys_enter_openat & sys_exit_openat)',
    tier: 'beginner',
    hookType: 'tracepoint',
    duration: '15 min',
    minKernel: 'Linux 5.8+',
    summary:
      'Correlate sys_enter_openat (__user filename string) with sys_exit_openat (returned file descriptor or -EACCES error) using a TID-keyed inflight hash map.',
    learningObjectives: [
      'Read __user filename pointers safely with bpf_probe_read_user_str() on sys_enter_openat.',
      'Stash inflight syscall arguments in a BPF_MAP_TYPE_HASH keyed by full 64-bit pid_tgid.',
      'Join entry arguments with ctx->ret in sys_exit_openat to detect failed file access attempts (-EACCES / -ENOENT).'
    ],
    conceptGuide: {
      whatIsTitle: 'Why Do Syscall Tracepoints Come in sys_enter and sys_exit Pairs?',
      whatIsContent:
        'When a process calls openat(), the filename pointer exists at syscall entry (sys_enter_openat), but the kernel does not know whether the open will succeed or return -EACCES (-13) until the VFS finishes running (sys_exit_openat). By pairing both tracepoints via a thread-keyed BPF hash map, you get both the filename and the resulting file descriptor or error code!',
      howItWorksTitle: 'How Thread-ID Map Correlation Works',
      howItWorksContent:
        'In sys_enter_openat, we use bpf_get_current_pid_tgid() (64-bit TGID+TID) as a key in an inflight hash map and save the filename string. When that same thread reaches sys_exit_openat a few microseconds later, we look up the saved filename by pid_tgid, attach ctx->ret, emit a complete RingBuffer record, and delete the map entry.',
      whyUseInsteadTitle: 'Why Correlate Entry & Exit Instead of Only Hooking sys_enter_openat?',
      whyUseInsteadContent:
        'Hooking only sys_enter_openat tells you what a process tried to open, but not whether it succeeded or failed with Permission Denied (-EACCES), nor which file descriptor number was assigned.',
      comparisonHighlight: {
        chosenApproach: 'Paired sys_enter_openat + sys_exit_openat with TID Hash Map',
        alternativeApproach: 'Single sys_enter_openat Hook Only',
        overheadDelta: '+1 hash map lookup/delete (~40ns) for complete return code visibility',
        stabilityNote: 'Always call bpf_map_delete_elem() in sys_exit so the inflight map never fills up!'
      }
    },
    cFileName: 'openat_correlate.bpf.c',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct open_inflight_val {
    __u32 flags;
    char filename[128];
};

struct open_audit_event {
    __u32 pid;
    __s64 ret_fd;
    __u32 flags;
    char comm[16];
    char filename[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64); // 64-bit pid_tgid
    __type(value, struct open_inflight_val);
} inflight_opens SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} open_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct open_inflight_val val = {};

    const char *filename_ptr = (const char *)ctx->args[1];
    val.flags = (__u32)ctx->args[2];

    bpf_probe_read_user_str(&val.filename, sizeof(val.filename), filename_ptr);
    bpf_map_update_elem(&inflight_opens, &id, &val, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_exit_openat(struct trace_event_raw_sys_exit *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct open_inflight_val *val = bpf_map_lookup_elem(&inflight_opens, &id);
    if (!val)
        return 0;

    struct open_audit_event *e = bpf_ringbuf_reserve(&open_events, sizeof(*e), 0);
    if (e) {
        e->pid = id >> 32;
        e->ret_fd = ctx->ret;
        e->flags = val->flags;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        __builtin_memcpy(&e->filename, val->filename, sizeof(e->filename));
        bpf_ringbuf_submit(e, 0);
    }

    bpf_map_delete_elem(&inflight_opens, &id);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`,
    goFileName: 'main.go',
    goCode: `package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type open_audit_event bpf openat_correlate.bpf.c

func main() {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	tpEnter, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceEnterOpenat, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer tpEnter.Close()

	tpExit, err := link.Tracepoint("syscalls", "sys_exit_openat", objs.TraceExitOpenat, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer tpExit.Close()

	rd, err := ringbuf.NewReader(objs.OpenEvents)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	var evt bpfOpenAuditEvent
	for {
		rec, err := rd.Read()
		if err != nil {
			break
		}
		_ = binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &evt)
		fmt.Printf("PID=%d (%s) openat(%q) => ret=%d\n",
			evt.Pid,
			unix.ByteSliceToString(evt.Comm[:]),
			unix.ByteSliceToString(evt.Filename[:]),
			evt.RetFd,
		)
	}
}`,
    steps: [
      {
        stepNumber: 1,
        title: 'Capture __user Filename on sys_enter_openat',
        explanation:
          'ctx->args[1] holds the userspace filename pointer. We copy it safely with bpf_probe_read_user_str() and store it in inflight_opens keyed by the 64-bit pid_tgid.',
        activePipelineNode: 'hook',
        cHighlightLines: [30, 41],
        goHighlightLines: [21, 25],
        keyInsight: 'Using the full 64-bit pid_tgid prevents thread collisions in multi-threaded Go/Java apps.'
      },
      {
        stepNumber: 2,
        title: 'Join with Return Code & Clean Up Map in sys_exit_openat',
        explanation:
          'When openat finishes, we look up inflight_opens, combine the saved filename with ctx->ret (the FD or negative -errno), submit to RingBuf, and delete the map key.',
        activePipelineNode: 'ringbuf',
        cHighlightLines: [43, 62],
        goHighlightLines: [27, 48],
        keyInsight: 'Always delete the inflight map entry even if bpf_ringbuf_reserve fails!'
      }
    ],
    verifierChallenge: {
      title: 'Fix Kernel vs. User Address Space Helper Bug',
      prompt:
        'Using bpf_probe_read_kernel_str() on a syscall argument pointer (const char __user *filename) fails on modern CPUs with SMAP/PAN!',
      buggySnippet: `const char *filename_ptr = (const char *)ctx->args[1];
// BUG: filename_ptr is a __user address, not a kernel address!
bpf_probe_read_kernel_str(&val.filename, sizeof(val.filename), filename_ptr);`,
      fixedSnippet: `const char *filename_ptr = (const char *)ctx->args[1];
bpf_probe_read_user_str(&val.filename, sizeof(val.filename), filename_ptr);`,
      verifierErrorOutput: `Runtime SMAP fault (-EFAULT): attempted kernel read on __user address 0x7ffc8a910420`,
      verifierPassOutput: `14: (85) call bpf_probe_read_user_str#114
safe — user-space page-fault-tolerant string copy verified`,
      explanation:
        'System call pointer arguments point into user-space virtual memory and must always be read with bpf_probe_read_user() or bpf_probe_read_user_str().'
    },
    simulatorPresetId: 'preset-syscall-execve'
  },
  {
    id: 'tut-beg-07-core-ancestry',
    index: '17',
    title: 'Process Ancestry & Container Escape Detection with BPF_CORE_READ',
    tier: 'beginner',
    hookType: 'kprobe',
    duration: '16 min',
    minKernel: 'Linux 5.5+',
    summary:
      'Use BPF_KPROBE and variadic BPF_CORE_READ() macros to walk task->real_parent->real_parent pointer chains and detect suspicious web-server shell spawns.',
    learningObjectives: [
      'Unpack function arguments portably across x86_64 and ARM64 using BPF_KPROBE.',
      'Chain multi-hop pointer dereferences in a single BPF_CORE_READ(task, real_parent, tgid) call.',
      'Extract grandparent PID and command name (comm) to spot reverse-shell process trees (e.g., nginx -> sh -> curl).'
    ],
    conceptGuide: {
      whatIsTitle: 'What is Multi-Hop Pointer Chasing in eBPF?',
      whatIsContent:
        'In Linux, every process is represented by a struct task_struct containing a pointer to its parent process (task->real_parent), which in turn points to the grandparent process (task->real_parent->real_parent). Walking this ancestry chain inside eBPF lets you immediately see that a curl command was spawned by /bin/sh inside an nginx worker!',
      howItWorksTitle: 'How Variadic BPF_CORE_READ() Chases Pointers Safely',
      howItWorksContent:
        'Instead of writing three separate bpf_probe_read_kernel() calls with temporary stack variables, BPF_CORE_READ(task, real_parent, real_parent, tgid) automatically expands into nested CO-RE relocated kernel reads.',
      whyUseInsteadTitle: 'Why Capture Process Ancestry in Kernel Instead of Querying /proc/<ppid> in Userspace?',
      whyUseInsteadContent:
        'Attackers frequently use double-fork tricks where the intermediate parent shell exits in 1 millisecond—long before a userspace agent can read /proc/<ppid>/stat! Reading task->real_parent inside the kernel hook captures the exact parent at the microsecond of execution.',
      comparisonHighlight: {
        chosenApproach: 'In-Kernel BPF_CORE_READ(task, real_parent, ...)',
        alternativeApproach: 'Userspace /proc/<ppid>/status Polling',
        overheadDelta: 'Zero race conditions against short-lived double-forked processes',
        stabilityNote: 'Always use real_parent (actual spawning process) rather than parent (which changes under ptrace/gdb).'
      }
    },
    cFileName: 'process_ancestry.bpf.c',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct ancestry_event {
    __u32 pid;
    __u32 ppid;
    __u32 gppid;
    char comm[16];
    char parent_comm[16];
    char grandparent_comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} lineage_rb SEC(".maps");

SEC("kprobe/wake_up_new_task")
int BPF_KPROBE(kp_wake_up_new_task, struct task_struct *child) {
    struct ancestry_event *e = bpf_ringbuf_reserve(&lineage_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid   = BPF_CORE_READ(child, tgid);
    e->ppid  = BPF_CORE_READ(child, real_parent, tgid);
    e->gppid = BPF_CORE_READ(child, real_parent, real_parent, tgid);

    BPF_CORE_READ_STR_INTO(&e->comm, child, comm);
    BPF_CORE_READ_STR_INTO(&e->parent_comm, child, real_parent, comm);
    BPF_CORE_READ_STR_INTO(&e->grandparent_comm, child, real_parent, real_parent, comm);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`,
    goFileName: 'main.go',
    goCode: `package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type ancestry_event bpf process_ancestry.bpf.c

func main() {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	kp, err := link.Kprobe("wake_up_new_task", objs.KpWakeUpNewTask, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer kp.Close()

	rd, err := ringbuf.NewReader(objs.LineageRb)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	var evt bpfAncestryEvent
	for {
		rec, err := rd.Read()
		if err != nil {
			break
		}
		_ = binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &evt)
		fmt.Printf("[Process Tree] %s(%d) -> %s(%d) -> %s(%d)\n",
			unix.ByteSliceToString(evt.GrandparentComm[:]), evt.Gppid,
			unix.ByteSliceToString(evt.ParentComm[:]), evt.Ppid,
			unix.ByteSliceToString(evt.Comm[:]), evt.Pid,
		)
	}
}`,
    steps: [
      {
        stepNumber: 1,
        title: 'Hook wake_up_new_task with BPF_KPROBE',
        explanation:
          'wake_up_new_task(struct task_struct *child) is called by the kernel scheduler whenever a newly forked/cloned task is about to run for the first time.',
        activePipelineNode: 'hook',
        cHighlightLines: [21, 25],
        goHighlightLines: [21, 25],
        keyInsight: 'BPF_KPROBE automatically extracts the first argument (struct task_struct *child) from PT_REGS_PARM1(ctx).'
      },
      {
        stepNumber: 2,
        title: 'Read 3 Generations of Process Lineage with BPF_CORE_READ',
        explanation:
          'BPF_CORE_READ and BPF_CORE_READ_STR_INTO traverse child -> real_parent -> real_parent in one line and copy each comm string into the Ring Buffer.',
        activePipelineNode: 'ringbuf',
        cHighlightLines: [27, 36],
        goHighlightLines: [34, 46],
        keyInsight: 'Even if an intermediate pointer were NULL, bpf_probe_read_kernel safely zeroes the output rather than panicking.'
      }
    ],
    verifierChallenge: {
      title: 'Fix Hardcoded Architecture Register Access in Kprobe',
      prompt:
        'Reading ctx->di directly in a kprobe fails to compile on ARM64 (where argument 1 is stored in regs[0], not rdi). Use PT_REGS_PARM1 or BPF_KPROBE!',
      buggySnippet: `SEC("kprobe/wake_up_new_task")
int kp_wake_up_new_task(struct pt_regs *ctx) {
    // BUG: ctx->di only exists on x86_64! Fails on ARM64 Graviton / Apple Silicon!
    struct task_struct *child = (struct task_struct *)ctx->di;
    return 0;
}`,
      fixedSnippet: `SEC("kprobe/wake_up_new_task")
int BPF_KPROBE(kp_wake_up_new_task, struct task_struct *child) {
    __u32 pid = BPF_CORE_READ(child, tgid);
    return 0;
}`,
      verifierErrorOutput: `error: no member named 'di' in 'struct user_pt_regs' (target: bpfel / arm64)`,
      verifierPassOutput: `BPF_KPROBE expanded to PT_REGS_PARM1(ctx)
safe — cross-architecture register ABI verified`,
      explanation:
        'BPF_KPROBE and PT_REGS_PARM1() abstract CPU register names across x86_64, ARM64, RISC-V, and s390x.'
    },
    simulatorPresetId: 'preset-syscall-execve'
  },
  {
    id: 'tut-mid-13-fentry-fexit',
    index: '18',
    title: 'Zero-Overhead Function Profiling with fentry & fexit BTF Trampolines',
    tier: 'intermediate',
    hookType: 'fexit',
    duration: '18 min',
    minKernel: 'Linux 5.5+',
    summary:
      'Replace legacy kprobe + kretprobe pairs with a single BTF-typed fexit trampoline that accesses both input arguments and the return value simultaneously at 10x lower overhead.',
    learningObjectives: [
      'Declare a BTF-enabled SEC("fexit/...") program using the BPF_PROG macro.',
      'Access both input struct pointers (like struct sock *sk) and the function return value in the same fexit hook.',
      'Attach fentry/fexit programs in Go via link.AttachTracing(link.TracingOptions{Program: ...}).'
    ],
    conceptGuide: {
      whatIsTitle: 'What Are fentry and fexit BPF Trampolines?',
      whatIsContent:
        'Introduced in Linux 5.5, fentry (function entry) and fexit (function exit) replace CPU breakpoint traps (int3) with direct native call trampolines at the 5-byte NOP ftrace header of kernel functions. Even better, fexit receives all input arguments PLUS the return value together!',
      howItWorksTitle: 'How BTF Direct Memory Access Works in fentry/fexit',
      howItWorksContent:
        'Because the kernel Verifier knows the exact BTF signature of the hooked function, pointers passed to BPF_PROG are trusted PTR_TO_BTF_ID registers. You can read sk->__sk_common.skc_daddr directly using normal C arrow syntax without calling bpf_probe_read_kernel()!',
      whyUseInsteadTitle: 'Why Use fexit Instead of kretprobe?',
      whyUseInsteadContent:
        'In a kretprobe, input arguments are lost when the function returns, forcing you to attach a second kprobe at entry and stash arguments in a BPF hash map. fexit preserves input arguments in the trampoline stack frame automatically!',
      comparisonHighlight: {
        chosenApproach: 'SEC("fexit/tcp_connect") BTF Trampoline',
        alternativeApproach: 'kprobe + kretprobe + Hash Map Correlation',
        overheadDelta: '~30ns direct call vs ~350ns dual int3 trap + map lookup',
        stabilityNote: 'Attached in Go via link.AttachTracing(link.TracingOptions{Program: objs.FexitTcpConnect}).'
      }
    },
    cFileName: 'fexit_tcp_connect.bpf.c',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

struct tcp_conn_result {
    __u32 pid;
    __u32 saddr;
    __u32 daddr;
    __u16 dport;
    __s32 ret;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} conn_rb SEC(".maps");

// Kernel signature: int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
// In fexit, BPF_PROG receives all 3 input parameters PLUS the return value (int ret) last!
SEC("fexit/tcp_v4_connect")
int BPF_PROG(fexit_tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret) {
    struct tcp_conn_result *e = bpf_ringbuf_reserve(&conn_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid   = bpf_get_current_pid_tgid() >> 32;
    // Direct BTF pointer access — no bpf_probe_read_kernel required!
    e->saddr = sk->__sk_common.skc_rcv_saddr;
    e->daddr = sk->__sk_common.skc_daddr;
    e->dport = __bpf_ntohs(sk->__sk_common.skc_dport);
    e->ret   = ret;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`,
    goFileName: 'main.go',
    goCode: `package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type tcp_conn_result bpf fexit_tcp_connect.bpf.c

func main() {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	// Attach BTF fexit trampoline via link.AttachTracing
	tr, err := link.AttachTracing(link.TracingOptions{
		Program: objs.FexitTcpV4Connect,
	})
	if err != nil {
		log.Fatalf("attaching fexit trampoline: %v", err)
	}
	defer tr.Close()

	rd, err := ringbuf.NewReader(objs.ConnRb)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	var res bpfTcpConnResult
	for {
		rec, err := rd.Read()
		if err != nil {
			break
		}
		_ = binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &res)
		dstIP := make(net.IP, 4)
		binary.LittleEndian.PutUint32(dstIP, res.Daddr)
		fmt.Printf("PID=%d tcp_v4_connect -> %s:%d (ret=%d)\n", res.Pid, dstIP, res.Dport, res.Ret)
	}
}`,
    steps: [
      {
        stepNumber: 1,
        title: 'Declare SEC("fexit/tcp_v4_connect") with BPF_PROG',
        explanation:
          'BPF_PROG unpacks the 64-bit trampoline context array into typed parameters: (struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret).',
        activePipelineNode: 'hook',
        cHighlightLines: [20, 24],
        goHighlightLines: [21, 28],
        keyInsight: 'Notice how fexit gives you both struct sock *sk (which sk_daddr was populated into during the call) AND int ret!'
      },
      {
        stepNumber: 2,
        title: 'Direct BTF Pointer Dereference & link.AttachTracing',
        explanation:
          'Because sk has verifier type PTR_TO_BTF_ID, sk->__sk_common.skc_daddr compiles to a single native CPU load instruction.',
        activePipelineNode: 'verifier',
        cHighlightLines: [28, 35],
        goHighlightLines: [36, 48],
        keyInsight: 'In Go, fentry and fexit programs are attached using link.AttachTracing rather than link.Kprobe.'
      }
    ],
    verifierChallenge: {
      title: 'Fix BPF_KPROBE vs. BPF_PROG Macro Mismatch in fentry/fexit',
      prompt:
        'Using BPF_KPROBE on an fentry/fexit hook fails because fentry/fexit passes a raw uint64_t args[] array, not a struct pt_regs * register frame!',
      buggySnippet: `SEC("fexit/tcp_v4_connect")
// BUG: BPF_KPROBE expects struct pt_regs *, but fexit passes unsigned long long *ctx!
int BPF_KPROBE(fexit_tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len) {
    return 0;
}`,
      fixedSnippet: `SEC("fexit/tcp_v4_connect")
// FIXED: BPF_PROG unpacks the BTF trampoline ctx[] array including return value ret
int BPF_PROG(fexit_tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret) {
    return 0;
}`,
      verifierErrorOutput: `invalid bpf_context access off=112 size=8: fexit context only has 32 bytes (4 args × 8B)`,
      verifierPassOutput: `BTF trampoline verified: 3 input args + 1 return value (32 bytes)
safe — PTR_TO_BTF_ID(struct sock) direct access enabled`,
      explanation:
        'Always pair kprobe/uprobe with BPF_KPROBE, and pair fentry/fexit/lsm/tp_btf with BPF_PROG.'
    },
    simulatorPresetId: 'preset-tcp-latency'
  },
  {
    id: 'tut-mid-14-cgroup-connect4',
    index: '19',
    title: 'Container Socket Load Balancing & Egress Policy with cgroup/connect4',
    tier: 'intermediate',
    hookType: 'cgroup',
    duration: '19 min',
    minKernel: 'Linux 4.17+',
    summary:
      'Intercept outbound IPv4 connect() calls inside a container cgroup v2 hierarchy to transparently redirect Virtual Service IPs to backend pods before a single SYN packet is sent.',
    learningObjectives: [
      'Write a SEC("cgroup/connect4") program receiving struct bpf_sock_addr *ctx.',
      'Rewrite ctx->user_ip4 and ctx->user_port in-place to redirect connections at the socket layer.',
      'Attach the program to a cgroup v2 directory in Go via link.AttachCgroup.'
    ],
    conceptGuide: {
      whatIsTitle: 'How Does Socket-Layer Load Balancing (kube-proxy Replacement) Work?',
      whatIsContent:
        'When a microservice dials a Kubernetes Service Virtual IP (like 10.96.0.1:80), traditional kube-proxy lets the kernel create a TCP packet to 10.96.0.1 and then uses iptables DNAT to rewrite the packet header on every packet. With SEC("cgroup/connect4"), eBPF intercepts the connect() syscall and updates ctx->user_ip4 to the backend pod IP (e.g. 10.244.1.40:8080) before the TCP handshake even starts!',
      howItWorksTitle: 'How Return Values Work in cgroup/connect4',
      howItWorksContent:
        'In cgroup/connect4, returning 1 ALLOWS the connection (using whatever user_ip4 and user_port values are currently in ctx), while returning 0 DENIES the connection immediately with -EPERM (Operation not permitted).',
      whyUseInsteadTitle: 'Why Use cgroup/connect4 Instead of TC/iptables Packet NAT?',
      whyUseInsteadContent:
        'Socket-layer redirection executes only once per TCP connection during connect(), reducing per-packet NAT overhead to zero for the entire lifetime of the connection!',
      comparisonHighlight: {
        chosenApproach: 'SEC("cgroup/connect4") Socket Destination Rewrite',
        alternativeApproach: 'iptables DNAT + nf_conntrack per-packet translation',
        overheadDelta: '0 ns per data packet after connect(); no conntrack table pressure',
        stabilityNote: 'Remember: in cgroup hooks, 1 = ALLOW and 0 = DENY!'
      }
    },
    cFileName: 'cgroup_lb.bpf.c',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct vip_key {
    __u32 vip;
    __u16 vport;
    __u16 pad;
};

struct backend_val {
    __u32 backend_ip;
    __u16 backend_port;
    __u16 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct vip_key);
    __type(value, struct backend_val);
} service_lb_map SEC(".maps");

SEC("cgroup/connect4")
int cg_sock_connect4(struct bpf_sock_addr *ctx) {
    if (ctx->protocol != IPPROTO_TCP)
        return 1; // 1 = ALLOW non-TCP connections untouched

    struct vip_key key = {
        .vip   = ctx->user_ip4,
        .vport = __bpf_ntohs(ctx->user_port),
    };

    struct backend_val *dst = bpf_map_lookup_elem(&service_lb_map, &key);
    if (!dst)
        return 1; // Not a virtual service IP; allow normal connect

    // Rewrite destination IP and port in-place before TCP SYN is generated!
    ctx->user_ip4  = dst->backend_ip;
    ctx->user_port = __bpf_htons(dst->backend_port);
    return 1; // 1 = ALLOW connection with rewritten destination
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`,
    goFileName: 'main.go',
    goCode: `package main

import (
	"encoding/binary"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf cgroup_lb.bpf.c

func ipToUint32(ipStr string) uint32 {
	ip := net.ParseIP(ipStr).To4()
	return binary.LittleEndian.Uint32(ip)
}

func main() {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	// Map Virtual Service 10.96.0.1:80 -> Backend Pod 10.244.1.50:8080
	key := bpfVipKey{Vip: ipToUint32("10.96.0.1"), Vport: 80}
	val := bpfBackendVal{BackendIp: ipToUint32("10.244.1.50"), BackendPort: 8080}
	if err := objs.ServiceLbMap.Put(&key, &val); err != nil {
		log.Fatal(err)
	}

	cg, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.CgSockConnect4,
	})
	if err != nil {
		log.Fatalf("attaching cgroup/connect4: %v", err)
	}
	defer cg.Close()
	log.Println("Cgroup v2 socket load balancer active!")
}`,
    steps: [
      {
        stepNumber: 1,
        title: 'Look Up Destination VIP in service_lb_map',
        explanation:
          'When a process calls connect(), ctx->user_ip4 and ctx->user_port hold the target address. We look up that pair in service_lb_map.',
        activePipelineNode: 'map',
        cHighlightLines: [25, 37],
        goHighlightLines: [25, 31],
        keyInsight: 'ctx->user_port is stored in network byte order (big-endian), so use __bpf_ntohs / __bpf_htons.'
      },
      {
        stepNumber: 2,
        title: 'Mutate ctx->user_ip4 In-Place & Attach to Cgroup v2',
        explanation:
          'Overwriting ctx->user_ip4 and ctx->user_port redirects the socket transparently before tcp_v4_connect runs.',
        activePipelineNode: 'hook',
        cHighlightLines: [39, 43],
        goHighlightLines: [33, 41],
        keyInsight: 'Returning 1 permits the connection; returning 0 blocks the connection with EPERM.'
      }
    ],
    verifierChallenge: {
      title: 'Fix Inverted Return Code in Cgroup Socket Hook',
      prompt:
        'Unlike kprobes or LSM hooks (where 0 means success/allow), returning 0 from cgroup/connect4 or cgroup/skb DROPS/BLOCKS every connection in the container!',
      buggySnippet: `SEC("cgroup/connect4")
int cg_sock_connect4(struct bpf_sock_addr *ctx) {
    // BUG: Returning 0 in cgroup/connect4 DENIES all outbound connections with -EPERM!
    return 0;
}`,
      fixedSnippet: `SEC("cgroup/connect4")
int cg_sock_connect4(struct bpf_sock_addr *ctx) {
    // FIXED: Return 1 to allow the connection in cgroup hooks
    return 1;
}`,
      verifierErrorOutput: `Runtime policy bug: return 0 in BPF_CGROUP_INET4_CONNECT rejects syscall with -EPERM`,
      verifierPassOutput: `24: (b7) r0 = 1 ; CGROUP_ALLOW
safe — valid cgroup verdict range [0, 1] verified`,
      explanation:
        'In cgroup/connect4 and cgroup/skb, return 1 means ALLOW and return 0 means DENY.'
    },
    simulatorPresetId: 'preset-tc-ratelimit'
  },
  {
    id: 'tut-adv-20-fileless-memfd',
    index: '20',
    title: 'Detecting Fileless Malware Execution (memfd_create + execveat)',
    tier: 'advanced',
    hookType: 'tracepoint',
    duration: '22 min',
    minKernel: 'Linux 5.8+',
    summary:
      'Build a runtime security detector that catches in-memory ELF payload execution via memfd_create() and AT_EMPTY_PATH execveat() syscalls without touching disk.',
    learningObjectives: [
      'Understand how Linux fileless malware uses memfd_create() to create anonymous RAM-backed files.',
      'Hook sys_enter_memfd_create and sys_enter_execveat to flag anonymous fd execution (AT_EMPTY_PATH = 0x1000).',
      'Stream high-severity forensic alerts to Go userspace over a BPF Ring Buffer.'
    ],
    conceptGuide: {
      whatIsTitle: 'How Does Fileless Malware Evade Disk Antivirus on Linux?',
      whatIsContent:
        'Traditional security scanners watch filesystem writes on disk. Sophisticated attackers bypass disk inspection entirely by calling memfd_create("", MFD_CLOEXEC), writing a downloaded ELF binary directly into the returned RAM file descriptor, and executing `/proc/self/fd/<fd>` via execveat(fd, "", argv, envp, AT_EMPTY_PATH)!',
      howItWorksTitle: 'How Multi-Syscall eBPF Correlation Spots In-Memory Execution',
      howItWorksContent:
        'By hooking tracepoint/syscalls/sys_enter_memfd_create and tracepoint/syscalls/sys_enter_execveat, our eBPF program records processes that allocate anonymous memory files and immediately alerts when execveat is called with AT_EMPTY_PATH (0x1000) or a /proc/self/fd path.',
      whyUseInsteadTitle: 'Why Detect Fileless Execution in eBPF Instead of File Integrity Monitoring (FIM)?',
      whyUseInsteadContent:
        'FIM tools (like inotify/fanotify on disk mounts) never see anonymous tmpfs/ramfs memfd files because no disk inode is ever created. Syscall and LSM hooks in eBPF catch every execution regardless of backing storage.',
      comparisonHighlight: {
        chosenApproach: 'eBPF memfd_create + execveat Syscall Correlation',
        alternativeApproach: 'Disk-Based File Integrity Monitoring (FIM)',
        overheadDelta: '100% visibility into RAM-backed anonymous ELF execution',
        stabilityNote: 'Combine with lsm/bprm_check_security to block memfd execution inline!'
      }
    },
    cFileName: 'fileless_detect.bpf.c',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define AT_EMPTY_PATH 0x1000

struct fileless_alert {
    __u32 pid;
    __u32 uid;
    __u32 flags;
    char alert_type[16];
    char comm[16];
    char name[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} alerts SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int trace_memfd_create(struct trace_event_raw_sys_enter *ctx) {
    struct fileless_alert *a = bpf_ringbuf_reserve(&alerts, sizeof(*a), 0);
    if (!a)
        return 0;

    a->pid   = bpf_get_current_pid_tgid() >> 32;
    a->uid   = bpf_get_current_uid_gid();
    a->flags = (__u32)ctx->args[1];
    __builtin_memcpy(a->alert_type, "MEMFD_CREATE", 13);
    bpf_get_current_comm(&a->comm, sizeof(a->comm));

    const char *uname = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&a->name, sizeof(a->name), uname);

    bpf_ringbuf_submit(a, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_execveat(struct trace_event_raw_sys_enter *ctx) {
    __u32 flags = (__u32)ctx->args[4];
    struct fileless_alert *a = bpf_ringbuf_reserve(&alerts, sizeof(*a), 0);
    if (!a)
        return 0;

    a->pid   = bpf_get_current_pid_tgid() >> 32;
    a->uid   = bpf_get_current_uid_gid();
    a->flags = flags;
    __builtin_memcpy(a->alert_type, (flags & AT_EMPTY_PATH) ? "FD_EXECVEAT" : "EXECVEAT", 12);
    bpf_get_current_comm(&a->comm, sizeof(a->comm));

    const char *path = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&a->name, sizeof(a->name), path);

    bpf_ringbuf_submit(a, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`,
    goFileName: 'main.go',
    goCode: `package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type fileless_alert bpf fileless_detect.bpf.c

func main() {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	tpMemfd, err := link.Tracepoint("syscalls", "sys_enter_memfd_create", objs.TraceMemfdCreate, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer tpMemfd.Close()

	tpExec, err := link.Tracepoint("syscalls", "sys_enter_execveat", objs.TraceExecveat, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer tpExec.Close()

	rd, err := ringbuf.NewReader(objs.Alerts)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	var al bpfFilelessAlert
	for {
		rec, err := rd.Read()
		if err != nil {
			break
		}
		_ = binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &al)
		fmt.Printf("[SECURITY ALERT: %s] PID=%d UID=%d COMM=%s target=%q flags=0x%x\n",
			unix.ByteSliceToString(al.AlertType[:]),
			al.Pid, al.Uid,
			unix.ByteSliceToString(al.Comm[:]),
			unix.ByteSliceToString(al.Name[:]),
			al.Flags,
		)
	}
}`,
    steps: [
      {
        stepNumber: 1,
        title: 'Monitor Anonymous RAM File Creation (sys_enter_memfd_create)',
        explanation:
          'ctx->args[0] holds the anonymous memfd name and ctx->args[1] holds flags (MFD_CLOEXEC). We log every process creating an in-memory file descriptor.',
        activePipelineNode: 'hook',
        cHighlightLines: [21, 38],
        goHighlightLines: [21, 25],
        keyInsight: 'Legitimate apps rarely call memfd_create followed by execve/execveat inside a container.'
      },
      {
        stepNumber: 2,
        title: 'Detect Descriptor Execution via sys_enter_execveat',
        explanation:
          'When execveat is called with AT_EMPTY_PATH (0x1000), the kernel executes the open file descriptor passed in args[0] directly from RAM.',
        activePipelineNode: 'ringbuf',
        cHighlightLines: [40, 58],
        goHighlightLines: [27, 50],
        keyInsight: 'Checking (flags & AT_EMPTY_PATH) immediately identifies descriptor-based binary execution.'
      }
    ],
    verifierChallenge: {
      title: 'Fix Unreleased RingBuffer Reservation Leak on Conditional Branch',
      prompt:
        'If you reserve a RingBuffer slot via bpf_ringbuf_reserve() and return early on a branch without calling bpf_ringbuf_submit() or bpf_ringbuf_discard(), the Verifier rejects the program for leaking a reference!',
      buggySnippet: `struct fileless_alert *a = bpf_ringbuf_reserve(&alerts, sizeof(*a), 0);
if (!a) return 0;
if (flags == 0) {
    // BUG: Returning without submitting or discarding 'a' leaks the ringbuf reference!
    return 0;
}
bpf_ringbuf_submit(a, 0);`,
      fixedSnippet: `struct fileless_alert *a = bpf_ringbuf_reserve(&alerts, sizeof(*a), 0);
if (!a) return 0;
if (flags == 0) {
    bpf_ringbuf_discard(a, 0);
    return 0;
}
bpf_ringbuf_submit(a, 0);`,
      verifierErrorOutput: `Unreleased reference id=2 alloc_insn=6 (must call bpf_ringbuf_submit or bpf_ringbuf_discard before exit)`,
      verifierPassOutput: `All paths release alloc_mem_or_null(id=2)
safe — reference tracking verified`,
      explanation:
        'Either filter before calling bpf_ringbuf_reserve(), or call bpf_ringbuf_discard(a, 0) on every abort path.'
    },
    simulatorPresetId: 'preset-lsm-security'
  },
  {
    id: 'tut-adv-21-spinlock-timer',
    index: '21',
    title: 'Concurrency-Safe Token Bucket Rate Limiter with bpf_spin_lock',
    tier: 'advanced',
    hookType: 'XDP',
    duration: '23 min',
    minKernel: 'Linux 5.1+',
    summary:
      'Protect multi-field token-bucket state across CPU cores using struct bpf_spin_lock inside a BTF-typed BPF map without race conditions.',
    learningObjectives: [
      'Embed struct bpf_spin_lock inside a BTF-defined BPF map value struct.',
      'Acquire and release locks with bpf_spin_lock(&b->lock) and bpf_spin_unlock(&b->lock).',
      'Satisfy the Verifier’s strict critical-section rules (no helper calls while holding a spinlock!).'
    ],
    conceptGuide: {
      whatIsTitle: 'Why Do Multi-Field Map Updates Need bpf_spin_lock?',
      whatIsContent:
        'A token bucket rate limiter must read last_refill_ns, compute elapsed time, add tokens, and decrement tokens atomically for a shared source IP across all CPU cores. Without a spinlock, two cores processing packets from the same IP simultaneously will overwrite each other’s token balance!',
      howItWorksTitle: 'How the Verifier Enforces Deadlock-Free Spinlocks',
      howItWorksContent:
        'The Verifier enforces three ironclad rules on bpf_spin_lock: (1) You can only hold ONE spinlock at a time, (2) You CANNOT call any BPF helper functions inside the critical section (so call bpf_ktime_get_ns() BEFORE acquiring the lock!), and (3) Every exit path must call bpf_spin_unlock().',
      whyUseInsteadTitle: 'Why Use bpf_spin_lock Instead of __sync_fetch_and_add?',
      whyUseInsteadContent:
        'Atomic instructions (__sync_fetch_and_add) can only update a single 64-bit integer. Updating two coupled fields (tokens AND last_ts) invariants atomically requires bpf_spin_lock.',
      comparisonHighlight: {
        chosenApproach: 'struct bpf_spin_lock Inside BTF Hash Map Value',
        alternativeApproach: 'Unlocked Read-Modify-Write Across Cores',
        overheadDelta: '100% race-free multi-field state transitions across all CPUs',
        stabilityNote: 'Always call bpf_ktime_get_ns() BEFORE bpf_spin_lock() because helpers are forbidden inside spinlocks!'
      }
    },
    cFileName: 'spinlock_ratelimit.bpf.c',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct token_bucket {
    struct bpf_spin_lock lock;
    __u64 last_ts_ns;
    __u64 tokens;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32); // Source IPv4
    __type(value, struct token_bucket);
} buckets SEC(".maps");

SEC("xdp")
int xdp_token_bucket_guard(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != __bpf_htons(0x0800))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;
    // IMPORTANT: Call helper BEFORE acquiring bpf_spin_lock!
    __u64 now = bpf_ktime_get_ns();

    struct token_bucket *b = bpf_map_lookup_elem(&buckets, &src_ip);
    if (!b)
        return XDP_PASS;

    __u32 action = XDP_PASS;

    bpf_spin_lock(&b->lock);
    __u64 elapsed = now - b->last_ts_ns;
    __u64 refill  = elapsed / 1000000; // 1 token per ms
    if (refill > 0) {
        b->tokens += refill;
        if (b->tokens > 100)
            b->tokens = 100;
        b->last_ts_ns = now;
    }
    if (b->tokens > 0) {
        b->tokens--;
    } else {
        action = XDP_DROP;
    }
    bpf_spin_unlock(&b->lock);

    return action;
}

char LICENSE[] SEC("license") = "GPL";`,
    goFileName: 'main.go',
    goCode: `package main

import (
	"log"
	"net"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf spinlock_ratelimit.bpf.c

func main() {
	var objs bpfObjects
	// BTF map value containing struct bpf_spin_lock is verified at load time
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading spinlock program: %v", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName("eth0")
	if err != nil {
		log.Fatal(err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpTokenBucketGuard,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	log.Println("Spinlock-protected XDP token bucket rate limiter active!")
}`,
    steps: [
      {
        stepNumber: 1,
        title: 'Fetch Timestamp Before Entering Critical Section',
        explanation:
          'Because the Verifier forbids calling any BPF helper while holding a spinlock, we call bpf_ktime_get_ns() before calling bpf_spin_lock(&b->lock).',
        activePipelineNode: 'verifier',
        cHighlightLines: [34, 41],
        goHighlightLines: [14, 18],
        keyInsight: 'Never invoke bpf_ktime_get_ns() or bpf_printk() between bpf_spin_lock and bpf_spin_unlock!'
      },
      {
        stepNumber: 2,
        title: 'Atomic Multi-Field Refill & Decrement Under bpf_spin_lock',
        explanation:
          'Inside the critical section, we compute token refills, cap burst size at 100, decrement 1 token, and release the lock before returning action.',
        activePipelineNode: 'map',
        cHighlightLines: [43, 59],
        goHighlightLines: [24, 31],
        keyInsight: 'Store the verdict in a local variable (action) and return it only AFTER bpf_spin_unlock(&b->lock).'
      }
    ],
    verifierChallenge: {
      title: 'Fix Helper Call Inside bpf_spin_lock Critical Section',
      prompt:
        'Calling bpf_ktime_get_ns() or returning early while holding bpf_spin_lock(&b->lock) is immediately rejected by the eBPF Verifier to prevent kernel deadlocks!',
      buggySnippet: `bpf_spin_lock(&b->lock);
// BUG: Calling a BPF helper inside a bpf_spin_lock critical section is forbidden!
__u64 now = bpf_ktime_get_ns();
b->last_ts_ns = now;
bpf_spin_unlock(&b->lock);`,
      fixedSnippet: `__u64 now = bpf_ktime_get_ns(); // Call helper BEFORE locking
bpf_spin_lock(&b->lock);
b->last_ts_ns = now;
bpf_spin_unlock(&b->lock);`,
      verifierErrorOutput: `function calls are not allowed while holding a lock (insn 29: call bpf_ktime_get_ns#5)`,
      verifierPassOutput: `bpf_spin_lock acquired at insn 28, released at insn 44
safe — zero helper calls inside critical section`,
      explanation:
        'Pre-calculate all helper values (like timestamps or random numbers) in local variables prior to acquiring bpf_spin_lock.'
    },
    simulatorPresetId: 'preset-xdp-synflood'
  }
];

