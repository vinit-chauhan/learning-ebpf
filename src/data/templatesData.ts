import { ProjectTemplate } from '../types/ebpf';

export const PROJECT_TEMPLATES: ProjectTemplate[] = [
  {
    id: 'tpl-xdp-ddos-lb',
    index: '01',
    title: 'Cilium-Style XDP Edge DDoS Scrubber & L4 Load Balancer',
    domain: 'Cloud-Native Networking',
    hookTypes: ['XDP'],
    difficulty: 'intermediate',
    minKernel: 'Linux 5.4+',
    summary:
      'Production-ready XDP firewall and packet classifier in C and Go (cilium/ebpf) with LPM Trie CIDR blocklists, Per-CPU Prometheus metrics, and zero-downtime bpf_link pinning.',
    realWorldInspiration: 'Inspired by Cloudflare L4 Drop & Cilium XDP NodePort Accelerator',
    problemSolved:
      'Drops volumetric SYN/UDP flood traffic directly inside the NIC driver RX queue at 20M+ packets/sec per core before the kernel allocates sk_buff structures.',
    architectureFlow: [
      {
        stage: '1. NIC RX Ring',
        component: 'XDP Driver Hook (SEC("xdp"))',
        description: 'Intercepts raw Ethernet frame via DMA ring before sk_buff allocation.'
      },
      {
        stage: '2. CIDR Match',
        component: 'BPF_MAP_TYPE_LPM_TRIE',
        description: 'Matches source IPv4 subnet against dynamic blocklist prefixes in O(1) time.'
      },
      {
        stage: '3. Lockless Telemetry',
        component: 'BPF_MAP_TYPE_PERCPU_ARRAY',
        description: 'Increments per-verdict packet and byte counters in local CPU L1 cache.'
      },
      {
        stage: '4. Go Control Plane',
        component: 'cilium/ebpf + Prometheus HTTP Exporter',
        description: 'Hot-reloads CIDR blocklists via REST/CLI and exposes /metrics for Grafana.'
      }
    ],
    productionChecklist: [
      'Pin bpf_link to /sys/fs/bpf/xdp_scrubber so packet filtering survives Go control-plane restarts.',
      'Ensure NIC driver supports Native XDP mode (i40e, mlx5, ena, virtio_net) rather than Generic SKB mode.',
      'Use BPF_F_NO_PREALLOC on BPF_MAP_TYPE_LPM_TRIE maps as required by the kernel verifier.'
    ],
    simulatorPresetId: 'preset-xdp-firewall',
    files: [
      {
        filename: 'bpf/xdp_scrubber.bpf.c',
        language: 'c',
        description: 'Kernel XDP C program with LPM Trie CIDR matching and Per-CPU traffic accounting',
        content: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP        0x0800
#define BPF_F_NO_PREALLOC (1U << 0)

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 saddr;
};

struct traffic_counters {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 32768);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u32);
} cidr_blacklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4); // Indexed by XDP action (XDP_DROP=1, XDP_PASS=2)
    __type(key, __u32);
    __type(value, struct traffic_counters);
} verdict_stats SEC(".maps");

SEC("xdp")
int xdp_edge_guard(struct xdp_md *ctx) {
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

    struct ipv4_lpm_key key = {
        .prefixlen = 32,
        .saddr     = ip->saddr,
    };

    __u32 action = XDP_PASS;
    if (bpf_map_lookup_elem(&cidr_blacklist, &key)) {
        action = XDP_DROP;
    }

    struct traffic_counters *ctr = bpf_map_lookup_elem(&verdict_stats, &action);
    if (ctr) {
        ctr->packets += 1;
        ctr->bytes   += (ctx->data_end - ctx->data);
    }

    return action;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`
      },
      {
        filename: 'main.go',
        language: 'go',
        description: 'Go control plane using cilium/ebpf to manage LPM CIDR rules and export Per-CPU metrics',
        content: `package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type ipv4_lpm_key -type traffic_counters bpf ./bpf/xdp_scrubber.bpf.c

func blockCIDR(objs *bpfObjects, cidr string) error {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	ones, _ := ipNet.Mask.Size()
	key := bpfIpv4LpmKey{
		Prefixlen: uint32(ones),
		Saddr:     binary.LittleEndian.Uint32(ip.To4()),
	}
	val := uint32(1)
	return objs.CidrBlacklist.Put(&key, &val)
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading eBPF objects: %v", err)
	}
	defer objs.Close()

	// Seed blocked botnet subnet
	if err := blockCIDR(&objs, "198.51.100.0/24"); err != nil {
		log.Fatal(err)
	}

	iface, err := net.InterfaceByName("eth0")
	if err != nil {
		log.Fatal(err)
	}
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpEdgeGuard,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	for range time.Tick(2 * time.Second) {
		for _, verdict := range []uint32{1, 2} {
			var perCPU []bpfTrafficCounters
			_ = objs.VerdictStats.Lookup(&verdict, &perCPU)
			var pkts, bytes uint64
			for _, c := range perCPU {
				pkts += c.Packets
				bytes += c.Bytes
			}
			label := "XDP_DROP"
			if verdict == 2 {
				label = "XDP_PASS"
			}
			fmt.Printf("%-10s: %d pkts (%d bytes)\\n", label, pkts, bytes)
		}
	}
}`
      },
      {
        filename: 'Makefile',
        language: 'makefile',
        description: 'Build automation for generating vmlinux.h, running bpf2go, and compiling static Go binary',
        content: `CLANG ?= clang
GO ?= go

.PHONY: all generate build clean

all: generate build

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

generate:
	$(GO) generate ./...

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -ldflags="-s -w" -o bin/xdp-scrubber .

clean:
	rm -rf bin/ bpf_*`
      }
    ]
  },
  {
    id: 'tpl-falco-tetragon-auditor',
    index: '02',
    title: 'Tetragon-Style Kubernetes Process Lineage & File Integrity Monitor',
    domain: 'Runtime Security',
    hookTypes: ['tracepoint'],
    difficulty: 'intermediate',
    minKernel: 'Linux 5.8+',
    summary:
      'Zero-copy RingBuffer security agent that captures container process execution trees, UTS pod hostnames, cgroup IDs, and sensitive file opens.',
    realWorldInspiration: 'Inspired by Cilium Tetragon & CNCF Falco',
    problemSolved:
      'Detects short-lived malicious shell executions (e.g., reverse shells or crypto miners) inside Kubernetes pods synchronously using CO-RE task_struct traversal.',
    architectureFlow: [
      {
        stage: '1. Syscall & Sched Hooks',
        component: 'SEC("tracepoint/sched/sched_process_exec")',
        description: 'Fires synchronously inside kernel context whenever any binary executes on the node.'
      },
      {
        stage: '2. CO-RE Lineage Extraction',
        component: 'BPF_CORE_READ(task, nsproxy, uts_ns)',
        description: 'Reads parent PID, container UTS hostname, and cgroup_id before short-lived processes can exit.'
      },
      {
        stage: '3. Zero-Copy Streaming',
        component: 'BPF_MAP_TYPE_RINGBUF',
        description: 'Reserves and submits structured security events with global chronological ordering.'
      },
      {
        stage: '4. Go Alert Engine',
        component: 'cilium/ebpf/ringbuf Reader',
        description: 'Evaluates behavioral rules in Go and emits JSON structured security alerts.'
      }
    ],
    productionChecklist: [
      'Size the BPF_MAP_TYPE_RINGBUF to at least 4MB–16MB on high-churn Kubernetes nodes.',
      'Use BPF_CORE_READ_STR_INTO for all kernel string pointers to guarantee CO-RE portability.',
      'Filter noisy healthcheck binaries in-kernel using a BPF Hash Map allowlist.'
    ],
    simulatorPresetId: 'preset-syscall-execve',
    files: [
      {
        filename: 'bpf/runtime_auditor.bpf.c',
        language: 'c',
        description: 'CO-RE eBPF probe capturing process lineage, container hostname, and cgroup ID',
        content: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct security_exec_event {
    __u64 timestamp_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char pod_nodename[64];
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024); // 4 MB Ring Buffer
} audit_events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int audit_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct security_exec_event *e = bpf_ringbuf_reserve(&audit_events, sizeof(*e), 0);
    if (!e)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->cgroup_id    = bpf_get_current_cgroup_id();
    e->pid          = BPF_CORE_READ(task, tgid);
    e->ppid         = BPF_CORE_READ(task, real_parent, tgid);
    e->uid          = bpf_get_current_uid_gid();

    BPF_CORE_READ_STR_INTO(&e->pod_nodename, task, nsproxy, uts_ns, name.nodename);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`
      },
      {
        filename: 'main.go',
        language: 'go',
        description: 'Go RingBuffer consumer with JSON structured security telemetry output',
        content: `package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type security_exec_event bpf ./bpf/runtime_auditor.bpf.c

func main() {
	_ = rlimit.RemoveMemlock()
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("sched", "sched_process_exec", objs.AuditProcessExec, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.AuditEvents)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		rd.Close()
	}()

	var raw bpfSecurityExecEvent
	enc := json.NewEncoder(os.Stdout)
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		_ = binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &raw)
		_ = enc.Encode(map[string]any{
			"pid":       raw.Pid,
			"ppid":      raw.Ppid,
			"uid":       raw.Uid,
			"cgroup_id": raw.CgroupId,
			"pod":       unix.ByteSliceToString(raw.PodNodename[:]),
			"comm":      unix.ByteSliceToString(raw.Comm[:]),
		})
	}
}`
      }
    ]
  },
  {
    id: 'tpl-lsm-zero-trust-blocker',
    index: '03',
    title: 'BPF LSM Mandatory Access Control & Container Escape Preventer',
    domain: 'Runtime Security',
    hookTypes: ['lsm'],
    difficulty: 'advanced',
    minKernel: 'Linux 5.7+ (CONFIG_BPF_LSM=y)',
    summary:
      'Enforces TOCTOU-immune inline security policies on file opens and binary executions using BPF LSM hooks, returning -EPERM before compromise occurs.',
    realWorldInspiration: 'Inspired by Google KRSI (Kernel Runtime Security Instrumentation) & Kubearmor',
    problemSolved:
      'Prevents container escapes (e.g., reading /etc/shadow, /var/run/docker.sock, or executing compilers inside production pods) synchronously without race windows.',
    architectureFlow: [
      {
        stage: '1. VFS Path Resolution',
        component: 'Linux Kernel VFS Layer',
        description: 'Resolves userspace paths and symlinks into an immutable struct file * and struct inode *.'
      },
      {
        stage: '2. LSM Gatekeeper',
        component: 'SEC("lsm/file_open")',
        description: 'Invokes BPF LSM program with resolved kernel file pointer prior to granting file descriptor.'
      },
      {
        stage: '3. Inode Policy Check',
        component: 'BPF_MAP_TYPE_HASH (restricted_inodes)',
        description: 'Checks target inode and process UID/cgroup against dynamic policy map.'
      },
      {
        stage: '4. Synchronous Verdict',
        component: 'Return -EPERM (-1) or 0',
        description: 'Blocks unauthorized openat() calls inline and streams violation alert to Go.'
      }
    ],
    productionChecklist: [
      'Verify "bpf" is present in /sys/kernel/security/lsm boot parameters.',
      'Always respect prior LSM denials: if (ret != 0) return ret; at the start of every BPF_PROG.',
      'Key file policies by (device_id, inode_number) so hardlink/symlink renaming cannot bypass protection.'
    ],
    simulatorPresetId: 'preset-lsm-security',
    files: [
      {
        filename: 'bpf/lsm_enforcer.bpf.c',
        language: 'c',
        description: 'BPF LSM hook blocking unauthorized access to sensitive host inodes',
        content: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);   // Target Inode
    __type(value, __u32); // Allowed UID
} protected_inodes SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open_guard, struct file *file, int ret) {
    if (ret != 0)
        return ret;

    __u64 ino = BPF_CORE_READ(file, f_inode, i_ino);
    __u32 *allowed_uid = bpf_map_lookup_elem(&protected_inodes, &ino);
    if (!allowed_uid)
        return 0;

    __u32 uid = bpf_get_current_uid_gid();
    if (uid != *allowed_uid) {
        return -EPERM;
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";`
      },
      {
        filename: 'main.go',
        language: 'go',
        description: 'Go loader resolving /etc/shadow inode via os.Stat and attaching BPF LSM',
        content: `package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf ./bpf/lsm_enforcer.bpf.c

func main() {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	fi, err := os.Stat("/etc/shadow")
	if err == nil {
		stat := fi.Sys().(*syscall.Stat_t)
		rootUID := uint32(0)
		_ = objs.ProtectedInodes.Put(&stat.Ino, &rootUID)
		log.Printf("Protected /etc/shadow (inode %d) via BPF LSM", stat.Ino)
	}

	lsm, err := link.AttachLSM(link.LSMOptions{
		Program: objs.LsmFileOpenGuard,
	})
	if err != nil {
		log.Fatalf("attaching LSM: %v", err)
	}
	defer lsm.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}`
      }
    ]
  },
  {
    id: 'tpl-tcp-rtt-retransmit-profiler',
    index: '04',
    title: 'Fleet-Wide TCP Handshake RTT & Retransmission Profiler',
    domain: 'Performance Engineering',
    hookTypes: ['kprobe', 'kretprobe', 'tracepoint'],
    difficulty: 'intermediate',
    minKernel: 'Linux 4.19+',
    summary:
      'Correlates kprobe/kretprobe on tcp_v4_connect with tracepoint/tcp/tcp_retransmit_skb to build Per-CPU Log2 latency histograms and pinpoint tail-latency spikes.',
    realWorldInspiration: 'Inspired by Cloudflare ebpf_exporter & Brendan Gregg tcplife / tcpretrans',
    problemSolved:
      'Identifies whether microservice tail latency is caused by slow downstream TCP SYN/SYN-ACK handshakes, packet loss retransmissions, or application queueing.',
    architectureFlow: [
      {
        stage: '1. Handshake Start',
        component: 'SEC("kprobe/tcp_v4_connect")',
        description: 'Records monotonic timestamp bpf_ktime_get_ns() in LRU Hash Map keyed by Thread ID.'
      },
      {
        stage: '2. Handshake Complete',
        component: 'SEC("kretprobe/tcp_v4_connect")',
        description: 'Computes elapsed microseconds and increments Per-CPU Log2 histogram bucket.'
      },
      {
        stage: '3. Retransmit Hook',
        component: 'SEC("tracepoint/tcp/tcp_retransmit_skb")',
        description: 'Captures TCP segment retransmissions with socket state and destination IP/port.'
      },
      {
        stage: '4. Go Percentile Calculator',
        component: 'cilium/ebpf Histogram Aggregator',
        description: 'Computes p50, p95, and p99 connection latencies across all CPU cores.'
      }
    ],
    productionChecklist: [
      'Use BPF_MAP_TYPE_LRU_HASH for in-flight connection timestamps so aborted threads auto-evict cleanly.',
      'Prefer tracepoint/tcp/tcp_retransmit_skb over kprobe/tcp_retransmit_skb for cross-kernel stability.'
    ],
    simulatorPresetId: 'preset-tcp-latency',
    files: [
      {
        filename: 'bpf/tcp_profiler.bpf.c',
        language: 'c',
        description: 'Kernel TCP latency histogram and retransmission tracer',
        content: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u64);
} inflight_connects SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u64);
} rtt_hist SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kp_connect, struct sock *sk) {
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 ts  = bpf_ktime_get_ns();
    bpf_map_update_elem(&inflight_connects, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(kret_connect, int ret) {
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 *start = bpf_map_lookup_elem(&inflight_connects, &tid);
    if (!start)
        return 0;

    __u64 delta_us = (bpf_ktime_get_ns() - *start) / 1000;
    bpf_map_delete_elem(&inflight_connects, &tid);

    __u32 slot = 0;
    #pragma unroll
    for (int i = 0; i < 20; i++) {
        if (delta_us <= 1) break;
        delta_us >>= 1;
        slot++;
    }
    __u64 *cnt = bpf_map_lookup_elem(&rtt_hist, &slot);
    if (cnt)
        *cnt += 1;
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`
      },
      {
        filename: 'main.go',
        language: 'go',
        description: 'Go histogram collector printing live ASCII latency distributions',
        content: `package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf ./bpf/tcp_profiler.bpf.c

func main() {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	kp, _ := link.Kprobe("tcp_v4_connect", objs.KpConnect, nil)
	defer kp.Close()
	kretp, _ := link.Kretprobe("tcp_v4_connect", objs.KretConnect, nil)
	defer kretp.Close()

	for range time.Tick(3 * time.Second) {
		for slot := uint32(0); slot < 16; slot++ {
			var perCPU []uint64
			_ = objs.RttHist.Lookup(&slot, &perCPU)
			var sum uint64
			for _, v := range perCPU {
				sum += v
			}
			if sum > 0 {
				fmt.Printf("[%5d - %5d us] : %d\\n", 1<<slot, (1<<(slot+1))-1, sum)
			}
		}
	}
}`
      }
    ]
  },
  {
    id: 'tpl-uprobe-tls-http-tracer',
    index: '05',
    title: 'Zero-Code OpenSSL / TLS Plaintext API Tracer (Uprobe)',
    domain: 'Performance Engineering',
    hookTypes: ['uprobe'],
    difficulty: 'advanced',
    minKernel: 'Linux 4.19+',
    summary:
      'Captures decrypted HTTP/1.1, HTTP/2, and REST payloads at the libssl.so SSL_write / SSL_read boundary without modifying application containers or TLS certs.',
    realWorldInspiration: 'Inspired by Pixie (CNCF) & Grafana Beyla eBPF Auto-Instrumentation',
    problemSolved:
      'Provides instant L7 HTTP visibility into encrypted outbound and inbound microservice calls without deploying sidecar proxies or breaking mTLS.',
    architectureFlow: [
      {
        stage: '1. ELF Symbol Resolution',
        component: 'link.OpenExecutable("libssl.so.3")',
        description: 'Locates the file offset of SSL_write and SSL_read inside the shared library ELF table.'
      },
      {
        stage: '2. Userspace Trap',
        component: 'SEC("uprobe/SSL_write")',
        description: 'Intercepts cleartext buffer pointer and byte length right before encryption.'
      },
      {
        stage: '3. Verifier-Safe Copy',
        component: 'bpf_probe_read_user()',
        description: 'Masks read size (len & 0xFF) and copies up to 256 bytes into a Ring Buffer record.'
      },
      {
        stage: '4. Go L7 Parser',
        component: 'HTTP Method & Path Extractor',
        description: 'Parses HTTP status codes, methods, and paths in Go for instant APM traces.'
      }
    ],
    productionChecklist: [
      'Filter events by HTTP magic bytes ("GET ", "POST", "HTTP") in-kernel to skip binary payload chunks.',
      'Discover container library paths via /proc/<pid>/root/usr/lib/... when attaching to containerized processes.'
    ],
    simulatorPresetId: 'preset-uprobe-ssl',
    files: [
      {
        filename: 'bpf/tls_tracer.bpf.c',
        language: 'c',
        description: 'Uprobe capturing HTTP plaintext from OpenSSL SSL_write',
        content: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_CHUNK 256

struct tls_chunk {
    __u32 pid;
    __u32 len;
    char comm[16];
    char data[MAX_CHUNK];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} tls_events SEC(".maps");

SEC("uprobe/SSL_write")
int BPF_KPROBE(trace_ssl_write, void *ssl, const char *buf, int num) {
    if (num < 4)
        return 0;

    struct tls_chunk *e = bpf_ringbuf_reserve(&tls_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->len = (__u32)num;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __u32 copy_len = (__u32)num & (MAX_CHUNK - 1);
    bpf_probe_read_user(&e->data, copy_len, buf);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`
      },
      {
        filename: 'main.go',
        language: 'go',
        description: 'Go Uprobe loader and HTTP header inspector',
        content: `package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type tls_chunk bpf ./bpf/tls_tracer.bpf.c

func main() {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	ex, err := link.OpenExecutable("/usr/lib/x86_64-linux-gnu/libssl.so.3")
	if err != nil {
		log.Fatal(err)
	}
	up, err := ex.Uprobe("SSL_write", objs.TraceSslWrite, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer up.Close()

	rd, _ := ringbuf.NewReader(objs.TlsEvents)
	defer rd.Close()

	var chunk bpfTlsChunk
	for {
		rec, err := rd.Read()
		if err != nil {
			break
		}
		_ = binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &chunk)
		fmt.Printf("[PID %d] %s\\n", chunk.Pid, string(chunk.Data[:]))
	}
}`
      }
    ]
  },
  {
    id: 'tpl-sockops-service-mesh',
    index: '06',
    title: 'Sidecarless Service Mesh Socket Accelerator (Sockops & SK_MSG)',
    domain: 'Cloud-Native Networking',
    hookTypes: ['TC'],
    difficulty: 'advanced',
    minKernel: 'Linux 5.4+',
    summary:
      'Short-circuits the TCP/IP and veth network stack for local pod-to-pod and pod-to-proxy sockets using BPF_PROG_TYPE_SOCK_OPS and BPF_MAP_TYPE_SOCKHASH.',
    realWorldInspiration: 'Inspired by Cilium Socket-Level Load Balancing & Envoy eBPF Bypass',
    problemSolved:
      'Eliminates redundant TCP segmentation, checksums, and loopback routing when two communicating sockets reside on the same Kubernetes node.',
    architectureFlow: [
      {
        stage: '1. Cgroup Sockops Hook',
        component: 'SEC("sockops")',
        description: 'Intercepts active and passive TCP 3-way handshake completion events in the cgroup.'
      },
      {
        stage: '2. Socket Registration',
        component: 'BPF_MAP_TYPE_SOCKHASH',
        description: 'Stores kernel socket reference keyed by IPv4 4-tuple (local_ip, remote_ip, local_port, remote_port).'
      },
      {
        stage: '3. Sendmsg Interception',
        component: 'SEC("sk_msg")',
        description: 'Intercepts application sendmsg() calls before TCP/IP headers are constructed.'
      },
      {
        stage: '4. Zero-Stack Splice',
        component: 'bpf_msg_redirect_hash(..., BPF_F_INGRESS)',
        description: 'Copies payload bytes directly into the peer socket receive queue.'
      }
    ],
    productionChecklist: [
      'Ensure cgroup v2 is mounted at /sys/fs/cgroup on target Kubernetes nodes.',
      'Normalize port byte order carefully: skops->local_port is host order while skops->remote_port is network order.'
    ],
    simulatorPresetId: 'preset-tcp-latency',
    files: [
      {
        filename: 'bpf/sock_redir.bpf.c',
        language: 'c',
        description: 'Sockops connection tracker and SK_MSG socket queue redirector',
        content: `//go:build ignore
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
int bpf_sockmap_establish(struct bpf_sock_ops *skops) {
    if (skops->family != 2)
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
int bpf_tcp_msg_redir(struct sk_msg_md *msg) {
    struct sock_key peer = {
        .sip4  = msg->remote_ip4,
        .dip4  = msg->local_ip4,
        .sport = __bpf_ntohl(msg->remote_port),
        .dport = msg->local_port,
    };
    bpf_msg_redirect_hash(msg, &sock_ops_map, &peer, BPF_F_INGRESS);
    return SK_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`
      },
      {
        filename: 'main.go',
        language: 'go',
        description: 'Go cgroup v2 sockops and SOCKHASH sk_msg attachment loader',
        content: `package main

import (
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf ./bpf/sock_redir.bpf.c

func main() {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	cg, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupSockOps,
		Program: objs.BpfSockmapEstablish,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer cg.Close()

	if err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  objs.SockOpsMap.FD(),
		Program: objs.BpfTcpMsgRedir,
		Attach:  ebpf.AttachSkMsgVerdict,
	}); err != nil {
		log.Fatal(err)
	}

	log.Println("Sockops + SK_MSG local TCP acceleration active!")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
}`
      }
    ]
  }
];
