import { SimulatorPreset, ProjectTemplate } from '../types/ebpf';

export const SIMULATOR_PRESETS: SimulatorPreset[] = [
  {
    id: 'preset-xdp-firewall',
    name: 'XDP Line-Rate DDoS Scrubber & Per-IP Counter',
    hookPoint: 'XDP',
    category: 'Networking',
    description:
      'Parses L2 Ethernet -> L3 IPv4 -> L4 TCP headers inside the NIC driver RX ring buffer, blocks SYN flood / blocklisted source IPs with XDP_DROP, and updates per-IP packet counters.',
    mapName: 'ip_traffic_hash',
    mapType: 'BPF_MAP_TYPE_HASH',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct ip_stats {
    __u64 passed_pkts;
    __u64 dropped_pkts;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct ip_stats);
} ip_traffic_hash SEC(".maps");

SEC("xdp")
int xdp_ddos_scrubber(struct xdp_md *ctx) {
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
    struct ip_stats *st = bpf_map_lookup_elem(&ip_traffic_hash, &src_ip);
    if (!st)
        return XDP_PASS;

    // Drop high-rate SYN flood or blocklisted subnet (198.51.100.0/24)
    if ((src_ip & 0x00FFFFFF) == 0x006433C6) {
        __sync_fetch_and_add(&st->dropped_pkts, 1);
        return XDP_DROP;
    }

    __sync_fetch_and_add(&st->passed_pkts, 1);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`,
    goCode: `package main

import (
	"log"
	"net"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf xdp_ddos.bpf.c

func main() {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("verifier rejected program: %v", err)
	}
	defer objs.Close()

	iface, _ := net.InterfaceByName("eth0")
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpDdosScrubber,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("attach XDP: %v", err)
	}
	defer xdpLink.Close()
}`,
    bpfBytecode: [
      '0: (61) r2 = *(u32 *)(r1 +4)          ; r2 = ctx->data_end (pkt_end)',
      '1: (61) r1 = *(u32 *)(r1 +0)          ; r1 = ctx->data (pkt_start)',
      '2: (bf) r3 = r1                       ; r3 = ethhdr pointer',
      '3: (07) r3 += 14                      ; r3 = eth + sizeof(struct ethhdr)',
      '4: (2d) if r3 > r2 goto pc+19         ; [SAFETY] packet bounds check L2',
      '5: (71) r4 = *(u8 *)(r1 +12)          ; read eth->h_proto',
      '6: (bf) r5 = r3                       ; r5 = iphdr pointer',
      '7: (07) r5 += 20                      ; r5 = ip + sizeof(struct iphdr)',
      '8: (2d) if r5 > r2 goto pc+15         ; [SAFETY] packet bounds check L3',
      '9: (61) r6 = *(u32 *)(r3 +12)         ; r6 = ip->saddr',
      '10: (63) *(u32 *)(r10 -4) = r6        ; store key on R10 stack fp-4',
      '11: (18) r1 = map[id:1]               ; &ip_traffic_hash',
      '12: (bf) r2 = r10                     ; r2 = fp0',
      '13: (07) r2 += -4                     ; r2 = fp-4',
      '14: (85) call bpf_map_lookup_elem#1   ; R0 = map_value_or_null',
      '15: (15) if r0 == 0x0 goto pc+8       ; [SAFETY] null pointer check',
      '16: (b7) r7 = 1                       ; increment counter',
      '17: (db) lock *(u64 *)(r0 +0) += r7   ; atomic add st->passed_pkts',
      '18: (b7) r0 = 2                       ; R0 = XDP_PASS (2)',
      '19: (95) exit'
    ],
    safetyToggles: [
      {
        id: 'packetBoundsCheck',
        label: 'Enforce L2/L3 Packet Bounds Check (data + hdr <= data_end)',
        description: 'When disabled, removes if ((void *)(ip + 1) > data_end) on line 31, causing the Verifier to reject out-of-bounds packet reads.',
        cLineNumber: 31,
        buggyLineReplacement: '    // [BUG INJECTED] Omitted if ((void *)(ip + 1) > data_end) check!',
        verifierErrorLog: [
          '0: R1=ctx(off=0,imm=0) R10=fp0',
          '4: if r3 > r2 goto pc+19 -> R1=pkt(off=0,r=14) R2=pkt_end()',
          '9: (61) r6 = *(u32 *)(r3 +12)',
          'invalid access to packet, off=26 size=4, R3(id=0,off=26,r=14)',
          'R3 offset is outside of the packet (verified range r=14, attempted read at byte 26)',
          'verification failed: bpf(BPF_PROG_LOAD) returned -EACCES (Permission denied)'
        ],
        failedRegisterState: {
          R0: 'uninit',
          R1: 'pkt(off=0,r=14)',
          R2: 'pkt_end()',
          R3: 'pkt(off=14,r=14) [OUT OF BOUNDS]',
          R10: 'fp0'
        }
      },
      {
        id: 'nullMapPointerCheck',
        label: 'Enforce Map Lookup Null-Pointer Check (if (!st) return)',
        description: 'When disabled, dereferences the pointer returned by bpf_map_lookup_elem() on line 36 without checking for NULL.',
        cLineNumber: 36,
        buggyLineReplacement: '    // [BUG INJECTED] Omitted if (!st) return XDP_PASS; null check!',
        verifierErrorLog: [
          '14: (85) call bpf_map_lookup_elem#1',
          '15: R0_w=map_value_or_null(id=1,off=0,ks=4,vs=16,imm=0)',
          '16: (db) lock *(u64 *)(r0 +0) += r7',
          "R0 invalid mem access 'map_value_or_null'",
          'Hint: check if (st != NULL) before dereferencing map lookup pointer',
          'verification failed: bpf(BPF_PROG_LOAD) returned -EACCES'
        ],
        failedRegisterState: {
          R0: 'map_value_or_null(id=1) [UNCHECKED NULL]',
          R1: '0x0 (clobbered)',
          R2: '0x0 (clobbered)',
          R6: 'scalar(umin=0,umax=4294967295)',
          R10: 'fp0'
        }
      }
    ],
    initialMapEntries: [
      {
        key: '10.244.1.42 (Pod-Frontend)',
        rawHexKey: '0x0af4012a',
        value: 'passed: 1,420 | dropped: 0',
        numericValue: 1420,
        cpuCore: 0,
        updatedAt: '0.2s ago'
      },
      {
        key: '10.244.2.19 (Pod-Checkout)',
        rawHexKey: '0x0af40213',
        value: 'passed: 984 | dropped: 0',
        numericValue: 984,
        cpuCore: 1,
        updatedAt: '0.4s ago'
      },
      {
        key: '198.51.100.77 (Botnet-SYN)',
        rawHexKey: '0xc633644d',
        value: 'passed: 0 | dropped: 4,812',
        numericValue: 4812,
        cpuCore: 2,
        updatedAt: '0.1s ago'
      },
      {
        key: '172.16.0.10 (Ingress-GW)',
        rawHexKey: '0xac10000a',
        value: 'passed: 2,310 | dropped: 0',
        numericValue: 2310,
        cpuCore: 3,
        updatedAt: '0.3s ago'
      }
    ],
    initialLatencyHistogram: [
      { bucketLabel: '0–1 us', rangeUs: '1', count: 4820 },
      { bucketLabel: '2–4 us', rangeUs: '4', count: 1290 },
      { bucketLabel: '4–8 us', rangeUs: '8', count: 310 },
      { bucketLabel: '8–16 us', rangeUs: '16', count: 64 },
      { bucketLabel: '16–32 us', rangeUs: '32', count: 12 },
      { bucketLabel: '32+ us', rangeUs: '64', count: 2 }
    ]
  },

  {
    id: 'preset-syscall-execve',
    name: 'Syscall Process Execution & Container Lineage Tracer',
    hookPoint: 'tracepoint',
    category: 'Security',
    description:
      'Attaches to tracepoint/syscalls/sys_enter_execve, extracts PID, Parent PID via CO-RE, and streams binary execution records to Go via a zero-copy BPF Ring Buffer.',
    mapName: 'exec_events_ringbuf',
    mapType: 'BPF_MAP_TYPE_RINGBUF',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct exec_audit_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char comm[16];
    char filename[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} exec_events_ringbuf SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_sys_execve(struct trace_event_raw_sys_enter *ctx) {
    struct exec_audit_event *e = bpf_ringbuf_reserve(&exec_events_ringbuf, sizeof(*e), 0);
    if (!e)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->uid  = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    const char *fname = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), fname);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`,
    goCode: `package main

import (
	"bytes"
	"encoding/binary"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

func main() {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	tp, _ := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceSysExecve, nil)
	defer tp.Close()

	rd, _ := ringbuf.NewReader(objs.ExecEventsRingbuf)
	defer rd.Close()

	var ev bpfExecAuditEvent
	for {
		rec, _ := rd.Read()
		_ = binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &ev)
		log.Printf("EXEC: pid=%d ppid=%d bin=%s", ev.Pid, ev.Ppid, string(ev.Filename[:]))
	}
}`,
    bpfBytecode: [
      '0: (bf) r6 = r1                       ; save tracepoint ctx in R6',
      '1: (18) r1 = map[id:2]               ; &exec_events_ringbuf',
      '2: (b7) r2 = 92                      ; sizeof(struct exec_audit_event)',
      '3: (b7) r3 = 0                       ; flags = 0',
      '4: (85) call bpf_ringbuf_reserve#131 ; R0 = ringbuf_mem_or_null(ref_id=1)',
      '5: (15) if r0 == 0x0 goto pc+18      ; [SAFETY] check ringbuf ptr non-null',
      '6: (bf) r7 = r0                      ; R7 = ringbuf record pointer',
      '7: (85) call bpf_get_current_task#35 ; R0 = task_struct ptr',
      '8: (85) call bpf_get_current_pid_tgid#14',
      '9: (77) r0 >>= 32                    ; extract TGID (PID)',
      '10: (63) *(u32 *)(r7 +0) = r0        ; e->pid = pid',
      '11: (79) r3 = *(u64 *)(r6 +16)       ; ctx->args[0] filename user ptr',
      '12: (bf) r1 = r7                     ; r1 = &e->filename',
      '13: (07) r1 += 28                    ; offset 28 inside ringbuf struct',
      '14: (b7) r2 = 64                     ; max 64 bytes',
      '15: (85) call bpf_probe_read_user_str#114',
      '16: (bf) r1 = r7                     ; r1 = reserved ringbuf ptr',
      '17: (b7) r2 = 0                      ; flags = 0',
      '18: (85) call bpf_ringbuf_submit#132 ; release ref_id=1',
      '19: (b7) r0 = 0',
      '20: (95) exit'
    ],
    safetyToggles: [
      {
        id: 'nullMapPointerCheck',
        label: 'Enforce RingBuffer Reserve Null & Submit Check',
        description: 'When disabled, omits the null check after bpf_ringbuf_reserve() on line 22.',
        cLineNumber: 22,
        buggyLineReplacement: '    // [BUG INJECTED] Omitted if (!e) return 0; null check on ringbuf_reserve!',
        verifierErrorLog: [
          '4: (85) call bpf_ringbuf_reserve#131',
          '5: R0_w=ringbuf_mem_or_null(id=1,ref_obj_id=1,off=0,imm=0)',
          '10: (63) *(u32 *)(r7 +0) = r0',
          "R7 invalid mem access 'ringbuf_mem_or_null'",
          'verification failed: pointer from bpf_ringbuf_reserve must be checked for NULL'
        ],
        failedRegisterState: {
          R0: 'scalar(pid)',
          R6: 'ctx(off=0)',
          R7: 'ringbuf_mem_or_null(ref_id=1) [UNCHECKED]',
          R10: 'fp0'
        }
      },
      {
        id: 'stackSizeLimitCheck',
        label: 'Respect 512-Byte Kernel Stack Frame Limit',
        description: 'When disabled, allocates a 1024-byte local char array on the eBPF stack instead of using the RingBuffer.',
        cLineNumber: 25,
        buggyLineReplacement: '    char oversized_stack_buf[1024]; // [BUG INJECTED] Exceeds 512B stack limit!',
        verifierErrorLog: [
          'combined stack size of 1 calls is 1056. Max is 512',
          'Error: eBPF stack frame size (1056 bytes) exceeds kernel limit of 512 bytes (R10)',
          'Hint: allocate large structs in BPF_MAP_TYPE_PERCPU_ARRAY or via bpf_ringbuf_reserve()'
        ],
        failedRegisterState: {
          R0: 'ringbuf_mem(ref_id=1)',
          R6: 'ctx(off=0)',
          R10: 'fp0 [STACK OVERFLOW: -1056B > 512B MAX]'
        }
      }
    ],
    initialMapEntries: [
      {
        key: 'RingBuf Slot #1041',
        rawHexKey: '0x00000411',
        value: 'PID=4812 PPID=4100 UID=0 COMM=kubectl BIN=/usr/bin/kubectl',
        numericValue: 4812,
        cpuCore: 0,
        updatedAt: '0.1s ago'
      },
      {
        key: 'RingBuf Slot #1042',
        rawHexKey: '0x00000412',
        value: 'PID=4819 PPID=2910 UID=33 COMM=sh BIN=/bin/sh',
        numericValue: 4819,
        cpuCore: 2,
        updatedAt: '0.3s ago'
      },
      {
        key: 'RingBuf Slot #1043',
        rawHexKey: '0x00000413',
        value: 'PID=4825 PPID=1012 UID=1000 COMM=go BIN=/usr/local/go/bin/go',
        numericValue: 4825,
        cpuCore: 1,
        updatedAt: '0.5s ago'
      }
    ],
    initialLatencyHistogram: [
      { bucketLabel: '1–2 us', rangeUs: '2', count: 920 },
      { bucketLabel: '2–4 us', rangeUs: '4', count: 2140 },
      { bucketLabel: '4–8 us', rangeUs: '8', count: 680 },
      { bucketLabel: '8–16 us', rangeUs: '16', count: 140 },
      { bucketLabel: '16–32 us', rangeUs: '32', count: 29 },
      { bucketLabel: '32+ us', rangeUs: '64', count: 4 }
    ]
  },

  {
    id: 'preset-tcp-latency',
    name: 'TCP Handshake RTT & Retransmit Histogram (kprobe/kretprobe)',
    hookPoint: 'kprobe',
    category: 'Observability',
    description:
      'Hooks kprobe/tcp_v4_connect and kretprobe/tcp_v4_connect to correlate connection timestamps per Thread ID and build a lockless Per-CPU microsecond latency histogram.',
    mapName: 'tcp_rtt_histogram',
    mapType: 'BPF_MAP_TYPE_PERCPU_ARRAY',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u64);
} inflight_connect SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} tcp_rtt_histogram SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kp_tcp_connect, struct sock *sk) {
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&inflight_connect, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(krp_tcp_connect, int ret) {
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 *start_ns = bpf_map_lookup_elem(&inflight_connect, &tid);
    if (!start_ns)
        return 0;

    __u64 delta_us = (bpf_ktime_get_ns() - *start_ns) / 1000;
    bpf_map_delete_elem(&inflight_connect, &tid);

    __u32 bucket = 0;
    #pragma unroll
    for (int i = 0; i < 6; i++) {
        if (delta_us > (10ULL << i))
            bucket = i + 1;
    }

    __u64 *slot = bpf_map_lookup_elem(&tcp_rtt_histogram, &bucket);
    if (slot)
        *slot += 1;
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`,
    goCode: `package main

import (
	"log"

	"github.com/cilium/ebpf/link"
)

func main() {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	kp, _ := link.Kprobe("tcp_v4_connect", objs.KpTcpConnect, nil)
	defer kp.Close()

	krp, _ := link.Kretprobe("tcp_v4_connect", objs.KrpTcpConnect, nil)
	defer krp.Close()
}`,
    bpfBytecode: [
      '0: (85) call bpf_get_current_pid_tgid#14',
      '1: (63) *(u32 *)(r10 -4) = r0          ; store TID at fp-4',
      '2: (18) r1 = map[id:1]                 ; &inflight_connect',
      '3: (bf) r2 = r10                       ; r2 = fp-4',
      '4: (07) r2 += -4',
      '5: (85) call bpf_map_lookup_elem#1     ; lookup start_ns',
      '6: (15) if r0 == 0x0 goto pc+18        ; [SAFETY] null check on start_ns',
      '7: (79) r6 = *(u64 *)(r0 +0)           ; r6 = *start_ns',
      '8: (85) call bpf_ktime_get_ns#5        ; r0 = now_ns',
      '9: (1f) r0 -= r6                       ; delta_ns = now - start',
      '10: (37) r0 /= 1000                    ; delta_us',
      '11: (18) r1 = map[id:2]                ; &tcp_rtt_histogram',
      '12: (85) call bpf_map_lookup_elem#1    ; lookup bucket slot',
      '13: (15) if r0 == 0x0 goto pc+2        ; [SAFETY] null check on slot',
      '14: (79) r1 = *(u64 *)(r0 +0)',
      '15: (07) r1 += 1                       ; per-cpu lockless increment',
      '16: (7b) *(u64 *)(r0 +0) = r1',
      '17: (b7) r0 = 0',
      '18: (95) exit'
    ],
    safetyToggles: [
      {
        id: 'boundedLoopCheck',
        label: 'Enforce Bounded Loop Unrolling (#pragma unroll)',
        description: 'When disabled, replaces the bounded 6-step histogram loop on line 40 with an unbounded data-dependent while loop.',
        cLineNumber: 40,
        buggyLineReplacement: '    while (delta_us != 1) { delta_us >>= 1; bucket++; } // [BUG] Unbounded loop!',
        verifierErrorLog: [
          'back-edge from insn 14 to 11 detected',
          'Verifier state explosion: loop termination not provable when delta_us == 0',
          'BPF program is too large. Processed 1000001 insn (limit 1000000)',
          'verification failed: unbounded loop rejected by kernel verifier'
        ],
        failedRegisterState: {
          R0: 'scalar(umin=0,umax=18446744073709551615)',
          R6: 'scalar(infinite back-edge)',
          R10: 'fp0'
        }
      },
      {
        id: 'nullMapPointerCheck',
        label: 'Enforce Inflight Timestamp Null-Pointer Check',
        description: 'When disabled, omits if (!start_ns) return 0; on line 32 before computing (now - *start_ns).',
        cLineNumber: 32,
        buggyLineReplacement: '    // [BUG INJECTED] Omitted if (!start_ns) return 0;',
        verifierErrorLog: [
          '5: (85) call bpf_map_lookup_elem#1',
          '6: R0_w=map_value_or_null(id=1,off=0,ks=4,vs=8)',
          '7: (79) r6 = *(u64 *)(r0 +0)',
          "R0 invalid mem access 'map_value_or_null'",
          'verification failed: bpf(BPF_PROG_LOAD) returned -EACCES'
        ],
        failedRegisterState: {
          R0: 'map_value_or_null(id=1) [NULL DEREF]',
          R10: 'fp0'
        }
      }
    ],
    initialMapEntries: [
      {
        key: 'Bucket 0 (<10 us)',
        rawHexKey: '0x00000000',
        value: 'count: 842 (Local Loopback / Same-Node Pod)',
        numericValue: 842,
        cpuCore: 0,
        updatedAt: '0.2s ago'
      },
      {
        key: 'Bucket 1 (10–40 us)',
        rawHexKey: '0x00000001',
        value: 'count: 1,910 (Intra-AZ Mesh VPC)',
        numericValue: 1910,
        cpuCore: 1,
        updatedAt: '0.1s ago'
      },
      {
        key: 'Bucket 2 (40–160 us)',
        rawHexKey: '0x00000002',
        value: 'count: 615 (Cross-AZ Database)',
        numericValue: 615,
        cpuCore: 2,
        updatedAt: '0.4s ago'
      },
      {
        key: 'Bucket 3 (>1,000 us)',
        rawHexKey: '0x00000003',
        value: 'count: 38 (TCP SYN Retransmit / WAN)',
        numericValue: 38,
        cpuCore: 3,
        updatedAt: '0.8s ago'
      }
    ],
    initialLatencyHistogram: [
      { bucketLabel: '<10 us', rangeUs: '10', count: 842 },
      { bucketLabel: '10–40 us', rangeUs: '40', count: 1910 },
      { bucketLabel: '40–160 us', rangeUs: '160', count: 615 },
      { bucketLabel: '160–640 us', rangeUs: '640', count: 210 },
      { bucketLabel: '0.6–2.5 ms', rangeUs: '2500', count: 74 },
      { bucketLabel: '>2.5 ms', rangeUs: '10000', count: 38 }
    ]
  },

  {
    id: 'preset-uprobe-ssl',
    name: 'Userspace OpenSSL Plaintext HTTP/2 Sniffer (uprobe/SSL_write)',
    hookPoint: 'uprobe',
    category: 'Observability',
    description:
      'Attaches a userspace breakpoint trap (uprobe) to SSL_write inside libssl.so.3 to inspect plaintext HTTP headers and queries before TLS encryption.',
    mapName: 'tls_plaintext_ringbuf',
    mapType: 'BPF_MAP_TYPE_RINGBUF',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct tls_event {
    __u32 pid;
    __u32 len;
    char comm[16];
    char payload[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} tls_plaintext_ringbuf SEC(".maps");

SEC("uprobe/SSL_write")
int BPF_KPROBE(uprobe_ssl_write, void *ssl, const char *buf, int num) {
    if (num <= 0)
        return 0;

    struct tls_event *e = bpf_ringbuf_reserve(&tls_plaintext_ringbuf, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __u32 safe_len = (__u32)num & 0x7F; // Clamp to max 127 bytes
    e->len = safe_len;
    bpf_probe_read_user(&e->payload, safe_len, buf);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`,
    goCode: `package main

import (
	"log"

	"github.com/cilium/ebpf/link"
)

func main() {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	ex, err := link.OpenExecutable("/lib/x86_64-linux-gnu/libssl.so.3")
	if err != nil {
		log.Fatal(err)
	}
	up, err := ex.Uprobe("SSL_write", objs.UprobeSslWrite, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer up.Close()
}`,
    bpfBytecode: [
      '0: (79) r6 = *(u64 *)(r1 +96)          ; r6 = PT_REGS_PARM2 (const char *buf)',
      '1: (79) r7 = *(u64 *)(r1 +88)          ; r7 = PT_REGS_PARM3 (int num)',
      '2: (65) if r7 s<= 0x0 goto pc+14       ; ignore empty writes',
      '3: (18) r1 = map[id:1]                 ; &tls_plaintext_ringbuf',
      '4: (b7) r2 = 152                       ; sizeof(struct tls_event)',
      '5: (b7) r3 = 0',
      '6: (85) call bpf_ringbuf_reserve#131',
      '7: (15) if r0 == 0x0 goto pc+9         ; [SAFETY] null check on ringbuf ptr',
      '8: (bf) r8 = r0',
      '9: (57) r7 &= 127                      ; [SAFETY] clamp umax=127 (< 128B buf)',
      '10: (bf) r1 = r8',
      '11: (07) r1 += 24                      ; &e->payload',
      '12: (bf) r2 = r7                       ; clamped safe_len',
      '13: (bf) r3 = r6                       ; userspace buf ptr',
      '14: (85) call bpf_probe_read_user#112',
      '15: (bf) r1 = r8',
      '16: (b7) r2 = 0',
      '17: (85) call bpf_ringbuf_submit#132',
      '18: (b7) r0 = 0',
      '19: (95) exit'
    ],
    safetyToggles: [
      {
        id: 'packetBoundsCheck',
        label: 'Enforce Userspace Buffer Length Clamp (safe_len &= 0x7F)',
        description: 'When disabled, passes the unbounded userspace int num directly to bpf_probe_read_user() on line 30.',
        cLineNumber: 30,
        buggyLineReplacement: '    __u32 safe_len = (__u32)num; // [BUG] Unbounded length > 128B buffer!',
        verifierErrorLog: [
          '12: R2_w=scalar(umin=1,umax=2147483647)',
          '14: (85) call bpf_probe_read_user#112',
          'invalid access to memory, mem_size=128 off=24 size=2147483647',
          'R2 max value (2147483647) is outside of the destination buffer range (128 bytes)',
          'verification failed: bpf(BPF_PROG_LOAD) returned -EACCES'
        ],
        failedRegisterState: {
          R1: 'ringbuf_mem(off=24,size=128)',
          R2: 'scalar(umin=1,umax=2147483647) [OVERFLOWS 128B]',
          R3: 'scalar(userspace_ptr)',
          R10: 'fp0'
        }
      }
    ],
    initialMapEntries: [
      {
        key: 'TLS Record #881',
        rawHexKey: '0x00000371',
        value: 'PID=3091 COMM=curl PAYLOAD="GET /api/v2/payments HTTP/1.1"',
        numericValue: 3091,
        cpuCore: 1,
        updatedAt: '0.2s ago'
      },
      {
        key: 'TLS Record #882',
        rawHexKey: '0x00000372',
        value: 'PID=2104 COMM=python3 PAYLOAD="POST /v1/embeddings Content-Length: 512"',
        numericValue: 2104,
        cpuCore: 3,
        updatedAt: '0.5s ago'
      }
    ],
    initialLatencyHistogram: [
      { bucketLabel: '1–2 us', rangeUs: '2', count: 640 },
      { bucketLabel: '2–4 us', rangeUs: '4', count: 1410 },
      { bucketLabel: '4–8 us', rangeUs: '8', count: 520 },
      { bucketLabel: '8–16 us', rangeUs: '16', count: 95 },
      { bucketLabel: '16–32 us', rangeUs: '32', count: 18 },
      { bucketLabel: '32+ us', rangeUs: '64', count: 3 }
    ]
  },

  {
    id: 'preset-lsm-security',
    name: 'BPF LSM Mandatory File Guard (lsm/file_open)',
    hookPoint: 'lsm',
    category: 'Security',
    description:
      'Enforces TOCTOU-proof mandatory access control at the kernel VFS security_file_open hook, denying non-root reads of protected host inodes (/etc/shadow) inline with -EPERM.',
    mapName: 'protected_inodes_map',
    mapType: 'BPF_MAP_TYPE_HASH',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, __u32);
} protected_inodes_map SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(lsm_guard_open, struct file *file, int ret) {
    if (ret != 0)
        return ret;

    __u64 ino = BPF_CORE_READ(file, f_inode, i_ino);
    __u32 *policy = bpf_map_lookup_elem(&protected_inodes_map, &ino);
    if (!policy)
        return 0;

    __u32 uid = bpf_get_current_uid_gid();
    if (uid != 0) {
        bpf_printk("LSM DENY (-EPERM): blocked UID=%d from inode=%llu\\n", uid, ino);
        return -EPERM;
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`,
    goCode: `package main

import (
	"log"

	"github.com/cilium/ebpf/link"
)

func main() {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	lsm, err := link.AttachLSM(link.LSMOptions{
		Program: objs.LsmGuardOpen,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer lsm.Close()
}`,
    bpfBytecode: [
      '0: (61) r2 = *(u32 *)(r1 +8)           ; r2 = int ret parameter',
      '1: (55) if r2 != 0x0 goto pc+13        ; respect previous LSM denial',
      '2: (79) r1 = *(u64 *)(r1 +0)           ; r1 = struct file *file (BTF ptr)',
      '3: (79) r1 = *(u64 *)(r1 +32)          ; r1 = file->f_inode',
      '4: (79) r6 = *(u64 *)(r1 +64)          ; r6 = f_inode->i_ino',
      '5: (7b) *(u64 *)(r10 -8) = r6          ; store inode key at fp-8',
      '6: (18) r1 = map[id:1]                 ; &protected_inodes_map',
      '7: (bf) r2 = r10',
      '8: (07) r2 += -8',
      '9: (85) call bpf_map_lookup_elem#1',
      '10: (15) if r0 == 0x0 goto pc+4        ; [SAFETY] null check on policy',
      '11: (85) call bpf_get_current_uid_gid#15',
      '12: (15) if r0 == 0x0 goto pc+2        ; allow root (UID 0)',
      '13: (b7) r0 = -1                       ; return -EPERM (-1)',
      '14: (95) exit'
    ],
    safetyToggles: [
      {
        id: 'nullMapPointerCheck',
        label: 'Enforce Policy Map Null Check & Read-Only BTF Contract',
        description: 'When disabled, attempts to dereference the policy map pointer without a NULL check.',
        cLineNumber: 23,
        buggyLineReplacement: '    if (*policy == 1) // [BUG] Dereferenced map_value_or_null without if (!policy) check!',
        verifierErrorLog: [
          '9: (85) call bpf_map_lookup_elem#1',
          '10: R0_w=map_value_or_null(id=1,off=0,ks=8,vs=4)',
          "R0 invalid mem access 'map_value_or_null'",
          'verification failed: bpf(BPF_PROG_LOAD) returned -EACCES'
        ],
        failedRegisterState: {
          R0: 'map_value_or_null(id=1) [UNCHECKED]',
          R6: 'scalar(inode=131074)',
          R10: 'fp0'
        }
      }
    ],
    initialMapEntries: [
      {
        key: 'Inode 131074 (/etc/shadow)',
        rawHexKey: '0x00020002',
        value: 'POLICY=DENY_NON_ROOT | blocked_attempts: 14',
        numericValue: 14,
        cpuCore: 0,
        updatedAt: '0.1s ago'
      },
      {
        key: 'Inode 262199 (/var/run/secrets/k8s.io/token)',
        rawHexKey: '0x00040037',
        value: 'POLICY=DENY_NON_ROOT | blocked_attempts: 3',
        numericValue: 3,
        cpuCore: 2,
        updatedAt: '0.9s ago'
      }
    ],
    initialLatencyHistogram: [
      { bucketLabel: '<1 us', rangeUs: '1', count: 3120 },
      { bucketLabel: '1–2 us', rangeUs: '2', count: 890 },
      { bucketLabel: '2–4 us', rangeUs: '4', count: 140 },
      { bucketLabel: '4–8 us', rangeUs: '8', count: 22 },
      { bucketLabel: '8–16 us', rangeUs: '16', count: 4 },
      { bucketLabel: '16+ us', rangeUs: '32', count: 0 }
    ]
  }
];

export const PROJECT_TEMPLATES: ProjectTemplate[] = [
  {
    id: 'tpl-net-xdp-ddos-lb',
    index: '01',
    title: 'Cilium/Katran-Style XDP L4 Load Balancer & DDoS Scrubber',
    domain: 'Cloud-Native Networking',
    hookTypes: ['XDP'],
    difficulty: 'intermediate',
    minKernel: 'Linux 5.4+',
    summary:
      'High-speed L4 packet scrubber and LPM Trie CIDR firewall that drops volumetric SYN floods at the NIC driver and tracks per-CPU bandwidth metrics.',
    realWorldInspiration: 'Inspired by Cloudflare rakelimit, Meta Katran, and Cilium XDP NodePort acceleration.',
    problemSolved:
      'Protects Kubernetes ingress nodes from multi-million packet-per-second SYN and UDP amplification floods before kernel sk_buff allocation occurs.',
    architectureFlow: [
      {
        stage: '01. NIC RX Ring',
        component: 'XDP Driver Hook (SEC("xdp"))',
        description: 'Intercepts raw Ethernet frame in DMA memory prior to sk_buff allocation.'
      },
      {
        stage: '02. Subnet Match',
        component: 'BPF_MAP_TYPE_LPM_TRIE',
        description: 'Matches source IPv4 CIDR prefixes (e.g., /24 or /32 blocklists) in O(1) prefix steps.'
      },
      {
        stage: '03. Accounting',
        component: 'BPF_MAP_TYPE_PERCPU_ARRAY',
        description: 'Increments lockless per-CPU XDP_PASS and XDP_DROP packet/byte counters.'
      },
      {
        stage: '04. Control Plane',
        component: 'Go cilium/ebpf Daemon + Prometheus Exporter',
        description: 'Dynamically updates blocked CIDRs via HTTP API and exports Prometheus metrics.'
      }
    ],
    productionChecklist: [
      'Verify NIC driver supports Native XDP (i40e, ice, mlx5, ena, virtio_net) rather than Generic SKB mode.',
      'Pin BPF maps to /sys/fs/bpf/xdp_scrubber so firewall rules survive Go binary upgrades.',
      'Ensure multi-queue RSS channels are balanced across CPU cores via ethtool -L.'
    ],
    simulatorPresetId: 'preset-xdp-firewall',
    files: [
      {
        filename: 'bpf/xdp_scrubber.bpf.c',
        language: 'c',
        description: 'Kernel XDP program with LPM Trie CIDR matching and Per-CPU accounting',
        content: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct lpm_v4_key {
    __u32 prefixlen;
    __u32 addr;
};

struct datarec {
    __u64 passed_packets;
    __u64 dropped_packets;
    __u64 dropped_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_v4_key);
    __type(value, __u8);
} cidr_blocklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct datarec);
} xdp_metrics SEC(".maps");

SEC("xdp")
int xdp_l4_guard(struct xdp_md *ctx) {
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

    __u32 stats_key = 0;
    struct datarec *rec = bpf_map_lookup_elem(&xdp_metrics, &stats_key);
    if (!rec)
        return XDP_PASS;

    struct lpm_v4_key key = {
        .prefixlen = 32,
        .addr = ip->saddr,
    };

    __u8 *blocked = bpf_map_lookup_elem(&cidr_blocklist, &key);
    if (blocked) {
        rec->dropped_packets++;
        rec->dropped_bytes += (ctx->data_end - ctx->data);
        return XDP_DROP;
    }

    rec->passed_packets++;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`
      },
      {
        filename: 'main.go',
        language: 'go',
        description: 'Go cilium/ebpf control plane with dynamic CIDR blocklist insertion and Per-CPU polling',
        content: `package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf bpf/xdp_scrubber.bpf.c

func blockCIDR(objs *bpfObjects, cidrStr string) error {
	prefix, err := netip.ParsePrefix(cidrStr)
	if err != nil {
		return err
	}
	ip4 := prefix.Addr().As4()
	key := bpfLpmV4Key{
		Prefixlen: uint32(prefix.Bits()),
		Addr:      binary.LittleEndian.Uint32(ip4[:]),
	}
	val := uint8(1)
	return objs.CidrBlocklist.Put(&key, &val)
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	_ = blockCIDR(&objs, "198.51.100.0/24")

	iface, err := net.InterfaceByName("eth0")
	if err != nil {
		log.Fatal(err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpL4Guard,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			var key uint32 = 0
			var perCpu []bpfDatarec
			if err := objs.XdpMetrics.Lookup(&key, &perCpu); err == nil {
				var pass, drop uint64
				for _, c := range perCpu {
					pass += c.PassedPackets
					drop += c.DroppedPackets
				}
				fmt.Printf("[XDP TELEMETRY] Passed: %d pkts | Dropped: %d pkts\\n", pass, drop)
			}
		case <-sig:
			return
		}
	}
}`
      },
      {
        filename: 'Makefile',
        language: 'makefile',
        description: 'Build automation for vmlinux.h, bpf2go generation, and static Go compilation',
        content: `CLANG ?= clang
GO ?= go

.PHONY: all generate build clean

all: generate build

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

generate:
	$(GO) generate ./...

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags="-s -w" -o bin/xdp-scrubber .

clean:
	rm -rf bin/ bpf_*`
      }
    ]
  },

  {
    id: 'tpl-sec-falco-tetragon-auditor',
    index: '02',
    title: 'Tetragon/Falco-Style Container Process & File Integrity Auditor',
    domain: 'Runtime Security',
    hookTypes: ['tracepoint', 'lsm'],
    difficulty: 'advanced',
    minKernel: 'Linux 5.8+',
    summary:
      'Correlates process execution (sched_process_exec), container PID namespaces via CO-RE, and inline BPF LSM file protection (lsm/file_open) into a unified Go security agent.',
    realWorldInspiration: 'Inspired by Cilium Tetragon and CNCF Falco eBPF runtime security engines.',
    problemSolved:
      'Detects container breakouts, unexpected shell spawns inside production pods, and blocks unauthorized access to /etc/shadow or cloud metadata credentials inline.',
    architectureFlow: [
      {
        stage: '01. Exec Lineage',
        component: 'SEC("tracepoint/sched/sched_process_exec")',
        description: 'Uses BPF_CORE_READ to capture PID, PPID, UID, cgroup_id, and container PID namespace inode.'
      },
      {
        stage: '02. Inline VFS Guard',
        component: 'SEC("lsm/file_open")',
        description: 'Inspects resolved struct file -> f_inode -> i_ino and blocks unauthorized access with -EPERM.'
      },
      {
        stage: '03. Event Streaming',
        component: 'BPF_MAP_TYPE_RINGBUF',
        description: 'Streams zero-copy binary security events across all CPUs in strict chronological order.'
      },
      {
        stage: '04. Alert Engine',
        component: 'Go cilium/ebpf RingBuf Consumer',
        description: 'Enriches cgroup IDs with Kubernetes Pod labels and emits structured JSON security alerts.'
      }
    ],
    productionChecklist: [
      'Confirm CONFIG_BPF_LSM=y is enabled and lsm=bpf,... is present in /sys/kernel/security/lsm.',
      'Size the BPF Ring Buffer to at least 8MB–16MB on high-churn Kubernetes nodes.',
      'Deploy as a Kubernetes DaemonSet with CAP_BPF, CAP_PERFMON, and CAP_SYS_ADMIN.'
    ],
    simulatorPresetId: 'preset-lsm-security',
    files: [
      {
        filename: 'bpf/runtime_security.bpf.c',
        language: 'c',
        description: 'Dual-hook eBPF security program combining exec tracepoints with inline BPF LSM enforcement',
        content: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1
#define EVENT_EXEC 1
#define EVENT_LSM_BLOCK 2

struct security_event {
    __u32 event_type;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u64 cgroup_id;
    __u64 target_inode;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, __u64);
    __type(value, __u8);
} restricted_inodes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 23); // 8 MB Ring Buffer
} sec_events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int audit_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct security_event *e = bpf_ringbuf_reserve(&sec_events, sizeof(*e), 0);
    if (!e)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->event_type   = EVENT_EXEC;
    e->pid          = BPF_CORE_READ(task, tgid);
    e->ppid         = BPF_CORE_READ(task, real_parent, tgid);
    e->uid          = bpf_get_current_uid_gid();
    e->cgroup_id    = bpf_get_current_cgroup_id();
    e->target_inode = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(lsm_enforce_file, struct file *file, int ret) {
    if (ret != 0)
        return ret;

    __u64 ino = BPF_CORE_READ(file, f_inode, i_ino);
    __u8 *restricted = bpf_map_lookup_elem(&restricted_inodes, &ino);
    if (!restricted)
        return 0;

    __u32 uid = bpf_get_current_uid_gid();
    if (uid != 0) {
        struct security_event *e = bpf_ringbuf_reserve(&sec_events, sizeof(*e), 0);
        if (e) {
            struct task_struct *task = (struct task_struct *)bpf_get_current_task();
            e->event_type   = EVENT_LSM_BLOCK;
            e->pid          = BPF_CORE_READ(task, tgid);
            e->ppid         = BPF_CORE_READ(task, real_parent, tgid);
            e->uid          = uid;
            e->cgroup_id    = bpf_get_current_cgroup_id();
            e->target_inode = ino;
            bpf_get_current_comm(&e->comm, sizeof(e->comm));
            bpf_ringbuf_submit(e, 0);
        }
        return -EPERM;
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`
      },
      {
        filename: 'main.go',
        language: 'go',
        description: 'Go security daemon attaching both the tracepoint and LSM hook and streaming JSON alerts',
        content: `package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type security_event bpf bpf/runtime_security.bpf.c

func main() {
	_ = rlimit.RemoveMemlock()

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("load objects: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("sched", "sched_process_exec", objs.AuditProcessExec, nil)
	if err != nil {
		log.Fatalf("attach exec tracepoint: %v", err)
	}
	defer tp.Close()

	lsm, err := link.AttachLSM(link.LSMOptions{Program: objs.LsmEnforceFile})
	if err != nil {
		log.Printf("LSM attach warning (check CONFIG_BPF_LSM): %v", err)
	} else {
		defer lsm.Close()
	}

	rd, err := ringbuf.NewReader(objs.SecEvents)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	var raw bpfSecurityEvent
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		_ = binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &raw)
		alert := map[string]any{
			"verdict":   map[uint32]string{1: "OBSERVED_EXEC", 2: "BLOCKED_EPERM"}[raw.EventType],
			"pid":       raw.Pid,
			"ppid":      raw.Ppid,
			"uid":       raw.Uid,
			"cgroup_id": raw.CgroupId,
			"comm":      unix.ByteSliceToString(raw.Comm[:]),
		}
		out, _ := json.Marshal(alert)
		fmt.Fprintln(os.Stdout, string(out))
	}
}`
      }
    ]
  },

  {
    id: 'tpl-perf-tcp-rtt-retransmit',
    index: '03',
    title: 'Production TCP Handshake RTT & Retransmit Profiler',
    domain: 'Performance Engineering',
    hookTypes: ['kprobe', 'kretprobe', 'tracepoint'],
    difficulty: 'intermediate',
    minKernel: 'Linux 5.4+',
    summary:
      'Measures microsecond TCP connection setup latency via kprobe/kretprobe and correlates packet retransmissions via tcp/tcp_retransmit_skb tracepoints.',
    realWorldInspiration: 'Inspired by Cloudflare ebpf_exporter and BCC tcplife / tcpretrans.',
    problemSolved:
      'Pinpoints whether microservice tail latency spikes are caused by slow application handlers or underlying VPC network packet loss and TCP SYN retransmissions.',
    architectureFlow: [
      {
        stage: '01. SYN Entry',
        component: 'SEC("kprobe/tcp_v4_connect")',
        description: 'Records nanosecond timestamp keyed by Thread ID when outbound TCP connect begins.'
      },
      {
        stage: '02. Return Histogram',
        component: 'SEC("kretprobe/tcp_v4_connect")',
        description: 'Computes duration in microseconds and increments Per-CPU log2 latency buckets.'
      },
      {
        stage: '03. Retransmit Hook',
        component: 'SEC("tracepoint/tcp/tcp_retransmit_skb")',
        description: 'Captures exact source/destination IP:Port and TCP state whenever a segment is retransmitted.'
      },
      {
        stage: '04. Histogram Reader',
        component: 'Go cilium/ebpf Collector',
        description: 'Renders live terminal histograms and exports Prometheus histogram buckets.'
      }
    ],
    productionChecklist: [
      'Use BPF_MAP_TYPE_LRU_HASH for inflight connection timestamps so half-open connections never exhaust map capacity.',
      'Prefer tracepoint/tcp/tcp_retransmit_skb over kprobe/tcp_retransmit_skb for long-term kernel ABI stability.'
    ],
    simulatorPresetId: 'preset-tcp-latency',
    files: [
      {
        filename: 'bpf/tcp_profiler.bpf.c',
        language: 'c',
        description: 'Kernel TCP latency histogram and retransmission tracepoint collector',
        content: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u64);
} connect_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} rtt_buckets SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_tcp_entry, struct sock *sk) {
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&connect_start, &tid, &now, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(trace_tcp_return, int ret) {
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 *ts = bpf_map_lookup_elem(&connect_start, &tid);
    if (!ts)
        return 0;

    __u64 delta_us = (bpf_ktime_get_ns() - *ts) / 1000;
    bpf_map_delete_elem(&connect_start, &tid);

    __u32 b = 0;
    #pragma unroll
    for (int i = 0; i < 14; i++) {
        if (delta_us > (1ULL << i))
            b = i + 1;
    }

    __u64 *cnt = bpf_map_lookup_elem(&rtt_buckets, &b);
    if (cnt)
        *cnt += 1;
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`
      },
      {
        filename: 'main.go',
        language: 'go',
        description: 'Go histogram aggregator printing live ASCII distribution bars across all CPU cores',
        content: `package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf bpf/tcp_profiler.bpf.c

func main() {
	_ = rlimit.RemoveMemlock()

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	kp, _ := link.Kprobe("tcp_v4_connect", objs.TraceTcpEntry, nil)
	defer kp.Close()
	krp, _ := link.Kretprobe("tcp_v4_connect", objs.TraceTcpReturn, nil)
	defer krp.Close()

	for range time.Tick(3 * time.Second) {
		fmt.Println("=== TCP Connect Latency Histogram (us) ===")
		for b := uint32(0); b < 10; b++ {
			var perCpu []uint64
			if err := objs.RttBuckets.Lookup(&b, &perCpu); err == nil {
				var sum uint64
				for _, v := range perCpu {
					sum += v
				}
				fmt.Printf("Bucket [%4d .. %4d us]: %d\\n", 1<<b, 1<<(b+1), sum)
			}
		}
	}
}`
      }
    ]
  },

  {
    id: 'tpl-net-cilium-socket-lb',
    index: '04',
    title: 'Socket-Level Kubernetes Service Load Balancer (cgroup/connect4)',
    domain: 'Cloud-Native Networking',
    hookTypes: ['TC'],
    difficulty: 'advanced',
    minKernel: 'Linux 5.4+',
    summary:
      'Rewrites virtual ClusterIP destination addresses directly at the connect() socket layer (cgroup/connect4), eliminating kube-proxy iptables NAT rules entirely.',
    realWorldInspiration: 'Inspired by Cilium kube-proxy replacement (Socket-LB).',
    problemSolved:
      'In Kubernetes clusters with 10,000+ Services, kube-proxy iptables rules cause O(N) packet traversal latency. Hooking cgroup/connect4 translates ClusterIP -> PodBackendIP once at socket connect time in O(1) hash lookup!',
    architectureFlow: [
      {
        stage: '01. App Socket Call',
        component: 'connect(fd, 10.96.0.10:80)',
        description: 'Container calls connect() targeting a virtual Kubernetes ClusterIP.'
      },
      {
        stage: '02. Cgroup Hook',
        component: 'SEC("cgroup/connect4")',
        description: 'Intercepts struct bpf_sock_addr before a single SYN packet is even created!'
      },
      {
        stage: '03. VIP Lookup',
        component: 'BPF_MAP_TYPE_HASH (service_backends)',
        description: 'Looks up ClusterIP:Port in O(1) and rewrites ctx->user_ip4 and ctx->user_port in-place.'
      },
      {
        stage: '04. Direct TCP',
        component: 'Linux TCP Stack',
        description: 'Kernel establishes TCP connection directly to the Pod IP with zero per-packet NAT overhead.'
      }
    ],
    productionChecklist: [
      'Attach to the root cgroup v2 hierarchy (/sys/fs/cgroup) so all child container cgroups inherit the hook.',
      'Ensure both user_ip4 and user_port are stored in network byte order (__be32 / __be16).'
    ],
    simulatorPresetId: 'preset-xdp-firewall',
    files: [
      {
        filename: 'bpf/sock_lb.bpf.c',
        language: 'c',
        description: 'Cgroup v2 connect4 socket load balancer rewriting virtual Service IPs in O(1)',
        content: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct vip_key {
    __u32 vip;
    __u16 port;
    __u16 pad;
};

struct backend_val {
    __u32 backend_ip;
    __u16 backend_port;
    __u16 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct vip_key);
    __type(value, struct backend_val);
} kube_services SEC(".maps");

SEC("cgroup/connect4")
int sock4_connect_lb(struct bpf_sock_addr *ctx) {
    struct vip_key key = {
        .vip  = ctx->user_ip4,
        .port = (__u16)ctx->user_port,
        .pad  = 0,
    };

    struct backend_val *dst = bpf_map_lookup_elem(&kube_services, &key);
    if (!dst)
        return 1; // Not a virtual service IP; proceed normally

    // Rewrite socket destination in-place before TCP SYN is sent!
    ctx->user_ip4  = dst->backend_ip;
    ctx->user_port = dst->backend_port;
    return 1;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`
      },
      {
        filename: 'main.go',
        language: 'go',
        description: 'Go cgroup v2 attachment and Kubernetes Service map synchronizer',
        content: `package main

import (
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func attachCgroupSocketLB(objs *bpfObjects) (link.Link, error) {
	cgLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.Sock4ConnectLb,
	})
	if err != nil {
		return nil, err
	}
	log.Println("Attached kube-proxy replacement to /sys/fs/cgroup (cgroup/connect4)")
	return cgLink, nil
}`
      }
    ]
  },

  {
    id: 'tpl-sec-tls-api-auditor',
    index: '05',
    title: 'Zero-Code Plaintext TLS & HTTP API Security Inspector (uprobe/SSL)',
    domain: 'Runtime Security',
    hookTypes: ['uprobe'],
    difficulty: 'advanced',
    minKernel: 'Linux 5.8+',
    summary:
      'Captures cleartext HTTP/1.1 and HTTP/2 payloads across OpenSSL applications using uprobe/SSL_write and uprobe/SSL_read without MITM proxy certificates.',
    realWorldInspiration: 'Inspired by Pixie (CNCF), Grafana Beyla, and Subtrace zero-code TLS tracers.',
    problemSolved:
      'Provides instant L7 API observability and sensitive PII/token leak detection across encrypted HTTPS egress traffic without modifying app code or breaking mTLS.',
    architectureFlow: [
      {
        stage: '01. App TLS Call',
        component: 'SSL_write(ssl, plaintext, len)',
        description: 'Application passes cleartext HTTP request to OpenSSL shared library.'
      },
      {
        stage: '02. Uprobe Trap',
        component: 'SEC("uprobe/SSL_write")',
        description: 'Kernel traps into eBPF program and clamps payload length to satisfy the Verifier.'
      },
      {
        stage: '03. RingBuf Copy',
        component: 'bpf_probe_read_user() -> RingBuffer',
        description: 'Copies cleartext header bytes into shared RingBuffer memory.'
      },
      {
        stage: '04. HTTP Parser',
        component: 'Go L7 Protocol Inspector',
        description: 'Parses HTTP methods, paths, and Authorization headers in Go userspace.'
      }
    ],
    productionChecklist: [
      'Discover container libssl.so paths dynamically via /proc/<pid>/maps to support both OpenSSL 1.1 and OpenSSL 3.x.',
      'Clamp captured payload size (e.g. 256 bytes) so only HTTP headers are inspected and bulk file uploads are skipped.'
    ],
    simulatorPresetId: 'preset-uprobe-ssl',
    files: [
      {
        filename: 'bpf/tls_inspector.bpf.c',
        language: 'c',
        description: 'Userspace probe capturing cleartext buffers from OpenSSL SSL_write',
        content: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct tls_msg {
    __u32 pid;
    __u32 len;
    char comm[16];
    char data[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} tls_events SEC(".maps");

SEC("uprobe/SSL_write")
int BPF_KPROBE(inspect_ssl_write, void *ssl, const char *buf, int num) {
    if (num <= 0)
        return 0;

    struct tls_msg *m = bpf_ringbuf_reserve(&tls_events, sizeof(*m), 0);
    if (!m)
        return 0;

    m->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&m->comm, sizeof(m->comm));

    __u32 capped = (__u32)num & 0xFF;
    m->len = capped;
    bpf_probe_read_user(&m->data, capped, buf);

    bpf_ringbuf_submit(m, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`
      },
      {
        filename: 'main.go',
        language: 'go',
        description: 'Go ELF symbol resolver and HTTP cleartext header parser',
        content: `package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

func attachAndInspectTLS(objs *bpfObjects) error {
	ex, err := link.OpenExecutable("/lib/x86_64-linux-gnu/libssl.so.3")
	if err != nil {
		return err
	}
	up, err := ex.Uprobe("SSL_write", objs.InspectSslWrite, nil)
	if err != nil {
		return err
	}
	defer up.Close()

	rd, _ := ringbuf.NewReader(objs.TlsEvents)
	defer rd.Close()

	var msg bpfTlsMsg
	for {
		rec, err := rd.Read()
		if err != nil {
			return err
		}
		_ = binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &msg)
		payload := string(msg.Data[:msg.Len])
		firstLine := strings.Split(payload, "\\r\\n")[0]
		fmt.Printf("[TLS CLEARTEXT] PID=%d HTTP=%q\\n", msg.Pid, firstLine)
	}
}`
      }
    ]
  },

  {
    id: 'tpl-perf-offcpu-memleak',
    index: '06',
    title: 'Continuous Off-CPU Scheduler & Heap Memory Leak Profiler',
    domain: 'Performance Engineering',
    hookTypes: ['sched', 'uprobe'],
    difficulty: 'advanced',
    minKernel: 'Linux 5.5+',
    summary:
      'Combines scheduler context-switch tracing (sched_switch) with libc malloc/free uprobes to diagnose lock contention stalls and unreleased heap allocations.',
    realWorldInspiration: 'Inspired by Parca / Polar Signals Continuous Profiler and BCC offcputime + memleak.',
    problemSolved:
      'Diagnoses the two hardest production performance bugs: services that freeze with 0% CPU usage (lock/futex contention) and services whose RSS memory slowly climbs until OOMKilled.',
    architectureFlow: [
      {
        stage: '01. Context Switch',
        component: 'SEC("tracepoint/sched/sched_switch")',
        description: 'Measures exact microseconds each thread spends sleeping off-CPU waiting on locks or I/O.'
      },
      {
        stage: '02. Heap Alloc',
        component: 'SEC("uprobe/malloc") + SEC("uretprobe/malloc")',
        description: 'Records allocation size and returned heap address in an active_allocs LRU map.'
      },
      {
        stage: '03. Heap Free',
        component: 'SEC("uprobe/free")',
        description: 'Deletes freed pointers so only long-lived unfreed allocations remain in the map.'
      },
      {
        stage: '04. Hotspot Report',
        component: 'Go Profiler CLI',
        description: 'Ranks threads by Off-CPU block time and lists unfreed heap pointers older than 60s.'
      }
    ],
    productionChecklist: [
      'Scope malloc/free uprobes to a specific target PID via link.UprobeOptions{PID: targetPid} to minimize system-wide trap overhead.',
      'Ignore kernel idle thread (pid == 0) in sched_switch.'
    ],
    simulatorPresetId: 'preset-tcp-latency',
    files: [
      {
        filename: 'bpf/offcpu_mem.bpf.c',
        language: 'c',
        description: 'Combined sched_switch Off-CPU tracker and malloc/free leak detector',
        content: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u64);
} thread_sleep_ts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u64);
} thread_offcpu_us SEC(".maps");

SEC("tracepoint/sched/sched_switch")
int profile_sched_switch(struct trace_event_raw_sched_switch *ctx) {
    __u64 now = bpf_ktime_get_ns();
    __u32 prev = ctx->prev_pid;
    __u32 next = ctx->next_pid;

    if (prev != 0)
        bpf_map_update_elem(&thread_sleep_ts, &prev, &now, BPF_ANY);

    if (next != 0) {
        __u64 *start = bpf_map_lookup_elem(&thread_sleep_ts, &next);
        if (start) {
            __u64 delta_us = (now - *start) / 1000;
            bpf_map_delete_elem(&thread_sleep_ts, &next);

            __u64 *tot = bpf_map_lookup_elem(&thread_offcpu_us, &next);
            if (tot) {
                __sync_fetch_and_add(tot, delta_us);
            } else {
                bpf_map_update_elem(&thread_offcpu_us, &next, &delta_us, BPF_ANY);
            }
        }
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`
      },
      {
        filename: 'main.go',
        language: 'go',
        description: 'Go continuous profiler reporting top blocked threads by Off-CPU duration',
        content: `package main

import (
	"fmt"
	"time"

	"github.com/cilium/ebpf/link"
)

func runOffCpuProfiler(objs *bpfObjects) error {
	tp, err := link.Tracepoint("sched", "sched_switch", objs.ProfileSchedSwitch, nil)
	if err != nil {
		return err
	}
	defer tp.Close()

	for range time.Tick(3 * time.Second) {
		var tid uint32
		var totalUs uint64
		iter := objs.ThreadOffcpuUs.Iterate()
		fmt.Println("--- Top Off-CPU Blocked Threads ---")
		for iter.Next(&tid, &totalUs) {
			fmt.Printf("Thread TID=%-6d | Blocked Off-CPU: %d ms\\n", tid, totalUs/1000)
		}
	}
	return nil
}`
      }
    ]
  }
];
