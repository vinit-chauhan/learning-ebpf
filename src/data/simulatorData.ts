import { SimulatorPreset, KernelSimulatedEvent } from '../types/ebpf';

export const SIMULATOR_PRESETS: SimulatorPreset[] = [
  {
    id: 'preset-xdp-firewall',
    name: 'XDP Line-Rate DDoS Scrubber & Packet Counter',
    hookPoint: 'XDP',
    category: 'Networking',
    description:
      'Parses Ethernet, IPv4, and TCP headers directly in the NIC driver RX ring buffer, drops SYN flood packets from blocked IPs using an O(1) BPF Hash Map, and increments lockless Per-CPU traffic counters.',
    mapName: 'blocked_ipv4_map',
    mapType: 'BPF_MAP_TYPE_HASH',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);   // Source IPv4 Address
    __type(value, __u64); // Dropped Packet Count
} blocked_ipv4_map SEC(".maps");

SEC("xdp")
int xdp_ddos_scrubber(struct xdp_md *ctx) {
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

    __u32 src_ip = ip->saddr;
    __u64 *drop_cnt = bpf_map_lookup_elem(&blocked_ipv4_map, &src_ip);
    if (!drop_cnt)
        return XDP_PASS;

    __sync_fetch_and_add(drop_cnt, 1);
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`,
    goCode: `package main

import (
	"encoding/binary"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf xdp_ddos.bpf.c

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("verifier rejected program: %v", err)
	}
	defer objs.Close()

	// Seed blocklist with known volumetric SYN flood botnet IP
	blockedIP := binary.LittleEndian.Uint32(net.ParseIP("198.51.100.77").To4())
	initialCount := uint64(0)
	_ = objs.BlockedIpv4Map.Put(&blockedIP, &initialCount)

	iface, _ := net.InterfaceByName("eth0")
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpDdosScrubber,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	for range time.Tick(time.Second) {
		var ipKey uint32
		var drops uint64
		iter := objs.BlockedIpv4Map.Iterate()
		for iter.Next(&ipKey, &drops) {
			log.Printf("Blocked IP %x -> %d packets dropped at NIC ring", ipKey, drops)
		}
	}
}`,
    bpfBytecode: [
      '0: (61) r2 = *(u32 *)(r1 +0)        ; R1=ctx(xdp_md) -> R2=pkt(off=0,r=0)',
      '1: (61) r3 = *(u32 *)(r1 +4)        ; R3=pkt_end()',
      '2: (bf) r4 = r2                     ; R4=pkt(off=0)',
      '3: (07) r4 += 14                    ; R4=pkt(off=14)',
      '4: (2d) if r4 > r3 goto pc+17       ; Prove Ethernet header (14B) <= data_end',
      '5: (69) r1 = *(u16 *)(r2 +12)       ; Read eth->h_proto (r=14 proven)',
      '6: (55) if r1 != 0x8 goto pc+15     ; Check ETH_P_IP (0x0800)',
      '7: (bf) r1 = r4                     ; R1=pkt(off=14)',
      '8: (07) r1 += 20                    ; R1=pkt(off=34)',
      '9: (2d) if r1 > r3 goto pc+12       ; Prove IPv4 header (20B) <= data_end',
      '10: (61) r1 = *(u32 *)(r2 +26)      ; Read ip->saddr at offset 26 (within r=34)',
      '11: (63) *(u32 *)(r10 -4) = r1      ; Store src_ip key on stack fp-4',
      '12: (18) r1 = 0xffff888104a2c000    ; R1=map_ptr(blocked_ipv4_map)',
      '14: (bf) r2 = r10                   ; R2=fp0',
      '15: (07) r2 += -4                   ; R2=fp-4',
      '16: (85) call bpf_map_lookup_elem#1 ; Returns R0=map_value_or_null',
      '17: (15) if r0 == 0x0 goto pc+4     ; Prove R0 != NULL -> R0=map_value',
      '18: (b7) r1 = 1                     ; R1=1',
      '19: (db) lock *(u64 *)(r0 +0) += r1 ; Atomic increment drop_cnt',
      '20: (b7) r0 = 1                     ; Return XDP_DROP (1)',
      '21: (95) exit',
      '22: (b7) r0 = 2                     ; Return XDP_PASS (2)',
      '23: (95) exit'
    ],
    safetyToggles: [
      {
        id: 'packetBoundsCheck',
        label: 'IPv4 Packet Bounds Check (ip + 1 <= data_end)',
        description:
          'When disabled, removes line 28 (if ((void *)(ip + 1) > data_end)) so ip->saddr reads offset 26 when only 14 bytes are verified.',
        cLineNumber: 28,
        buggyLineReplacement: '    // [BUG INJECTED] Omitted if ((void *)(ip + 1) > data_end) bounds check!',
        verifierErrorLog: [
          'Validating xdp_ddos_scrubber() insn 0..23:',
          '0: R1=ctx(off=0,imm=0) R10=fp0',
          '4: (2d) if r4 > r3 goto pc+17  ; R2=pkt(id=0,off=0,r=14) R3=pkt_end()',
          '10: (61) r1 = *(u32 *)(r2 +26)',
          'invalid access to packet, off=26 size=4, R2(id=0,off=26,r=14)',
          'R2 offset is outside of the packet',
          'verification time 42 usec | stack depth 4 | processed 11 insns — REJECTED (EACCES)'
        ],
        failedRegisterState: {
          R0: 'NOT_INIT',
          R1: 'scalar(imm=0x8)',
          R2: 'pkt(off=0, r=14)  <-- ERROR: reading off=26..30 when safe range r=14!',
          R3: 'pkt_end()',
          R4: 'pkt(off=14, r=14)',
          R10: 'fp0'
        }
      },
      {
        id: 'nullMapPointerCheck',
        label: 'Map Lookup NULL Pointer Check (if (!drop_cnt))',
        description:
          'When disabled, dereferences drop_cnt returned by bpf_map_lookup_elem() without checking if it is NULL.',
        cLineNumber: 33,
        buggyLineReplacement: '    // [BUG INJECTED] Omitted if (!drop_cnt) NULL check before dereference!',
        verifierErrorLog: [
          'Validating xdp_ddos_scrubber() insn 0..23:',
          '16: (85) call bpf_map_lookup_elem#1',
          '17: R0_w=map_value_or_null(id=1,off=0,ks=4,vs=8,imm=0)',
          '18: (b7) r1 = 1',
          '19: (db) lock *(u64 *)(r0 +0) += r1',
          "R0 invalid mem access 'map_value_or_null'",
          'Hint: check if (drop_cnt == NULL) before dereferencing R0.',
          'verification time 58 usec | stack depth 4 | processed 19 insns — REJECTED (EACCES)'
        ],
        failedRegisterState: {
          R0: 'map_value_or_null(id=1,ks=4,vs=8)  <-- ERROR: nullable pointer dereference!',
          R1: 'scalar(imm=1)',
          R2: 'NOT_INIT (clobbered by helper call)',
          R3: 'NOT_INIT (clobbered by helper call)',
          R10: 'fp0'
        }
      },
      {
        id: 'stackSizeLimitCheck',
        label: '512-Byte Kernel Stack Frame Limit',
        description:
          'When disabled, allocates char huge_scratch_buf[1024] on the local C stack, exceeding the strict 512-byte eBPF stack limit.',
        cLineNumber: 17,
        buggyLineReplacement: '    char huge_stack_buffer[1024]; // [BUG INJECTED] Exceeds 512-byte eBPF stack limit!',
        verifierErrorLog: [
          'Validating xdp_ddos_scrubber():',
          'combined stack size of 1 calls is 1056. Max is 512',
          'Error: eBPF stack frame is strictly capped at 512 bytes per program invocation.',
          'Hint: Use a 1-entry BPF_MAP_TYPE_PERCPU_ARRAY or bpf_ringbuf_reserve() for large buffers.',
          'REJECTED (E2BIG / EACCES)'
        ],
        failedRegisterState: {
          R0: 'NOT_INIT',
          R1: 'ctx(off=0)',
          R10: 'fp0 (requested fp-1056 exceeds max stack depth fp-512!)'
        }
      }
    ],
    initialMapEntries: [
      {
        key: '198.51.100.77 (SYN Botnet A)',
        rawHexKey: '0x6333644d',
        value: '14,820 pkts dropped',
        numericValue: 14820,
        cpuCore: 0,
        updatedAt: '0.2s ago'
      },
      {
        key: '203.0.113.249 (UDP Amp Node)',
        rawHexKey: '0xcb0071f9',
        value: '8,412 pkts dropped',
        numericValue: 8412,
        cpuCore: 2,
        updatedAt: '0.4s ago'
      },
      {
        key: '192.0.2.108 (Scanner Probe)',
        rawHexKey: '0xc000026c',
        value: '1,904 pkts dropped',
        numericValue: 1904,
        cpuCore: 5,
        updatedAt: '1.1s ago'
      }
    ],
    initialLatencyHistogram: [
      { bucketLabel: '8-15 ns', rangeUs: '0.01 µs', count: 4820 },
      { bucketLabel: '16-31 ns', rangeUs: '0.02 µs', count: 19450 },
      { bucketLabel: '32-63 ns', rangeUs: '0.05 µs', count: 6120 },
      { bucketLabel: '64-127 ns', rangeUs: '0.10 µs', count: 940 },
      { bucketLabel: '128-255 ns', rangeUs: '0.20 µs', count: 180 },
      { bucketLabel: '256+ ns', rangeUs: '0.40 µs', count: 24 }
    ]
  },
  {
    id: 'preset-syscall-execve',
    name: 'Syscall Process Execution Auditor (RingBuffer + Tracepoint)',
    hookPoint: 'tracepoint',
    category: 'Security',
    description:
      'Attaches to tracepoint/syscalls/sys_enter_execve, captures PID, UID, parent lineage, and command arguments, and streams zero-copy records to Go via BPF_MAP_TYPE_RINGBUF.',
    mapName: 'exec_ringbuf_events',
    mapType: 'BPF_MAP_TYPE_RINGBUF',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct exec_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char comm[16];
    char filename[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} exec_ringbuf_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve_ringbuf(struct trace_event_raw_sys_enter *ctx) {
    struct exec_event *e = bpf_ringbuf_reserve(&exec_ringbuf_events, sizeof(*e), 0);
    if (!e)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->uid  = bpf_get_current_uid_gid();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    const char *fname_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), fname_ptr);

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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type exec_event bpf execve_ringbuf.bpf.c

func main() {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecveRingbuf, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.ExecRingbufEvents)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	var evt bpfExecEvent
	for {
		rec, err := rd.Read()
		if err != nil {
			break
		}
		_ = binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &evt)
		log.Printf("[EXEC] PID=%d (PPID=%d, UID=%d) %s -> %s",
			evt.Pid, evt.Ppid, evt.Uid, string(evt.Comm[:]), string(evt.Filename[:]))
	}
}`,
    bpfBytecode: [
      '0: (bf) r6 = r1                       ; Save ctx in callee-saved R6',
      '1: (18) r1 = 0xffff88810940a000       ; R1=map_ptr(exec_ringbuf_events)',
      '3: (b7) r2 = 92                       ; R2=sizeof(struct exec_event)',
      '4: (b7) r3 = 0                        ; flags=0',
      '5: (85) call bpf_ringbuf_reserve#131  ; Returns R0=ringbuf_mem_or_null(ref_id=1)',
      '6: (15) if r0 == 0x0 goto pc+18       ; Check NULL before writing fields',
      '7: (bf) r7 = r0                       ; Save reserved ringbuf ptr in R7(ref_id=1)',
      '8: (85) call bpf_get_current_pid_tgid#14',
      '9: (77) r0 >>= 32',
      '10: (63) *(u32 *)(r7 +0) = r0         ; e->pid = pid',
      '11: (79) r3 = *(u64 *)(r6 +16)        ; ctx->args[0] (userspace filename ptr)',
      '12: (bf) r1 = r7',
      '13: (07) r1 += 28                     ; &e->filename',
      '14: (b7) r2 = 64                      ; sizeof(e->filename)',
      '15: (85) call bpf_probe_read_user_str#114',
      '16: (bf) r1 = r7',
      '17: (b7) r2 = 0',
      '18: (85) call bpf_ringbuf_submit#132  ; Releases ref_id=1',
      '19: (b7) r0 = 0',
      '20: (95) exit'
    ],
    safetyToggles: [
      {
        id: 'nullMapPointerCheck',
        label: 'RingBuf Reservation NULL Check (if (!e) return 0)',
        description:
          'When disabled, writes to e->pid without checking if bpf_ringbuf_reserve() returned NULL when the ring buffer is full.',
        cLineNumber: 22,
        buggyLineReplacement: '    // [BUG INJECTED] Omitted if (!e) check after bpf_ringbuf_reserve()!',
        verifierErrorLog: [
          'Validating trace_execve_ringbuf():',
          '5: (85) call bpf_ringbuf_reserve#131',
          '6: R0_w=rdonly_mem_or_null(id=1,ref_obj_id=1,off=0,imm=0)',
          '10: (63) *(u32 *)(r7 +0) = r0',
          "R7 invalid mem access 'mem_or_null'",
          'processed 11 insns — REJECTED (EACCES)'
        ],
        failedRegisterState: {
          R0: 'scalar(pid)',
          R6: 'ctx(trace_event_raw_sys_enter)',
          R7: 'mem_or_null(ref_obj_id=1)  <-- ERROR: writing to potentially NULL ringbuf pointer!',
          R10: 'fp0'
        }
      },
      {
        id: 'boundedLoopCheck',
        label: 'Release RingBuf Reference on Every Exit Path',
        description:
          'When disabled, simulates returning early before calling bpf_ringbuf_submit(e, 0), leaking the ring buffer reference lock.',
        cLineNumber: 34,
        buggyLineReplacement: '    // [BUG INJECTED] Omitted bpf_ringbuf_submit(e, 0) — leaks reference id=1!',
        verifierErrorLog: [
          'Validating trace_execve_ringbuf():',
          '5: (85) call bpf_ringbuf_reserve#131 ; acquires reference ref_obj_id=1',
          '19: (b7) r0 = 0',
          '20: (95) exit',
          'Unreleased reference id=1 alloc_insn=5',
          'Hint: Every path after bpf_ringbuf_reserve() must call bpf_ringbuf_submit() or bpf_ringbuf_discard().',
          'REJECTED (EINVAL / EACCES)'
        ],
        failedRegisterState: {
          R0: 'scalar(imm=0)',
          R7: 'ringbuf_mem(ref_obj_id=1)  <-- ERROR: reference id=1 still held at program exit!',
          R10: 'fp0'
        }
      }
    ],
    initialMapEntries: [
      {
        key: 'PID 4812 (kubelet)',
        rawHexKey: '0x000012cc',
        value: '/usr/bin/runc --systemd-cgroup',
        numericValue: 48,
        cpuCore: 1,
        updatedAt: '0.1s ago'
      },
      {
        key: 'PID 9104 (nginx-worker)',
        rawHexKey: '0x00002390',
        value: '/usr/sbin/nginx -g daemon off;',
        numericValue: 39,
        cpuCore: 3,
        updatedAt: '0.5s ago'
      },
      {
        key: 'PID 12840 (bash)',
        rawHexKey: '0x00003228',
        value: '/usr/bin/curl -s https://internal.svc/healthz',
        numericValue: 64,
        cpuCore: 2,
        updatedAt: '0.8s ago'
      }
    ],
    initialLatencyHistogram: [
      { bucketLabel: '16-31 ns', rangeUs: '0.02 µs', count: 1420 },
      { bucketLabel: '32-63 ns', rangeUs: '0.05 µs', count: 5890 },
      { bucketLabel: '64-127 ns', rangeUs: '0.10 µs', count: 8410 },
      { bucketLabel: '128-255 ns', rangeUs: '0.20 µs', count: 2150 },
      { bucketLabel: '256-511 ns', rangeUs: '0.40 µs', count: 410 },
      { bucketLabel: '512+ ns', rangeUs: '0.80 µs', count: 55 }
    ]
  },
  {
    id: 'preset-tcp-latency',
    name: 'TCP Handshake RTT & Retransmit Profiler (Kprobe / Kretprobe)',
    hookPoint: 'kprobe',
    category: 'Observability',
    description:
      'Hooks tcp_v4_connect entry and exit via kprobe/kretprobe, correlates timestamps per Thread ID in a BPF Hash Map, and updates a Per-CPU Log2 microsecond latency histogram.',
    mapName: 'tcp_rtt_histogram',
    mapType: 'BPF_MAP_TYPE_PERCPU_ARRAY',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} connect_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u64);
} tcp_rtt_histogram SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kp_tcp_v4_connect, struct sock *sk) {
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 ts  = bpf_ktime_get_ns();
    bpf_map_update_elem(&connect_start, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(kret_tcp_v4_connect, int ret) {
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 *start_ns = bpf_map_lookup_elem(&connect_start, &tid);
    if (!start_ns)
        return 0;

    __u64 delta_us = (bpf_ktime_get_ns() - *start_ns) / 1000;
    bpf_map_delete_elem(&connect_start, &tid);

    __u32 bucket = 0;
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        if (delta_us <= 1) break;
        delta_us >>= 1;
        bucket++;
    }
    __u64 *cnt = bpf_map_lookup_elem(&tcp_rtt_histogram, &bucket);
    if (cnt)
        *cnt += 1;
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";`,
    goCode: `package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf tcp_rtt.bpf.c

func main() {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	kp, _ := link.Kprobe("tcp_v4_connect", objs.KpTcpV4Connect, nil)
	defer kp.Close()

	kretp, _ := link.Kretprobe("tcp_v4_connect", objs.KretTcpV4Connect, nil)
	defer kretp.Close()

	for range time.Tick(2 * time.Second) {
		fmt.Println("--- TCP Connect Latency Histogram (us) ---")
		for b := uint32(0); b < 12; b++ {
			var perCPU []uint64
			_ = objs.TcpRttHistogram.Lookup(&b, &perCPU)
			var total uint64
			for _, v := range perCPU {
				total += v
			}
			fmt.Printf("Bucket [%4d - %4d us]: %d connects\\n", 1<<b, (1<<(b+1))-1, total)
		}
	}
}`,
    bpfBytecode: [
      '0: (85) call bpf_get_current_pid_tgid#14',
      '1: (63) *(u32 *)(r10 -4) = r0          ; tid stored at fp-4',
      '2: (18) r1 = 0xffff888102b44000        ; R1=map_ptr(connect_start)',
      '4: (bf) r2 = r10',
      '5: (07) r2 += -4                       ; R2=fp-4 (&tid)',
      '6: (85) call bpf_map_lookup_elem#1     ; R0=map_value_or_null',
      '7: (15) if r0 == 0x0 goto pc+18        ; Verify start_ns != NULL',
      '8: (79) r6 = *(u64 *)(r0 +0)           ; R6=*start_ns',
      '9: (85) call bpf_ktime_get_ns#5        ; R0=now_ns',
      '10: (1f) r0 -= r6                      ; delta_ns = now - start_ns',
      '11: (37) r0 /= 1000                    ; delta_us = delta_ns / 1000',
      '12: (85) call bpf_map_delete_elem#3    ; Delete tid entry from connect_start',
      '13: (85) call bpf_map_lookup_elem#1    ; Lookup tcp_rtt_histogram bucket',
      '14: (15) if r0 == 0x0 goto pc+2',
      '15: (79) r1 = *(u64 *)(r0 +0)',
      '16: (07) r1 += 1                       ; Lockless Per-CPU increment',
      '17: (7b) *(u64 *)(r0 +0) = r1',
      '18: (b7) r0 = 0',
      '19: (95) exit'
    ],
    safetyToggles: [
      {
        id: 'nullMapPointerCheck',
        label: 'Entry Timestamp NULL Check (if (!start_ns))',
        description:
          'When disabled, dereferences *start_ns in the kretprobe without checking if the kprobe recorded an entry for this TID.',
        cLineNumber: 33,
        buggyLineReplacement: '    // [BUG INJECTED] Omitted if (!start_ns) check in kretprobe!',
        verifierErrorLog: [
          'Validating kret_tcp_v4_connect():',
          '6: (85) call bpf_map_lookup_elem#1',
          '7: R0_w=map_value_or_null(id=1,off=0,ks=4,vs=8)',
          '8: (79) r6 = *(u64 *)(r0 +0)',
          "R0 invalid mem access 'map_value_or_null'",
          'REJECTED (EACCES)'
        ],
        failedRegisterState: {
          R0: 'map_value_or_null(id=1,ks=4,vs=8)  <-- ERROR: start_ns might be NULL!',
          R1: 'NOT_INIT',
          R10: 'fp0'
        }
      },
      {
        id: 'boundedLoopCheck',
        label: 'Bounded Log2 Loop Ceiling (for i < 16)',
        description:
          'When disabled, replaces the bounded for-loop with an unbounded while(delta_us != 0) loop lacking a verifiable upper bound.',
        cLineNumber: 41,
        buggyLineReplacement: '    while (delta_us != 0) { bucket++; /* [BUG] Unbounded loop! */ }',
        verifierErrorLog: [
          'Validating kret_tcp_v4_connect():',
          'back-edge from insn 16 to 14',
          'BPF program is too large. Processed 1000001 insn',
          'Error: Loop termination cannot be proven by the static verifier.',
          'REJECTED (E2BIG)'
        ],
        failedRegisterState: {
          R0: 'scalar(umin=1,umax=18446744073709551615)',
          R6: 'scalar(unbounded loop counter)',
          R10: 'fp0'
        }
      }
    ],
    initialMapEntries: [
      {
        key: 'Bucket 3 [8 - 15 µs] (Local Pod)',
        rawHexKey: '0x00000003',
        value: '4,290 connects',
        numericValue: 4290,
        cpuCore: 0,
        updatedAt: '0.2s ago'
      },
      {
        key: 'Bucket 7 [128 - 255 µs] (Intra-AZ)',
        rawHexKey: '0x00000007',
        value: '11,840 connects',
        numericValue: 11840,
        cpuCore: 1,
        updatedAt: '0.3s ago'
      },
      {
        key: 'Bucket 11 [2048 - 4095 µs] (Cross-AZ)',
        rawHexKey: '0x0000000b',
        value: '1,620 connects',
        numericValue: 1620,
        cpuCore: 3,
        updatedAt: '0.9s ago'
      }
    ],
    initialLatencyHistogram: [
      { bucketLabel: '8-31 µs', rangeUs: '16 µs', count: 4290 },
      { bucketLabel: '32-127 µs', rangeUs: '64 µs', count: 8920 },
      { bucketLabel: '128-511 µs', rangeUs: '250 µs', count: 11840 },
      { bucketLabel: '0.5-2 ms', rangeUs: '1,000 µs', count: 3410 },
      { bucketLabel: '2-8 ms', rangeUs: '4,000 µs', count: 1620 },
      { bucketLabel: '8+ ms (Retrans)', rangeUs: '15,000 µs', count: 310 }
    ]
  },
  {
    id: 'preset-uprobe-ssl',
    name: 'Zero-Instrumentation OpenSSL Plaintext Sniffer (Uprobe)',
    hookPoint: 'uprobe',
    category: 'Observability',
    description:
      'Attaches a userspace probe to SSL_write in libssl.so.3 to capture plaintext HTTP/1.1 and HTTP/2 payloads prior to TLS encryption.',
    mapName: 'tls_plaintext_rb',
    mapType: 'BPF_MAP_TYPE_RINGBUF',
    cCode: `//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_TLS_BUF 256

struct tls_msg_event {
    __u32 pid;
    __u32 len;
    char comm[16];
    char payload[MAX_TLS_BUF];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} tls_plaintext_rb SEC(".maps");

SEC("uprobe/SSL_write")
int BPF_KPROBE(uprobe_ssl_write, void *ssl, const char *buf, int num) {
    if (num <= 0)
        return 0;

    struct tls_msg_event *e = bpf_ringbuf_reserve(&tls_plaintext_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->len = (__u32)num;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __u32 safe_len = (__u32)num & (MAX_TLS_BUF - 1);
    bpf_probe_read_user(&e->payload, safe_len, buf);

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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type tls_msg_event bpf uprobe_ssl.bpf.c

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
	up, err := ex.Uprobe("SSL_write", objs.UprobeSslWrite, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer up.Close()

	rd, _ := ringbuf.NewReader(objs.TlsPlaintextRb)
	defer rd.Close()

	var evt bpfTlsMsgEvent
	for {
		rec, err := rd.Read()
		if err != nil {
			break
		}
		_ = binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &evt)
		log.Printf("[TLS Plaintext] PID=%d %s: %s", evt.Pid, string(evt.Comm[:]), string(evt.Payload[:]))
	}
}`,
    bpfBytecode: [
      '0: (79) r6 = *(u64 *)(r1 +104)       ; R6 = arg2 (const char *buf)',
      '1: (79) r7 = *(u64 *)(r1 +96)        ; R7 = arg3 (int num)',
      '2: (65) if r7 s<= 0x0 goto pc+16     ; Ignore empty/error writes',
      '3: (18) r1 = 0xffff888107c10000      ; R1 = map_ptr(tls_plaintext_rb)',
      '5: (b7) r2 = 280                     ; sizeof(struct tls_msg_event)',
      '6: (b7) r3 = 0',
      '7: (85) call bpf_ringbuf_reserve#131',
      '8: (15) if r0 == 0x0 goto pc+10',
      '9: (bf) r8 = r0                      ; R8 = reserved event ptr',
      '10: (bf) r2 = r7',
      '11: (54) w2 &= 255                   ; Bitmask safe_len <= 255 for Verifier',
      '12: (bf) r1 = r8',
      '13: (07) r1 += 24                    ; &e->payload',
      '14: (bf) r3 = r6                     ; userspace buf ptr',
      '15: (85) call bpf_probe_read_user#112',
      '16: (bf) r1 = r8',
      '17: (b7) r2 = 0',
      '18: (85) call bpf_ringbuf_submit#132',
      '19: (b7) r0 = 0',
      '20: (95) exit'
    ],
    safetyToggles: [
      {
        id: 'packetBoundsCheck',
        label: 'Bitmask Dynamic Read Size (safe_len &= 255)',
        description:
          'When disabled, passes the unmasked userspace integer num directly to bpf_probe_read_user(&e->payload, num, buf), risking a buffer overflow past 256 bytes.',
        cLineNumber: 33,
        buggyLineReplacement: '    __u32 safe_len = (__u32)num; // [BUG] Unmasked dynamic length can exceed 256B!',
        verifierErrorLog: [
          'Validating uprobe_ssl_write():',
          '14: (85) call bpf_probe_read_user#112',
          'R1=mem(id=1,ref_obj_id=1,off=24,imm=0) R2_w=scalar(umin=1,umax=2147483647)',
          'invalid access to memory, mem_size=280 off=24 size=2147483647',
          'R1 min value is outside of the allowed memory range',
          'Hint: Bitmask variable size with (MAX_TLS_BUF - 1) so umax <= 255.',
          'REJECTED (EACCES)'
        ],
        failedRegisterState: {
          R1: 'ringbuf_mem(off=24, max_size=256)',
          R2: 'scalar(umin=1, umax=2147483647)  <-- ERROR: umax exceeds destination buffer 256B!',
          R3: 'scalar(userspace_buf_ptr)',
          R10: 'fp0'
        }
      }
    ],
    initialMapEntries: [
      {
        key: 'PID 6021 (curl)',
        rawHexKey: '0x00001785',
        value: 'GET /api/v2/payments HTTP/1.1 | Host: api.stripe.internal',
        numericValue: 128,
        cpuCore: 2,
        updatedAt: '0.3s ago'
      },
      {
        key: 'PID 3190 (envoy)',
        rawHexKey: '0x00000c76',
        value: 'POST /grpc.auth.v1.TokenService/Verify | x-request-id: 94f1a',
        numericValue: 214,
        cpuCore: 4,
        updatedAt: '0.6s ago'
      }
    ],
    initialLatencyHistogram: [
      { bucketLabel: '128-255 ns', rangeUs: '0.20 µs', count: 920 },
      { bucketLabel: '256-511 ns', rangeUs: '0.40 µs', count: 4310 },
      { bucketLabel: '0.5-1.0 µs', rangeUs: '0.80 µs', count: 6180 },
      { bucketLabel: '1.0-2.0 µs', rangeUs: '1.50 µs', count: 1490 },
      { bucketLabel: '2.0+ µs', rangeUs: '2.50 µs', count: 210 }
    ]
  },
  {
    id: 'preset-lsm-security',
    name: 'BPF LSM Container Escape & Shadow File Guard',
    hookPoint: 'lsm',
    category: 'Security',
    description:
      'Attaches to lsm/file_open to inspect resolved kernel struct file and inode pointers, synchronously blocking unauthorized reads of /etc/shadow or host secrets with -EPERM.',
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
    __uint(max_entries, 1024);
    __type(key, __u64);   // Protected Kernel Inode
    __type(value, __u32); // Required UID (0 = root)
} protected_inodes_map SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(lsm_guard_file_open, struct file *file, int ret) {
    if (ret != 0)
        return ret;

    __u64 ino = BPF_CORE_READ(file, f_inode, i_ino);
    __u32 *req_uid = bpf_map_lookup_elem(&protected_inodes_map, &ino);
    if (!req_uid)
        return 0;

    __u32 cur_uid = bpf_get_current_uid_gid();
    if (cur_uid != *req_uid) {
        return -EPERM; // Synchronously block unauthorized file open!
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";`,
    goCode: `package main

import (
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf lsm_guard.bpf.c

func main() {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	shadowIno := uint64(131074)
	allowedUID := uint32(0)
	_ = objs.ProtectedInodesMap.Put(&shadowIno, &allowedUID)

	lsm, err := link.AttachLSM(link.LSMOptions{
		Program: objs.LsmGuardFileOpen,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer lsm.Close()

	log.Println("BPF LSM mandatory access guard enforcing policy!")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
}`,
    bpfBytecode: [
      '0: (79) r2 = *(u64 *)(r1 +8)          ; R2 = int ret (chained LSM result)',
      '1: (55) if r2 != 0x0 goto pc+15       ; Respect previous LSM denial',
      '2: (79) r1 = *(u64 *)(r1 +0)          ; R1 = btf_ptr(struct file *)',
      '3: (79) r1 = *(u64 *)(r1 +32)         ; R1 = file->f_inode',
      '4: (79) r1 = *(u64 *)(r1 +64)         ; R1 = f_inode->i_ino',
      '5: (7b) *(u64 *)(r10 -8) = r1         ; Store ino at fp-8',
      '6: (18) r1 = 0xffff888105118000       ; R1 = map_ptr(protected_inodes_map)',
      '8: (bf) r2 = r10',
      '9: (07) r2 += -8',
      '10: (85) call bpf_map_lookup_elem#1',
      '11: (15) if r0 == 0x0 goto pc+5       ; Not protected -> allow (0)',
      '12: (61) r6 = *(u32 *)(r0 +0)         ; R6 = *req_uid',
      '13: (85) call bpf_get_current_uid_gid#15',
      '14: (1d) if r0 == r6 goto pc+2',
      '15: (b7) r0 = -1                      ; Return -EPERM (-1) to block inline!',
      '16: (95) exit',
      '17: (b7) r0 = 0                       ; Return 0 (ALLOW)',
      '18: (95) exit'
    ],
    safetyToggles: [
      {
        id: 'nullMapPointerCheck',
        label: 'Policy Map Lookup NULL Check (if (!req_uid))',
        description:
          'When disabled, reads *req_uid without checking if the inode was found in protected_inodes_map.',
        cLineNumber: 23,
        buggyLineReplacement: '    // [BUG INJECTED] Omitted if (!req_uid) NULL check!',
        verifierErrorLog: [
          'Validating lsm_guard_file_open():',
          '10: (85) call bpf_map_lookup_elem#1',
          '11: R0_w=map_value_or_null(id=1,off=0,ks=8,vs=4)',
          '12: (61) r6 = *(u32 *)(r0 +0)',
          "R0 invalid mem access 'map_value_or_null'",
          'REJECTED (EACCES)'
        ],
        failedRegisterState: {
          R0: 'map_value_or_null(id=1,ks=8,vs=4)  <-- ERROR: dereferencing nullable map pointer!',
          R10: 'fp0'
        }
      }
    ],
    initialMapEntries: [
      {
        key: 'Inode 131074 (/etc/shadow)',
        rawHexKey: '0x00020002',
        value: 'UID 0 Only (Blocked 37 attempts)',
        numericValue: 37,
        cpuCore: 1,
        updatedAt: '0.4s ago'
      },
      {
        key: 'Inode 262910 (/var/run/docker.sock)',
        rawHexKey: '0x000403be',
        value: 'UID 0 Only (Blocked 12 attempts)',
        numericValue: 12,
        cpuCore: 0,
        updatedAt: '1.2s ago'
      }
    ],
    initialLatencyHistogram: [
      { bucketLabel: '16-31 ns', rangeUs: '0.02 µs', count: 6410 },
      { bucketLabel: '32-63 ns', rangeUs: '0.05 µs', count: 14200 },
      { bucketLabel: '64-127 ns', rangeUs: '0.10 µs', count: 3120 },
      { bucketLabel: '128+ ns', rangeUs: '0.20 µs', count: 190 }
    ]
  }
];

const SAMPLE_COMMS = ['nginx', 'envoy', 'kubelet', 'coredns', 'postgres', 'redis-server', 'curl', 'python3'];
const SAMPLE_IPS = ['10.244.1.18', '10.244.2.94', '198.51.100.77', '172.16.0.42', '203.0.113.249'];

export function generateSyntheticKernelEvent(
  preset: SimulatorPreset,
  anomalyMode?: 'syn_flood' | 'shadow_read' | 'tcp_retrans' | 'tls_burst'
): KernelSimulatedEvent {
  const now = new Date();
  const ts = `${now.toTimeString().split(' ')[0]}.${String(now.getMilliseconds()).padStart(3, '0')}`;
  const cpu = Math.floor(Math.random() * 8);
  const pid = 2000 + Math.floor(Math.random() * 14000);
  const comm = SAMPLE_COMMS[Math.floor(Math.random() * SAMPLE_COMMS.length)];

  if (anomalyMode === 'syn_flood' || preset.hookPoint === 'XDP') {
    const isMalicious = anomalyMode === 'syn_flood' ? true : Math.random() < 0.35;
    const srcIp = isMalicious ? '198.51.100.77' : SAMPLE_IPS[Math.floor(Math.random() * SAMPLE_IPS.length)];
    return {
      id: `evt-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      timestamp: ts,
      cpu,
      pid,
      comm: 'ksoftirqd/' + cpu,
      hookPoint: 'XDP',
      eventType: isMalicious ? 'TCP_SYN_FLOOD_PKT' : 'IPV4_TCP_FRAME',
      verdict: isMalicious ? 'XDP_DROP' : 'XDP_PASS',
      latencyNs: isMalicious ? 18 + Math.floor(Math.random() * 12) : 26 + Math.floor(Math.random() * 18),
      srcIp,
      dstPort: 443,
      details: isMalicious
        ? `src=${srcIp}:54912 -> dst=10.0.0.1:443 [SYN] matched blocked_ipv4_map -> XDP_DROP`
        : `src=${srcIp}:41820 -> dst=10.0.0.1:443 [ACK] verified clean -> XDP_PASS`
    };
  }

  if (anomalyMode === 'shadow_read' || preset.hookPoint === 'lsm') {
    const isUnauthorized = anomalyMode === 'shadow_read' ? true : Math.random() < 0.3;
    return {
      id: `evt-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      timestamp: ts,
      cpu,
      pid,
      comm: isUnauthorized ? 'sh' : comm,
      hookPoint: 'lsm',
      eventType: 'lsm/file_open',
      verdict: isUnauthorized ? 'BLOCK' : 'ALLOW',
      latencyNs: 34 + Math.floor(Math.random() * 25),
      details: isUnauthorized
        ? `UID=1001 attempted open("/etc/shadow", ino=131074) -> BPF LSM returned -EPERM (-1)`
        : `UID=0 opened("/etc/hosts", ino=94120) -> BPF LSM returned 0 (ALLOW)`
    };
  }

  if (anomalyMode === 'tcp_retrans' || preset.hookPoint === 'kprobe') {
    const isSlow = anomalyMode === 'tcp_retrans' ? true : Math.random() < 0.25;
    const rttUs = isSlow ? 4200 + Math.floor(Math.random() * 8000) : 45 + Math.floor(Math.random() * 180);
    return {
      id: `evt-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      timestamp: ts,
      cpu,
      pid,
      comm,
      hookPoint: 'kprobe',
      eventType: 'tcp_v4_connect',
      verdict: 'TRACED',
      latencyNs: rttUs * 1000,
      dstPort: 5432,
      details: `TID=${pid} -> 10.244.3.19:5432 handshake completed in ${rttUs} µs (bucket=${Math.min(15, Math.floor(Math.log2(rttUs)))})`
    };
  }

  if (anomalyMode === 'tls_burst' || preset.hookPoint === 'uprobe') {
    return {
      id: `evt-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      timestamp: ts,
      cpu,
      pid,
      comm: 'envoy',
      hookPoint: 'uprobe',
      eventType: 'uprobe/SSL_write',
      verdict: 'TRACED',
      latencyNs: 410 + Math.floor(Math.random() * 190),
      details: `Plaintext TLS write (164B): "POST /v1/checkout HTTP/2.0 | content-type: application/grpc"`
    };
  }

  return {
    id: `evt-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    timestamp: ts,
    cpu,
    pid,
    comm,
    hookPoint: 'tracepoint',
    eventType: 'sys_enter_execve',
    verdict: 'TRACED',
    latencyNs: 42 + Math.floor(Math.random() * 30),
    details: `PPID=${pid - 12} spawned /usr/bin/${comm} (RingBuf record 92B committed)`
  };
}
