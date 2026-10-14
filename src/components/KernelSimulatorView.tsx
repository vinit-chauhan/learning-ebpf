import React, { useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Cpu,
  Database,
  FastForward,
  Pause,
  Play,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Zap
} from 'lucide-react';
import { SIMULATOR_PRESETS } from '../data/simulatorAndTemplatesData';
import {
  BpfMapEntry,
  KernelSimulatedEvent,
  SimulatorPreset
} from '../types/ebpf';
import { SyntaxHighlighter } from './SyntaxHighlighter';

interface KernelSimulatorViewProps {
  selectedPresetId: string;
  onSelectPreset: (presetId: string) => void;
}

export const KernelSimulatorView: React.FC<KernelSimulatorViewProps> = ({
  selectedPresetId,
  onSelectPreset
}) => {
  const activePreset: SimulatorPreset =
    SIMULATOR_PRESETS.find((p) => p.id === selectedPresetId) || SIMULATOR_PRESETS[0];

  const [isRunning, setIsRunning] = useState<boolean>(true);
  const [eventRatePerSec, setEventRatePerSec] = useState<number>(4);
  const [codeTab, setCodeTab] = useState<'c' | 'go' | 'bytecode'>('c');
  const [telemetryTab, setTelemetryTab] = useState<'events' | 'map' | 'histogram'>('events');

  // Track which safety checks are disabled (injected bugs)
  const [disabledSafetyIds, setDisabledSafetyIds] = useState<string[]>([]);

  // Live simulated state
  const [events, setEvents] = useState<KernelSimulatedEvent[]>([]);
  const [mapEntries, setMapEntries] = useState<BpfMapEntry[]>(activePreset.initialMapEntries);
  const [histogram, setHistogram] = useState(activePreset.initialLatencyHistogram);
  const [totalPassed, setTotalPassed] = useState<number>(1420);
  const [totalDropped, setTotalDropped] = useState<number>(318);
  const [lastPulseVerdict, setLastPulseVerdict] = useState<'PASS' | 'DROP'>('PASS');

  // Reset state when preset changes
  useEffect(() => {
    setDisabledSafetyIds([]);
    setMapEntries(activePreset.initialMapEntries);
    setHistogram(activePreset.initialLatencyHistogram);
    setEvents([
      {
        id: 'ev-init-1',
        timestamp: new Date().toISOString().slice(11, 23),
        cpu: 0,
        pid: 4102,
        comm: 'envoy-proxy',
        hookPoint: activePreset.hookPoint,
        eventType: `${activePreset.hookPoint} Hook Attached`,
        verdict: activePreset.hookPoint === 'XDP' ? 'XDP_PASS' : 'ALLOW',
        latencyNs: 38,
        details: `Verified and attached ${activePreset.name} via Go cilium/ebpf`
      }
    ]);
  }, [activePreset.id]);

  // Determine if verifier fails due to any disabled safety check
  const activeFailureToggle = activePreset.safetyToggles.find((t) =>
    disabledSafetyIds.includes(t.id)
  );
  const isVerifierPassing = !activeFailureToggle;

  // Build C code reflecting any injected bug
  const displayedCCode = React.useMemo(() => {
    if (!activeFailureToggle) return activePreset.cCode;
    const lines = activePreset.cCode.split('\n');
    const targetIdx = activeFailureToggle.cLineNumber - 1;
    if (targetIdx >= 0 && targetIdx < lines.length) {
      lines[targetIdx] = activeFailureToggle.buggyLineReplacement;
    }
    return lines.join('\n');
  }, [activePreset, activeFailureToggle]);

  // Function to synthesize a realistic event
  const triggerSyntheticEvent = (
    scenario: 'normal_http' | 'syn_flood' | 'container_exec' | 'shadow_read' | 'tcp_retransmit'
  ) => {
    if (!isVerifierPassing) return;

    const nowStr = new Date().toISOString().slice(11, 23);
    const cpu = Math.floor(Math.random() * 4);
    let newEv: KernelSimulatedEvent;

    if (scenario === 'syn_flood') {
      newEv = {
        id: `ev-${Date.now()}-${Math.random()}`,
        timestamp: nowStr,
        cpu,
        pid: 0,
        comm: 'ksoftirqd/rx',
        hookPoint: activePreset.hookPoint,
        eventType: 'SYN_FLOOD_PKT',
        verdict: 'XDP_DROP',
        latencyNs: 19,
        details: 'SRC=198.51.100.77:54192 -> DST=10.244.1.42:443 [Blocked by XDP LPM/Hash]'
      };
      setTotalDropped((d) => d + 1);
      setLastPulseVerdict('DROP');
      setMapEntries((prev) =>
        prev.map((entry, idx) =>
          idx === 2
            ? {
                ...entry,
                numericValue: entry.numericValue + 1,
                value: `passed: 0 | dropped: ${(entry.numericValue + 1).toLocaleString()}`,
                updatedAt: 'just now'
              }
            : entry
        )
      );
    } else if (scenario === 'shadow_read') {
      newEv = {
        id: `ev-${Date.now()}-${Math.random()}`,
        timestamp: nowStr,
        cpu,
        pid: 8912,
        comm: 'cat',
        hookPoint: activePreset.hookPoint,
        eventType: 'VFS_FILE_OPEN',
        verdict: 'BLOCK',
        latencyNs: 44,
        details: 'UID=1000 attempted open("/etc/shadow", O_RDONLY) -> Denied -EPERM by BPF LSM'
      };
      setTotalDropped((d) => d + 1);
      setLastPulseVerdict('DROP');
      setMapEntries((prev) =>
        prev.map((entry, idx) =>
          idx === 0
            ? {
                ...entry,
                numericValue: entry.numericValue + 1,
                value: `POLICY=DENY_NON_ROOT | blocked_attempts: ${entry.numericValue + 1}`,
                updatedAt: 'just now'
              }
            : entry
        )
      );
    } else if (scenario === 'container_exec') {
      newEv = {
        id: `ev-${Date.now()}-${Math.random()}`,
        timestamp: nowStr,
        cpu,
        pid: 5100 + Math.floor(Math.random() * 800),
        comm: 'kubectl-exec',
        hookPoint: activePreset.hookPoint,
        eventType: 'SYS_ENTER_EXECVE',
        verdict: 'TRACED',
        latencyNs: 52,
        details: 'PPID=4100 UID=0 executed "/bin/sh -c ps aux" inside pid_ns=4026532410'
      };
      setTotalPassed((p) => p + 1);
      setLastPulseVerdict('PASS');
    } else if (scenario === 'tcp_retransmit') {
      newEv = {
        id: `ev-${Date.now()}-${Math.random()}`,
        timestamp: nowStr,
        cpu,
        pid: 3319,
        comm: 'postgres-client',
        hookPoint: activePreset.hookPoint,
        eventType: 'TCP_CONNECT_RTT',
        verdict: 'TRACED',
        latencyNs: 1840000,
        details: 'tcp_v4_connect -> 10.96.4.12:5432 RTT=1,840 us (Bucket >1,000 us)'
      };
      setTotalPassed((p) => p + 1);
      setLastPulseVerdict('PASS');
      setHistogram((prev) =>
        prev.map((b, i) => (i === prev.length - 1 ? { ...b, count: b.count + 1 } : b))
      );
    } else {
      newEv = {
        id: `ev-${Date.now()}-${Math.random()}`,
        timestamp: nowStr,
        cpu,
        pid: 2048 + Math.floor(Math.random() * 500),
        comm: 'go-api-srv',
        hookPoint: activePreset.hookPoint,
        eventType: activePreset.hookPoint === 'XDP' ? 'ETH_IPv4_TCP' : 'KERNEL_EVENT',
        verdict: activePreset.hookPoint === 'XDP' ? 'XDP_PASS' : 'ALLOW',
        latencyNs: 24 + Math.floor(Math.random() * 35),
        details:
          activePreset.hookPoint === 'uprobe'
            ? 'SSL_write(ssl, "GET /v1/healthz HTTP/1.1", 24) captured pre-encryption'
            : 'SRC=10.244.1.42:49122 -> DST=10.244.2.19:8080 [Verified & Passed]'
      };
      setTotalPassed((p) => p + 1);
      setLastPulseVerdict('PASS');
      setMapEntries((prev) =>
        prev.map((entry, idx) =>
          idx === 0
            ? {
                ...entry,
                numericValue: entry.numericValue + 1,
                value: entry.value.replace(/\d+(?:,\d+)*/, (entry.numericValue + 1).toLocaleString()),
                updatedAt: 'just now'
              }
            : entry
        )
      );
      setHistogram((prev) =>
        prev.map((b, i) => (i === 1 ? { ...b, count: b.count + 1 } : b))
      );
    }

    setEvents((prev) => [newEv, ...prev.slice(0, 39)]);
  };

  // Continuous simulation timer
  useEffect(() => {
    if (!isRunning || !isVerifierPassing) return;
    const intervalMs = Math.max(180, Math.floor(1000 / eventRatePerSec));
    const timer = setInterval(() => {
      const r = Math.random();
      if (activePreset.hookPoint === 'XDP') {
        triggerSyntheticEvent(r < 0.28 ? 'syn_flood' : 'normal_http');
      } else if (activePreset.hookPoint === 'lsm') {
        triggerSyntheticEvent(r < 0.35 ? 'shadow_read' : 'container_exec');
      } else if (activePreset.hookPoint === 'kprobe') {
        triggerSyntheticEvent(r < 0.25 ? 'tcp_retransmit' : 'normal_http');
      } else {
        triggerSyntheticEvent(r < 0.4 ? 'container_exec' : 'normal_http');
      }
    }, intervalMs);

    return () => clearInterval(timer);
  }, [isRunning, isVerifierPassing, eventRatePerSec, activePreset.id]);

  const toggleSafetyFlag = (id: string) => {
    setDisabledSafetyIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  const maxHistCount = Math.max(1, ...histogram.map((h) => h.count));

  return (
    <div className="space-y-6">
      {/* Top Preset Selector Strip */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 max-w-full">
          {SIMULATOR_PRESETS.map((preset) => (
            <button
              key={preset.id}
              onClick={() => onSelectPreset(preset.id)}
              className={`min-h-[40px] px-3.5 py-2 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                preset.id === activePreset.id
                  ? 'border-sky-500 bg-sky-500/12 text-slate-900 dark:text-white font-semibold'
                  : 'border-slate-200 dark:border-slate-800 bg-white dark:bg-[#111827] text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
              }`}
            >
              [{preset.hookPoint}] {preset.name}
            </button>
          ))}
        </div>

        {/* Simulation Playback Controls */}
        <div className="flex flex-wrap items-center gap-2 sm:gap-3">
          <div className="flex items-center gap-2 text-xs font-mono tabular-nums text-slate-600 dark:text-slate-300 bg-slate-100 dark:bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800 min-h-[40px]">
            <label htmlFor="rate-slider" className="whitespace-nowrap">
              Rate: <strong>{eventRatePerSec} ev/s</strong>
            </label>
            <input
              id="rate-slider"
              type="range"
              min={1}
              max={15}
              value={eventRatePerSec}
              onChange={(e) => setEventRatePerSec(Number(e.target.value))}
              className="w-16 sm:w-20 accent-sky-500 cursor-pointer"
            />
          </div>

          <button
            onClick={() => setIsRunning(!isRunning)}
            className="min-h-[40px] px-3.5 py-1.5 text-xs font-medium rounded-lg bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 hover:opacity-90 transition-opacity flex items-center gap-1.5 whitespace-nowrap cursor-pointer shadow-2xs"
          >
            {isRunning ? (
              <>
                <Pause className="w-3.5 h-3.5" />
                <span>Pause</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5" />
                <span>Resume</span>
              </>
            )}
          </button>

          <button
            onClick={() => triggerSyntheticEvent('normal_http')}
            disabled={!isVerifierPassing}
            className="min-h-[40px] px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-40 flex items-center gap-1 whitespace-nowrap cursor-pointer shadow-2xs"
          >
            <FastForward className="w-3.5 h-3.5" />
            <span>Step</span>
          </button>

          <button
            onClick={() => {
              setEvents([]);
              setTotalPassed(0);
              setTotalDropped(0);
            }}
            className="min-h-[40px] px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white flex items-center gap-1 whitespace-nowrap cursor-pointer"
            title="Reset telemetry counters"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset</span>
          </button>
        </div>
      </div>

      {/* TWO-ZONE SANDBOX LAYOUT: Left Stage (8 cols ~ 67%) + Right Telemetry & Control Deck (4 cols ~ 33%) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* LEFT ZONE: Interactive Visual Kernel Pipeline + Code & Safety Studio (8 cols) */}
        <div className="lg:col-span-8 space-y-6">
          {/* 1. Live Animated Kernel Event Pipeline Canvas */}
          <div className="border border-slate-200 dark:border-slate-800 rounded-xl bg-white dark:bg-[#111827] p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-xs font-mono">
                <span className="font-semibold text-slate-900 dark:text-white">
                  Live Linux Kernel Datapath Visualizer
                </span>
                <span aria-hidden="true" className="text-slate-400">·</span>
                {isVerifierPassing ? (
                  <span className="text-emerald-600 dark:text-emerald-400 font-semibold">
                    ● VERIFIED & ATTACHED ({activePreset.hookPoint})
                  </span>
                ) : (
                  <span className="text-red-600 dark:text-red-400 font-semibold">
                    ✕ ATTACHMENT BLOCKED BY VERIFIER (-EACCES)
                  </span>
                )}
              </div>

              <div className="flex items-center gap-4 text-xs font-mono tabular-nums">
                <span className="text-emerald-600 dark:text-emerald-400">
                  ✓ Passed/Traced: <strong>{totalPassed.toLocaleString()}</strong>
                </span>
                <span className="text-red-600 dark:text-red-400">
                  ✕ Dropped/Blocked: <strong>{totalDropped.toLocaleString()}</strong>
                </span>
              </div>
            </div>

            {/* SVG Animated Kernel Flow Diagram */}
            <div className="bg-slate-50 dark:bg-[#0B0F17] border border-slate-200 dark:border-slate-800 rounded-lg p-3 sm:p-4 overflow-x-auto">
              <div className="text-[10px] font-mono text-slate-500 dark:text-slate-400 sm:hidden mb-2 flex items-center justify-between">
                <span>Kernel Pipeline Diagram</span>
                <span>Scroll right to view full pipeline →</span>
              </div>
              <svg
                viewBox="0 0 780 145"
                className="w-full min-w-[640px] h-auto select-none"
                role="img"
                aria-label="Real-time eBPF kernel event execution pipeline"
              >
                {/* Connecting Flow Lines */}
                <line
                  x1="135"
                  y1="72"
                  x2="205"
                  y2="72"
                  stroke={isVerifierPassing ? '#0EA5E9' : '#64748B'}
                  strokeWidth="2.5"
                  className={isRunning && isVerifierPassing ? 'animate-flow-line' : ''}
                />
                <line
                  x1="345"
                  y1="72"
                  x2="415"
                  y2="72"
                  stroke={
                    !isVerifierPassing
                      ? '#EF4444'
                      : lastPulseVerdict === 'DROP'
                      ? '#EF4444'
                      : '#10B981'
                  }
                  strokeWidth="2.5"
                  className={isRunning && isVerifierPassing ? 'animate-flow-line' : ''}
                />
                <line
                  x1="565"
                  y1="72"
                  x2="630"
                  y2="72"
                  stroke={isVerifierPassing ? '#F59E0B' : '#64748B'}
                  strokeWidth="2.5"
                  className={isRunning && isVerifierPassing ? 'animate-flow-line' : ''}
                />

                {/* Node 1: Kernel Event / NIC Source */}
                <g transform="translate(10, 26)">
                  <rect
                    width="125"
                    height="92"
                    rx="8"
                    className="fill-white dark:fill-slate-900 stroke-slate-300 dark:stroke-slate-700"
                    strokeWidth="1.5"
                  />
                  <text x="12" y="24" className="fill-sky-600 dark:fill-sky-400 text-[10px] font-mono font-semibold">
                    [01. EVENT SOURCE]
                  </text>
                  <text x="12" y="46" className="fill-slate-900 dark:fill-white text-[12px] font-semibold">
                    {activePreset.hookPoint === 'XDP' ? 'NIC RX DMA Ring' : 'Syscall / VFS Trap'}
                  </text>
                  <text x="12" y="66" className="fill-slate-500 dark:fill-slate-400 text-[10px] font-mono">
                    {activePreset.hookPoint === 'XDP' ? 'struct xdp_md' : 'struct pt_regs / ctx'}
                  </text>
                  <text x="12" y="82" className="fill-emerald-600 dark:fill-emerald-400 text-[10px] font-mono">
                    Rate: {isVerifierPassing && isRunning ? `${eventRatePerSec} ev/s` : '0 ev/s'}
                  </text>
                </g>

                {/* Node 2: eBPF Verifier & Hook Execution */}
                <g transform="translate(205, 20)">
                  <rect
                    width="140"
                    height="104"
                    rx="8"
                    className={
                      isVerifierPassing
                        ? 'fill-sky-500/10 stroke-sky-500'
                        : 'fill-red-500/15 stroke-red-500'
                    }
                    strokeWidth="2"
                  />
                  <text
                    x="12"
                    y="24"
                    className={
                      isVerifierPassing
                        ? 'fill-sky-600 dark:fill-sky-400 text-[10px] font-mono font-semibold'
                        : 'fill-red-600 dark:fill-red-400 text-[10px] font-mono font-semibold'
                    }
                  >
                    [02. KERNEL HOOK]
                  </text>
                  <text x="12" y="46" className="fill-slate-900 dark:fill-white text-[12px] font-semibold">
                    SEC("{activePreset.hookPoint.toLowerCase()}")
                  </text>
                  <text x="12" y="66" className="fill-slate-600 dark:fill-slate-300 text-[10px] font-mono">
                    {isVerifierPassing ? '✓ Verifier: SAFE' : '✕ Verifier: REJECT'}
                  </text>
                  <text x="12" y="86" className="fill-slate-500 dark:fill-slate-400 text-[10px] font-mono">
                    {isVerifierPassing
                      ? lastPulseVerdict === 'DROP'
                        ? 'Verdict: DROP/-EPERM'
                        : 'Verdict: PASS/ALLOW'
                      : 'Halted at load time'}
                  </text>
                </g>

                {/* Node 3: BPF Map / RingBuffer */}
                <g transform="translate(415, 26)">
                  <rect
                    width="150"
                    height="92"
                    rx="8"
                    className="fill-white dark:fill-slate-900 stroke-slate-300 dark:stroke-slate-700"
                    strokeWidth="1.5"
                  />
                  <text x="12" y="24" className="fill-emerald-600 dark:fill-emerald-400 text-[10px] font-mono font-semibold">
                    [03. IN-KERNEL MAP]
                  </text>
                  <text x="12" y="46" className="fill-slate-900 dark:fill-white text-[12px] font-semibold">
                    {activePreset.mapName}
                  </text>
                  <text x="12" y="66" className="fill-slate-500 dark:fill-slate-400 text-[10px] font-mono">
                    {activePreset.mapType.replace('BPF_MAP_TYPE_', '')}
                  </text>
                  <text x="12" y="82" className="fill-sky-600 dark:fill-sky-400 text-[10px] font-mono">
                    Entries: {mapEntries.length} active
                  </text>
                </g>

                {/* Node 4: Userspace Go cilium/ebpf */}
                <g transform="translate(630, 26)">
                  <rect
                    width="140"
                    height="92"
                    rx="8"
                    className="fill-white dark:fill-slate-900 stroke-amber-500/60"
                    strokeWidth="1.5"
                  />
                  <text x="12" y="24" className="fill-amber-600 dark:fill-amber-400 text-[10px] font-mono font-semibold">
                    [04. USERSPACE GO]
                  </text>
                  <text x="12" y="46" className="fill-slate-900 dark:fill-white text-[12px] font-semibold">
                    cilium/ebpf Reader
                  </text>
                  <text x="12" y="66" className="fill-slate-500 dark:fill-slate-400 text-[10px] font-mono">
                    bpfObjects / ringbuf
                  </text>
                  <text x="12" y="82" className="fill-slate-600 dark:fill-slate-300 text-[10px] font-mono">
                    Events Rx: {events.length}
                  </text>
                </g>
              </svg>
            </div>

            {/* Interactive Verifier Safety Check Toggles (Test how the Verifier catches bugs!) */}
            <div className="pt-2 space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-800 dark:text-slate-200">
                  Interactive eBPF Verifier Safety Invariants (Uncheck a rule to inject a kernel bug & test the Verifier)
                </span>
                {disabledSafetyIds.length > 0 && (
                  <button
                    onClick={() => setDisabledSafetyIds([])}
                    className="text-xs font-mono text-emerald-600 dark:text-emerald-400 hover:underline"
                  >
                    Restore All Safety Checks
                  </button>
                )}
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {activePreset.safetyToggles.map((toggle) => {
                  const isSafeEnabled = !disabledSafetyIds.includes(toggle.id);
                  return (
                    <button
                      key={toggle.id}
                      onClick={() => toggleSafetyFlag(toggle.id)}
                      className={`text-left p-3 rounded-lg border transition-colors ${
                        isSafeEnabled
                          ? 'border-emerald-500/30 bg-emerald-500/5 hover:border-emerald-500/60'
                          : 'border-red-500 bg-red-500/12'
                      }`}
                    >
                      <div className="flex items-center justify-between text-xs font-mono font-semibold mb-1">
                        <span
                          className={
                            isSafeEnabled
                              ? 'text-emerald-700 dark:text-emerald-400'
                              : 'text-red-700 dark:text-red-400'
                          }
                        >
                          {isSafeEnabled ? '✓ SAFETY CHECK ACTIVE' : '✕ BUG INJECTED (UNSAFE)'}
                        </span>
                        <span className="text-slate-400">Line {toggle.cLineNumber}</span>
                      </div>
                      <div className="text-xs font-semibold text-slate-900 dark:text-white mb-0.5">
                        {toggle.label}
                      </div>
                      <p className="text-[11px] text-slate-600 dark:text-slate-400">
                        {toggle.description}
                      </p>
                    </button>
                  );
                })}
              </div>
            </div>
          </div>

          {/* 2. Dual-Pane Code & Bytecode Studio */}
          <div className="border border-slate-200 dark:border-slate-800 rounded-xl bg-white dark:bg-[#111827] p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg">
                <button
                  onClick={() => setCodeTab('c')}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                    codeTab === 'c'
                      ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs'
                      : 'text-slate-600 dark:text-slate-400'
                  }`}
                >
                  Kernel C (.bpf.c)
                </button>
                <button
                  onClick={() => setCodeTab('go')}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                    codeTab === 'go'
                      ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs'
                      : 'text-slate-600 dark:text-slate-400'
                  }`}
                >
                  Userspace Go (cilium/ebpf)
                </button>
                <button
                  onClick={() => setCodeTab('bytecode')}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                    codeTab === 'bytecode'
                      ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs'
                      : 'text-slate-600 dark:text-slate-400'
                  }`}
                >
                  Verifier Bytecode & Registers
                </button>
              </div>

              <span className="text-xs font-mono text-slate-500 dark:text-slate-400">
                {codeTab === 'c'
                  ? 'Compiled via Clang -target bpf -O2'
                  : codeTab === 'go'
                  ? 'Generated via bpf2go'
                  : '64-bit eBPF Virtual ISA Instructions'}
              </span>
            </div>

            {codeTab === 'c' && (
              <SyntaxHighlighter
                code={displayedCCode}
                language="c"
                title={`${activePreset.id}.bpf.c`}
                badgeText={`SEC("${activePreset.hookPoint.toLowerCase()}")`}
                errorLineNumber={activeFailureToggle ? activeFailureToggle.cLineNumber : null}
                errorMessage={
                  activeFailureToggle ? activeFailureToggle.verifierErrorLog[3] : null
                }
              />
            )}

            {codeTab === 'go' && (
              <SyntaxHighlighter
                code={activePreset.goCode}
                language="go"
                title="main.go"
                badgeText="github.com/cilium/ebpf"
              />
            )}

            {codeTab === 'bytecode' && (
              <SyntaxHighlighter
                code={activePreset.bpfBytecode.join('\n')}
                language="bpf-asm"
                title="llvm-objdump -S bpf_bpfel.o"
                badgeText="Verified eBPF Instructions"
              />
            )}
          </div>
        </div>

        {/* RIGHT ZONE: Workload Generator + Verifier Diagnostic Log + Map/RingBuf Inspector (4 cols) */}
        <div className="lg:col-span-4 space-y-6">
          {/* 1. Synthetic Workload & Anomaly Trigger Deck */}
          <div className="border border-slate-200 dark:border-slate-800 rounded-xl bg-white dark:bg-[#111827] p-5 space-y-3">
            <div className="text-xs font-mono text-amber-600 dark:text-amber-400 font-semibold">
              01. Synthetic Kernel Workload Generator
            </div>
            <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
              Inject Live Traffic & Syscall Bursts
            </h3>
            <div className="grid grid-cols-1 gap-2">
              <button
                onClick={() => triggerSyntheticEvent('normal_http')}
                disabled={!isVerifierPassing}
                className="w-full text-left px-3.5 py-2.5 rounded-lg border border-slate-200 dark:border-slate-800 hover:border-sky-500/60 bg-slate-50/70 dark:bg-slate-900/60 text-xs flex items-center justify-between disabled:opacity-40 transition-colors"
              >
                <span className="font-medium text-slate-800 dark:text-slate-200">
                  Send Legitimate Pod HTTP Request
                </span>
                <span className="font-mono text-emerald-600 dark:text-emerald-400">✓ PASS</span>
              </button>

              <button
                onClick={() => triggerSyntheticEvent('syn_flood')}
                disabled={!isVerifierPassing}
                className="w-full text-left px-3.5 py-2.5 rounded-lg border border-slate-200 dark:border-slate-800 hover:border-red-500/60 bg-slate-50/70 dark:bg-slate-900/60 text-xs flex items-center justify-between disabled:opacity-40 transition-colors"
              >
                <span className="font-medium text-slate-800 dark:text-slate-200">
                  Inject Botnet SYN Flood (198.51.100.77)
                </span>
                <span className="font-mono text-red-600 dark:text-red-400">✕ XDP_DROP</span>
              </button>

              <button
                onClick={() => triggerSyntheticEvent('container_exec')}
                disabled={!isVerifierPassing}
                className="w-full text-left px-3.5 py-2.5 rounded-lg border border-slate-200 dark:border-slate-800 hover:border-sky-500/60 bg-slate-50/70 dark:bg-slate-900/60 text-xs flex items-center justify-between disabled:opacity-40 transition-colors"
              >
                <span className="font-medium text-slate-800 dark:text-slate-200">
                  Spawn Container Shell (/bin/sh)
                </span>
                <span className="font-mono text-sky-600 dark:text-sky-400">● RINGBUF</span>
              </button>

              <button
                onClick={() => triggerSyntheticEvent('shadow_read')}
                disabled={!isVerifierPassing}
                className="w-full text-left px-3.5 py-2.5 rounded-lg border border-slate-200 dark:border-slate-800 hover:border-red-500/60 bg-slate-50/70 dark:bg-slate-900/60 text-xs flex items-center justify-between disabled:opacity-40 transition-colors"
              >
                <span className="font-medium text-slate-800 dark:text-slate-200">
                  Simulate Unauthorized /etc/shadow Read
                </span>
                <span className="font-mono text-red-600 dark:text-red-400">✕ LSM -EPERM</span>
              </button>

              <button
                onClick={() => triggerSyntheticEvent('tcp_retransmit')}
                disabled={!isVerifierPassing}
                className="w-full text-left px-3.5 py-2.5 rounded-lg border border-slate-200 dark:border-slate-800 hover:border-amber-500/60 bg-slate-50/70 dark:bg-slate-900/60 text-xs flex items-center justify-between disabled:opacity-40 transition-colors"
              >
                <span className="font-medium text-slate-800 dark:text-slate-200">
                  Trigger Cross-AZ TCP Latency Spike
                </span>
                <span className="font-mono text-amber-600 dark:text-amber-400">▲ 1,840 us</span>
              </button>
            </div>
          </div>

          {/* 2. eBPF Static Verifier Diagnostic & Register State Inspector */}
          <div className="border border-slate-200 dark:border-slate-800 rounded-xl bg-white dark:bg-[#111827] p-5 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-semibold text-sky-600 dark:text-sky-400">
                02. eBPF Verifier Register State (R0–R10)
              </span>
              <span
                className={`text-xs font-mono font-semibold ${
                  isVerifierPassing
                    ? 'text-emerald-600 dark:text-emerald-400'
                    : 'text-red-600 dark:text-red-400'
                }`}
              >
                {isVerifierPassing ? '✓ PASS (20 insns)' : '✕ REJECTED (-EACCES)'}
              </span>
            </div>

            <div
              className={`p-3 rounded-lg border font-mono text-[11px] space-y-1.5 ${
                isVerifierPassing
                  ? 'border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#0B0F17] text-slate-700 dark:text-slate-300'
                  : 'border-red-500/50 bg-red-500/10 text-red-800 dark:text-red-300'
              }`}
            >
              {isVerifierPassing ? (
                <>
                  <div>Func#0 @0: R1=ctx(off=0) R10=fp0</div>
                  <div>Stack Usage: 16 / 512 bytes (R10 frame safe)</div>
                  <div>Loops: 0 back-edges | Helper Calls: Verified</div>
                  <div className="text-emerald-600 dark:text-emerald-400 font-semibold">
                    safe: processed 20 insns (limit 1000000) -&gt; JIT x86_64
                  </div>
                </>
              ) : (
                activeFailureToggle?.verifierErrorLog.map((line, i) => (
                  <div key={i} className={i >= 3 ? 'font-bold' : ''}>
                    {line}
                  </div>
                ))
              )}
            </div>
          </div>

          {/* 3. Live BPF Map, RingBuffer & Histogram Telemetry Deck */}
          <div className="border border-slate-200 dark:border-slate-800 rounded-xl bg-white dark:bg-[#111827] p-5 space-y-4">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-mono font-semibold text-emerald-600 dark:text-emerald-400">
                03. Kernel Telemetry Inspector
              </span>
              <div className="flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-900 rounded-lg">
                {[
                  { id: 'events', label: 'RingBuf Stream' },
                  { id: 'map', label: 'BPF Map Table' },
                  { id: 'histogram', label: 'RTT Histogram' }
                ].map((t) => (
                  <button
                    key={t.id}
                    onClick={() => setTelemetryTab(t.id as any)}
                    className={`px-2.5 py-1 text-[11px] font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                      telemetryTab === t.id
                        ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs'
                        : 'text-slate-600 dark:text-slate-400'
                    }`}
                  >
                    {t.label}
                  </button>
                ))}
              </div>
            </div>

            {telemetryTab === 'events' && (
              <div className="space-y-2 max-h-72 overflow-y-auto pr-1 font-mono text-[11px] tabular-nums">
                {events.length === 0 ? (
                  <div className="py-8 text-center text-slate-500">
                    No kernel events recorded yet. Click "Step Event" or "Resume Stream".
                  </div>
                ) : (
                  events.map((ev) => (
                    <div
                      key={ev.id}
                      className="p-2.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-[#0B0F17] space-y-1"
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-slate-500">
                          {ev.timestamp} · CPU {ev.cpu} · {ev.comm}[{ev.pid}]
                        </span>
                        <span
                          className={`font-semibold ${
                            ev.verdict === 'XDP_DROP' || ev.verdict === 'BLOCK'
                              ? 'text-red-600 dark:text-red-400'
                              : 'text-emerald-600 dark:text-emerald-400'
                          }`}
                        >
                          {ev.verdict} ({ev.latencyNs}ns)
                        </span>
                      </div>
                      <div className="text-slate-800 dark:text-slate-200 break-all">
                        {ev.details}
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}

            {telemetryTab === 'map' && (
              <div className="space-y-2 font-mono text-[11px] tabular-nums">
                <div className="text-slate-500 dark:text-slate-400">
                  Map: <strong className="text-slate-900 dark:text-white">{activePreset.mapName}</strong> ({activePreset.mapType})
                </div>
                <div className="divide-y divide-slate-200 dark:divide-slate-800 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
                  {mapEntries.map((entry, idx) => (
                    <div
                      key={idx}
                      className="p-2.5 bg-slate-50/50 dark:bg-[#0B0F17] space-y-0.5"
                    >
                      <div className="flex items-center justify-between text-slate-900 dark:text-slate-100 font-semibold">
                        <span>{entry.key}</span>
                        <span className="text-slate-400">CPU #{entry.cpuCore}</span>
                      </div>
                      <div className="flex items-center justify-between text-slate-600 dark:text-slate-400">
                        <span>{entry.value}</span>
                        <span>{entry.updatedAt}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {telemetryTab === 'histogram' && (
              <div className="space-y-2.5 font-mono text-[11px] tabular-nums">
                <div className="text-slate-500 dark:text-slate-400">
                  In-Kernel Log2 Latency Distribution (BPF_MAP_TYPE_PERCPU_ARRAY)
                </div>
                {histogram.map((h, i) => {
                  const pct = Math.max(4, Math.round((h.count / maxHistCount) * 100));
                  return (
                    <div key={i} className="space-y-1">
                      <div className="flex items-center justify-between text-slate-700 dark:text-slate-300">
                        <span>{h.bucketLabel}</span>
                        <span className="font-semibold">{h.count.toLocaleString()} events</span>
                      </div>
                      <div className="w-full h-2 bg-slate-200 dark:bg-slate-800 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-sky-500 rounded-full transition-all"
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
