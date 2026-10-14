import React, { useState, useMemo } from 'react';
import {
  Search,
  Terminal,
  ShieldAlert,
  Cpu,
  Layers,
  AlertTriangle,
  CheckCircle2,
  ArrowUpRight,
  Code2,
  BookOpen,
  FileWarning,
  Binary
} from 'lucide-react';
import { TRACEABLE_SYSCALLS } from '../data/syscallsData';
import { SyscallCategory, SyscallReferenceItem } from '../types/ebpf';
import { SyntaxHighlighter } from './SyntaxHighlighter';

interface SyscallsReferenceViewProps {
  onNavigateToTutorial?: (tutorialId: string) => void;
}

const SYSCALL_CATEGORIES: ('ALL' | SyscallCategory)[] = [
  'ALL',
  'Process & Execution',
  'Filesystem & VFS',
  'Network & Sockets',
  'Memory, Privilege & Security'
];

export const SyscallsReferenceView: React.FC<SyscallsReferenceViewProps> = ({
  onNavigateToTutorial
}) => {
  const [selectedCategory, setSelectedCategory] = useState<'ALL' | SyscallCategory>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSyscallId, setSelectedSyscallId] = useState<string>(TRACEABLE_SYSCALLS[0].id);
  const [activeCodeTab, setActiveCodeTab] = useState<'both' | 'c' | 'go'>('both');
  const [showMobileSyscallList, setShowMobileSyscallList] = useState<boolean>(false);

  const filteredSyscalls = useMemo(() => {
    return TRACEABLE_SYSCALLS.filter((sc) => {
      const matchesCategory = selectedCategory === 'ALL' || sc.category === selectedCategory;
      const q = searchQuery.trim().toLowerCase();
      if (!q) return matchesCategory;
      const matchesQuery =
        sc.name.toLowerCase().includes(q) ||
        sc.shortSummary.toLowerCase().includes(q) ||
        sc.enterTracepoint.toLowerCase().includes(q) ||
        sc.cSignature.toLowerCase().includes(q) ||
        String(sc.syscallNumberX86_64).includes(q) ||
        sc.arguments.some((a) => a.name.toLowerCase().includes(q) || a.cType.toLowerCase().includes(q));
      return matchesCategory && matchesQuery;
    });
  }, [selectedCategory, searchQuery]);

  const activeSyscall: SyscallReferenceItem = useMemo(() => {
    const found = filteredSyscalls.find((s) => s.id === selectedSyscallId);
    if (found) return found;
    return filteredSyscalls[0] || TRACEABLE_SYSCALLS[0];
  }, [filteredSyscalls, selectedSyscallId]);

  const getPointerSpaceBadge = (space: SyscallReferenceItem['arguments'][number]['pointerSpace']) => {
    if (space === 'USER_POINTER (__user)') {
      return 'border-amber-500/40 bg-amber-500/10 text-amber-400';
    }
    if (space === 'USER_STRUCT_PTR (__user)') {
      return 'border-purple-500/40 bg-purple-500/10 text-purple-400';
    }
    return 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400';
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-cyan-400 mb-1">
              <Terminal className="w-3.5 h-3.5" />
              <span>LINUX KERNEL ABI &amp; SYSCALL TRACING ENCYCLOPEDIA</span>
            </div>
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-[var(--text-primary)]">
              Traceable Linux System Calls Catalog ({TRACEABLE_SYSCALLS.length} Deep-Dive Syscalls)
            </h1>
            <p className="text-sm text-[var(--text-secondary)] mt-1 max-w-4xl">
              Complete OS &amp; kernel-internals reference for every high-value Linux system call: exact{' '}
              <code className="font-mono text-cyan-400">tracepoint/syscalls/sys_enter_*</code> &amp;{' '}
              <code className="font-mono text-emerald-400">BPF LSM</code> attachment paths, kernel data structures mutated,{' '}
              <code className="font-mono text-amber-400">__user</code> pointer memory spaces, return <code className="font-mono">errno</code> codes, and production C + Go (<code className="font-mono">cilium/ebpf</code>) probes.
            </p>
          </div>

          {/* Quick Stats */}
          <div className="grid grid-cols-3 gap-2 shrink-0">
            <div className="border border-[var(--border-subtle)] bg-[var(--bg-elevated)] px-3 py-2">
              <div className="text-[10px] font-mono uppercase text-[var(--text-muted)]">Syscalls</div>
              <div className="text-lg font-mono font-bold text-cyan-400">{TRACEABLE_SYSCALLS.length}</div>
            </div>
            <div className="border border-[var(--border-subtle)] bg-[var(--bg-elevated)] px-3 py-2">
              <div className="text-[10px] font-mono uppercase text-[var(--text-muted)]">Entry/Exit ABI</div>
              <div className="text-lg font-mono font-bold text-emerald-400">x86_64/ARM64</div>
            </div>
            <div className="border border-[var(--border-subtle)] bg-[var(--bg-elevated)] px-3 py-2">
              <div className="text-[10px] font-mono uppercase text-[var(--text-muted)]">User Ptr Rule</div>
              <div className="text-xs font-mono font-bold text-amber-400 mt-1">probe_read_user</div>
            </div>
          </div>
        </div>

        {/* Filter & Search Bar */}
        <div className="mt-5 pt-4 border-t border-[var(--border-subtle)] flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between">
          <div className="flex flex-wrap gap-1.5">
            {SYSCALL_CATEGORIES.map((category) => {
              const active = selectedCategory === category;
              const count =
                category === 'ALL'
                  ? TRACEABLE_SYSCALLS.length
                  : TRACEABLE_SYSCALLS.filter((s) => s.category === category).length;
              return (
                <button
                  key={category}
                  onClick={() => setSelectedCategory(category)}
                  className={`px-3 py-1.5 text-xs font-mono border transition-colors cursor-pointer ${
                    active
                      ? 'border-cyan-500 bg-cyan-500/15 text-cyan-400 font-semibold'
                      : 'border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
                  }`}
                >
                  {category} <span className="opacity-70">({count})</span>
                </button>
              );
            })}
          </div>

          <div className="relative min-w-[260px]">
            <Search className="w-4 h-4 text-[var(--text-muted)] absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search syscall (e.g. execve, openat, mmap, #59)..."
              className="w-full pl-9 pr-3 py-1.5 text-xs font-mono bg-[var(--bg-elevated)] border border-[var(--border-subtle)] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>
      </div>

      {/* Mobile Quick Syscall Switcher Bar (Visible only on mobile < lg) */}
      <div className="lg:hidden p-3.5 border border-cyan-500/30 bg-cyan-500/5 rounded-lg">
        <div className="flex items-center justify-between gap-2">
          <div className="min-w-0 flex-1">
            <div className="text-[10px] font-mono uppercase text-cyan-400">
              Active Syscall #{activeSyscall.syscallNumberX86_64} (x86_64)
            </div>
            <div className="text-xs font-mono font-bold text-[var(--text-primary)] truncate">
              {activeSyscall.name}
            </div>
          </div>

          <button
            type="button"
            onClick={() => setShowMobileSyscallList(!showMobileSyscallList)}
            className="min-h-[44px] px-3 py-1.5 text-xs font-mono font-semibold border border-cyan-500/40 bg-[var(--bg-elevated)] text-cyan-400 flex items-center gap-1.5 shrink-0 shadow-xs cursor-pointer"
          >
            <span>{showMobileSyscallList ? 'Hide Syscalls' : `Switch (${filteredSyscalls.length})`}</span>
          </button>
        </div>

        {/* Expandable Mobile Syscall List */}
        {showMobileSyscallList && (
          <div className="mt-3 space-y-1.5 max-h-[320px] overflow-y-auto p-1.5 border border-[var(--border-subtle)] bg-[var(--bg-elevated)] rounded">
            {filteredSyscalls.map((sc) => {
              const isSelected = sc.id === activeSyscall.id;
              return (
                <button
                  key={sc.id}
                  type="button"
                  onClick={() => {
                    setSelectedSyscallId(sc.id);
                    setShowMobileSyscallList(false);
                  }}
                  className={`w-full min-h-[44px] text-left p-2.5 border transition-all flex items-center justify-between gap-2 cursor-pointer ${
                    isSelected
                      ? 'border-cyan-500 bg-cyan-500/15 text-cyan-400 font-bold'
                      : 'border-transparent hover:border-[var(--border-subtle)] text-[var(--text-primary)]'
                  }`}
                >
                  <div className="min-w-0">
                    <div className="text-xs font-mono font-bold truncate">
                      #{sc.syscallNumberX86_64} {sc.name}
                    </div>
                    <div className="text-[10px] font-mono text-[var(--text-muted)] truncate">
                      {sc.category}
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* Main Split View: Left Syscall List + Right Deep-Dive Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Sidebar: Syscall Selector (Always visible on desktop, hidden on mobile) */}
        <div className="hidden lg:block lg:col-span-3 space-y-1.5 max-h-[1200px] overflow-y-auto pr-1">
          {filteredSyscalls.map((sc) => {
            const isSelected = sc.id === activeSyscall.id;
            return (
              <button
                key={sc.id}
                onClick={() => setSelectedSyscallId(sc.id)}
                className={`w-full text-left p-3 border transition-all cursor-pointer ${
                  isSelected
                    ? 'border-cyan-500 bg-cyan-500/10'
                    : 'border-[var(--border-subtle)] bg-[var(--bg-surface)] hover:bg-[var(--bg-elevated)]'
                }`}
              >
                <div className="flex items-center justify-between gap-2 mb-1">
                  <span className="font-mono text-sm font-bold text-[var(--text-primary)]">
                    {sc.name}
                  </span>
                  <span className="px-1.5 py-0.5 text-[10px] font-mono border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-cyan-400">
                    #{sc.syscallNumberX86_64}
                  </span>
                </div>
                <div className="text-[10px] font-mono uppercase tracking-wider text-emerald-400 mb-1">
                  {sc.category}
                </div>
                <p className="text-xs text-[var(--text-secondary)] line-clamp-2">{sc.shortSummary}</p>
              </button>
            );
          })}
        </div>

        {/* Right Detail Panel */}
        <div className="lg:col-span-9 space-y-6">
          {/* Syscall Header Card & Hook Matrix */}
          <div className="border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5 space-y-4">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <div className="flex items-center gap-2.5 flex-wrap">
                  <span className="px-2 py-0.5 text-xs font-mono font-bold border border-cyan-500/40 bg-cyan-500/10 text-cyan-400">
                    SYSCALL #{activeSyscall.syscallNumberX86_64} (x86_64)
                  </span>
                  <span className="px-2 py-0.5 text-xs font-mono border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-[var(--text-secondary)]">
                    {activeSyscall.category}
                  </span>
                </div>
                <h2 className="text-2xl font-bold font-mono text-[var(--text-primary)] mt-2">
                  {activeSyscall.name}
                </h2>
                <p className="text-sm text-[var(--text-secondary)] mt-1">{activeSyscall.shortSummary}</p>
              </div>

              {activeSyscall.relatedTutorialId && onNavigateToTutorial && (
                <button
                  onClick={() => onNavigateToTutorial(activeSyscall.relatedTutorialId!)}
                  className="px-3 py-2 text-xs font-mono font-semibold border border-cyan-500/50 bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 flex items-center gap-1.5 cursor-pointer"
                >
                  <span>Open Hands-On Lab</span>
                  <ArrowUpRight className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {/* C Prototype Box */}
            <div className="border border-[var(--border-subtle)] bg-[var(--bg-elevated)] p-3">
              <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-1">
                POSIX / Kernel C Prototype
              </div>
              <code className="text-xs sm:text-sm font-mono text-cyan-400 break-all">
                {activeSyscall.cSignature}
              </code>
            </div>

            {/* 4 Hook Attachment Paths */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="border border-[var(--border-subtle)] bg-[var(--bg-elevated)] p-3">
                <div className="text-[10px] font-mono uppercase text-emerald-400 mb-1">
                  1. Entry Tracepoint (Inspect Input Args)
                </div>
                <code className="text-xs font-mono text-[var(--text-primary)] break-all">
                  SEC(&quot;{activeSyscall.enterTracepoint}&quot;)
                </code>
              </div>
              <div className="border border-[var(--border-subtle)] bg-[var(--bg-elevated)] p-3">
                <div className="text-[10px] font-mono uppercase text-cyan-400 mb-1">
                  2. Exit Tracepoint (Inspect Return Value / FD / -errno)
                </div>
                <code className="text-xs font-mono text-[var(--text-primary)] break-all">
                  SEC(&quot;{activeSyscall.exitTracepoint}&quot;)
                </code>
              </div>
              <div className="border border-[var(--border-subtle)] bg-[var(--bg-elevated)] p-3">
                <div className="text-[10px] font-mono uppercase text-purple-400 mb-1">
                  3. Internal Kernel Function / Fentry Hook
                </div>
                <code className="text-xs font-mono text-[var(--text-primary)] break-all">
                  {activeSyscall.fentryHook}
                </code>
              </div>
              <div className="border border-[var(--border-subtle)] bg-[var(--bg-elevated)] p-3">
                <div className="text-[10px] font-mono uppercase text-amber-400 mb-1">
                  4. TOCTOU-Proof BPF LSM Enforcement Hook
                </div>
                <code className="text-xs font-mono text-[var(--text-primary)] break-all">
                  {activeSyscall.lsmAlternative}
                </code>
              </div>
            </div>
          </div>

          {/* Section 1: Detailed OS & Kernel Explanation */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5 space-y-3">
              <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-cyan-400">
                <BookOpen className="w-4 h-4" />
                <span>1. What {activeSyscall.name} Does in Detail</span>
              </div>
              <div className="space-y-3 text-sm text-[var(--text-secondary)] leading-relaxed">
                {activeSyscall.whatItDoesInDetail.map((p, idx) => (
                  <p key={idx}>{p}</p>
                ))}
              </div>
            </div>

            <div className="border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5 space-y-3">
              <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-emerald-400">
                <Cpu className="w-4 h-4" />
                <span>2. Kernel Internals &amp; Data Structures Mutated</span>
              </div>
              <div className="space-y-3 text-sm text-[var(--text-secondary)] leading-relaxed">
                {activeSyscall.kernelInternalsAndStructures.map((p, idx) => (
                  <p key={idx}>{p}</p>
                ))}
              </div>
            </div>
          </div>

          {/* Section 2: Argument-by-Argument Memory Layout & Helper Table */}
          <div className="border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5 space-y-4">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-cyan-400">
                <Binary className="w-4 h-4" />
                <span>
                  3. Argument Layout in struct trace_event_raw_sys_enter (ctx-&gt;args[0..5])
                </span>
              </div>
              <span className="text-xs font-mono text-[var(--text-muted)]">
                Format file: /sys/kernel/tracing/events/syscalls/sys_enter_{activeSyscall.name.replace(/\(.*/, '')}/format
              </span>
            </div>

            <div className="overflow-x-auto border border-[var(--border-subtle)]">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-[10px] font-mono uppercase text-[var(--text-muted)]">
                    <th className="p-3">Tracepoint Index</th>
                    <th className="p-3">Argument &amp; C Type</th>
                    <th className="p-3">Address Space</th>
                    <th className="p-3">Required BPF Helper</th>
                    <th className="p-3">Detailed Kernel Meaning</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border-subtle)] text-xs">
                  {activeSyscall.arguments.map((arg) => (
                    <tr key={arg.argIndex} className="hover:bg-[var(--bg-elevated)]/60">
                      <td className="p-3 font-mono font-bold text-cyan-400 whitespace-nowrap">
                        {arg.argIndex}
                      </td>
                      <td className="p-3 font-mono whitespace-nowrap">
                        <div className="font-bold text-[var(--text-primary)]">{arg.name}</div>
                        <div className="text-[11px] text-[var(--text-muted)]">{arg.cType}</div>
                      </td>
                      <td className="p-3 whitespace-nowrap">
                        <span
                          className={`px-2 py-0.5 text-[10px] font-mono border ${getPointerSpaceBadge(
                            arg.pointerSpace
                          )}`}
                        >
                          {arg.pointerSpace}
                        </span>
                      </td>
                      <td className="p-3 font-mono text-emerald-400 whitespace-nowrap">
                        {arg.helperRequired}
                      </td>
                      <td className="p-3 text-[var(--text-secondary)] leading-relaxed min-w-[260px]">
                        {arg.detailedMeaning}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Section 3: How to Trace in eBPF + Pointer & Verifier Gotchas */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5 space-y-3">
              <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-emerald-400">
                <Layers className="w-4 h-4" />
                <span>4. How to Trace {activeSyscall.name} in eBPF</span>
              </div>
              <ul className="space-y-2.5 text-sm text-[var(--text-secondary)]">
                {activeSyscall.howToTraceInEbpf.map((item, idx) => (
                  <li key={idx} className="flex items-start gap-2.5">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="border border-amber-500/30 bg-amber-500/5 p-5 space-y-3">
              <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-amber-400">
                <AlertTriangle className="w-4 h-4" />
                <span>5. Pointer Safety, Page Fault &amp; Verifier Gotchas</span>
              </div>
              <ul className="space-y-2.5 text-sm text-[var(--text-secondary)]">
                {activeSyscall.pointerAndVerifierGotchas.map((gotcha, idx) => (
                  <li key={idx} className="flex items-start gap-2.5">
                    <FileWarning className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                    <span>{gotcha}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Section 4: Return Values (ctx->ret in sys_exit) & Common Errnos + Security Use Cases */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5 space-y-3">
              <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-cyan-400">
                <Terminal className="w-4 h-4" />
                <span>6. Return Values (sys_exit ctx-&gt;ret) &amp; Common Errnos</span>
              </div>
              <div className="p-3 border border-emerald-500/30 bg-emerald-500/5 text-xs text-[var(--text-primary)]">
                <span className="font-mono font-bold text-emerald-400 uppercase block mb-1">
                  On Success (ret &gt;= 0):
                </span>
                {activeSyscall.returnValuesAndErrnos.successMeaning}
              </div>
              <div className="space-y-2">
                {activeSyscall.returnValuesAndErrnos.commonErrors.map((errItem) => (
                  <div
                    key={errItem.errno}
                    className="p-2.5 border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs"
                  >
                    <span className="font-mono font-bold text-rose-400">{errItem.errno}: </span>
                    <span className="text-[var(--text-secondary)]">{errItem.reason}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5 space-y-3">
              <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-purple-400">
                <ShieldAlert className="w-4 h-4" />
                <span>7. Production Security &amp; Observability Use Cases</span>
              </div>
              <div className="space-y-3">
                {activeSyscall.securityAndObservabilityUseCases.map((uc, idx) => (
                  <div
                    key={idx}
                    className="p-3 border border-[var(--border-subtle)] bg-[var(--bg-elevated)] space-y-1"
                  >
                    <div className="text-xs font-mono font-bold text-[var(--text-primary)]">
                      {uc.title}
                    </div>
                    <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
                      {uc.scenario}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Section 5: Copyable C + Go (cilium/ebpf) Implementation */}
          <div className="border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-cyan-400">
                <Code2 className="w-4 h-4" />
                <span>8. Ready-to-Use Kernel C Probe &amp; Go (cilium/ebpf) Loader</span>
              </div>
              <div className="flex items-center gap-1">
                {(['both', 'c', 'go'] as const).map((tab) => (
                  <button
                    key={tab}
                    onClick={() => setActiveCodeTab(tab)}
                    className={`px-2.5 py-1 text-xs font-mono border cursor-pointer ${
                      activeCodeTab === tab
                        ? 'border-cyan-500 bg-cyan-500/15 text-cyan-400 font-semibold'
                        : 'border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-[var(--text-secondary)]'
                    }`}
                  >
                    {tab === 'both' ? 'Side-by-Side (C + Go)' : tab === 'c' ? 'Kernel C (.bpf.c)' : 'Go Loader (main.go)'}
                  </button>
                ))}
              </div>
            </div>

            <div
              className={`grid gap-4 ${
                activeCodeTab === 'both' ? 'grid-cols-1 xl:grid-cols-2' : 'grid-cols-1'
              }`}
            >
              {(activeCodeTab === 'both' || activeCodeTab === 'c') && (
                <SyntaxHighlighter
                  code={activeSyscall.cSnippet}
                  language="c"
                  title={`trace_${activeSyscall.name.replace(/\(.*/, '')}.bpf.c`}
                  badgeText="eBPF Kernel C"
                />
              )}
              {(activeCodeTab === 'both' || activeCodeTab === 'go') && (
                <SyntaxHighlighter
                  code={activeSyscall.goSnippet}
                  language="go"
                  title="main.go (cilium/ebpf)"
                  badgeText="Go Userspace Control Plane"
                />
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
