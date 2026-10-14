import React, { useState, useMemo } from 'react';
import {
  Search,
  Wrench,
  Cpu,
  ShieldCheck,
  GitCompare,
  Code2,
  BookOpen,
  CheckCircle2,
  Layers
} from 'lucide-react';
import { BPF_HELPERS_CATALOG } from '../data/helpersAndMacrosData';
import { BpfHelperCategory, BpfHelperReferenceItem } from '../types/ebpf';
import { SyntaxHighlighter } from './SyntaxHighlighter';

const HELPER_CATEGORIES: ('ALL' | BpfHelperCategory)[] = [
  'ALL',
  'Process & Task Context',
  'Memory & Pointer Probing',
  'BPF Map Operations',
  'RingBuffer & Telemetry',
  'Networking & Redirection',
  'Timers, Locks & Kfuncs'
];

export const HelpersReferenceView: React.FC = () => {
  const [selectedCategory, setSelectedCategory] = useState<'ALL' | BpfHelperCategory>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedHelperId, setSelectedHelperId] = useState<string>(BPF_HELPERS_CATALOG[0].id);

  const filteredHelpers = useMemo(() => {
    return BPF_HELPERS_CATALOG.filter((h) => {
      const matchesCategory = selectedCategory === 'ALL' || h.category === selectedCategory;
      const q = searchQuery.trim().toLowerCase();
      if (!q) return matchesCategory;
      const matchesQuery =
        h.name.toLowerCase().includes(q) ||
        h.shortSummary.toLowerCase().includes(q) ||
        h.signature.toLowerCase().includes(q) ||
        h.helperIdOrType.toLowerCase().includes(q) ||
        h.allowedProgramTypes.some((p) => p.toLowerCase().includes(q));
      return matchesCategory && matchesQuery;
    });
  }, [selectedCategory, searchQuery]);

  const activeHelper: BpfHelperReferenceItem = useMemo(() => {
    const found = filteredHelpers.find((h) => h.id === selectedHelperId);
    if (found) return found;
    return filteredHelpers[0] || BPF_HELPERS_CATALOG[0];
  }, [filteredHelpers, selectedHelperId]);

  const isKfunc = activeHelper.helperIdOrType.toLowerCase().includes('kfunc');

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-emerald-400 mb-1">
              <Wrench className="w-3.5 h-3.5" />
              <span>UAPI BPF HELPER FUNCTIONS &amp; BTF KFUNCS DICTIONARY</span>
            </div>
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-[var(--text-primary)]">
              BPF Helper Functions &amp; Kernel Kfuncs ({BPF_HELPERS_CATALOG.length} Core APIs)
            </h1>
            <p className="text-sm text-[var(--text-secondary)] mt-1 max-w-4xl">
              Since eBPF programs cannot call arbitrary kernel C functions directly, they interact with kernel memory, maps, sockets, and ring buffers exclusively through verified{' '}
              <code className="font-mono text-emerald-400">bpf_helper</code> functions (<code className="font-mono">&lt;bpf/bpf_helpers.h&gt;</code>) and BTF{' '}
              <code className="font-mono text-cyan-400">kfuncs</code>. Inspect register ABIs (<code className="font-mono">R1–R5</code> &rarr; <code className="font-mono">R0</code>), Verifier safety contracts, and &ldquo;Why Use X Instead of Y?&rdquo; engineering trade-offs.
            </p>
          </div>

          <div className="grid grid-cols-3 gap-2 shrink-0">
            <div className="border border-[var(--border-subtle)] bg-[var(--bg-elevated)] px-3 py-2">
              <div className="text-[10px] font-mono uppercase text-[var(--text-muted)]">Catalog Size</div>
              <div className="text-lg font-mono font-bold text-emerald-400">{BPF_HELPERS_CATALOG.length}</div>
            </div>
            <div className="border border-[var(--border-subtle)] bg-[var(--bg-elevated)] px-3 py-2">
              <div className="text-[10px] font-mono uppercase text-[var(--text-muted)]">Arg Registers</div>
              <div className="text-lg font-mono font-bold text-cyan-400">R1 – R5</div>
            </div>
            <div className="border border-[var(--border-subtle)] bg-[var(--bg-elevated)] px-3 py-2">
              <div className="text-[10px] font-mono uppercase text-[var(--text-muted)]">Return Reg</div>
              <div className="text-lg font-mono font-bold text-amber-400">R0</div>
            </div>
          </div>
        </div>

        {/* Category Filter & Search */}
        <div className="mt-5 pt-4 border-t border-[var(--border-subtle)] flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between">
          <div className="flex flex-wrap gap-1.5">
            {HELPER_CATEGORIES.map((category) => {
              const active = selectedCategory === category;
              const count =
                category === 'ALL'
                  ? BPF_HELPERS_CATALOG.length
                  : BPF_HELPERS_CATALOG.filter((h) => h.category === category).length;
              return (
                <button
                  key={category}
                  onClick={() => setSelectedCategory(category)}
                  className={`px-3 py-1.5 text-xs font-mono border transition-colors cursor-pointer ${
                    active
                      ? 'border-emerald-500 bg-emerald-500/15 text-emerald-400 font-semibold'
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
              placeholder="Search helper (e.g. probe_read_user, ringbuf, kfunc)..."
              className="w-full pl-9 pr-3 py-1.5 text-xs font-mono bg-[var(--bg-elevated)] border border-[var(--border-subtle)] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:outline-none focus:border-emerald-500"
            />
          </div>
        </div>
      </div>

      {/* Main Split View */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Sidebar */}
        <div className="lg:col-span-3 space-y-1.5 max-h-[1150px] overflow-y-auto pr-1">
          {filteredHelpers.map((helper) => {
            const isSelected = helper.id === activeHelper.id;
            const kfuncBadge = helper.helperIdOrType.toLowerCase().includes('kfunc');
            return (
              <button
                key={helper.id}
                onClick={() => setSelectedHelperId(helper.id)}
                className={`w-full text-left p-3 border transition-all cursor-pointer ${
                  isSelected
                    ? 'border-emerald-500 bg-emerald-500/10'
                    : 'border-[var(--border-subtle)] bg-[var(--bg-surface)] hover:bg-[var(--bg-elevated)]'
                }`}
              >
                <div className="flex items-center justify-between gap-2 mb-1">
                  <span className="font-mono text-xs sm:text-sm font-bold text-[var(--text-primary)] break-all">
                    {helper.name}
                  </span>
                  <span
                    className={`px-1.5 py-0.5 text-[10px] font-mono border shrink-0 ${
                      kfuncBadge
                        ? 'border-purple-500/40 bg-purple-500/10 text-purple-400'
                        : 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400'
                    }`}
                  >
                    {helper.minKernel}
                  </span>
                </div>
                <div className="text-[10px] font-mono uppercase tracking-wider text-cyan-400 mb-1">
                  {helper.category}
                </div>
                <p className="text-xs text-[var(--text-secondary)] line-clamp-2">
                  {helper.shortSummary}
                </p>
              </button>
            );
          })}
        </div>

        {/* Right Detail Panel */}
        <div className="lg:col-span-9 space-y-6">
          {/* Header & Signature Card */}
          <div className="border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5 space-y-4">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={`px-2 py-0.5 text-xs font-mono font-bold border ${
                  isKfunc
                    ? 'border-purple-500/40 bg-purple-500/10 text-purple-400'
                    : 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400'
                }`}
              >
                {activeHelper.helperIdOrType}
              </span>
              <span className="px-2 py-0.5 text-xs font-mono border border-cyan-500/40 bg-cyan-500/10 text-cyan-400">
                {activeHelper.minKernel}
              </span>
              <span className="px-2 py-0.5 text-xs font-mono border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-[var(--text-secondary)]">
                {activeHelper.category}
              </span>
            </div>

            <div>
              <h2 className="text-2xl font-bold font-mono text-[var(--text-primary)]">
                {activeHelper.name}
              </h2>
              <p className="text-sm text-[var(--text-secondary)] mt-1">
                {activeHelper.shortSummary}
              </p>
            </div>

            {/* C Signature & Return Spec */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="border border-[var(--border-subtle)] bg-[var(--bg-elevated)] p-3">
                <div className="text-[10px] font-mono uppercase text-[var(--text-muted)] mb-1">
                  Exact C Declaration
                </div>
                <code className="text-xs sm:text-sm font-mono text-emerald-400 break-all">
                  {activeHelper.signature}
                </code>
              </div>
              <div className="border border-[var(--border-subtle)] bg-[var(--bg-elevated)] p-3">
                <div className="text-[10px] font-mono uppercase text-[var(--text-muted)] mb-1">
                  Return Value Specification (Register R0)
                </div>
                <div className="text-xs font-mono text-cyan-400">
                  {activeHelper.returnValueSpec}
                </div>
              </div>
            </div>

            {/* Allowed Program Types */}
            <div className="flex flex-wrap items-center gap-2 pt-1">
              <span className="text-[11px] font-mono uppercase text-[var(--text-muted)] flex items-center gap-1">
                <Layers className="w-3.5 h-3.5 text-cyan-400" />
                Permitted Hook Types:
              </span>
              {activeHelper.allowedProgramTypes.map((pt) => (
                <span
                  key={pt}
                  className="px-2 py-0.5 text-xs font-mono border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-[var(--text-primary)]"
                >
                  {pt}
                </span>
              ))}
            </div>
          </div>

          {/* What It Does & How It Works Under the Hood */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5 space-y-3">
              <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-emerald-400">
                <BookOpen className="w-4 h-4" />
                <span>1. What {activeHelper.name} Does</span>
              </div>
              <div className="space-y-2.5 text-sm text-[var(--text-secondary)] leading-relaxed">
                {activeHelper.whatItDoes.map((p, i) => (
                  <p key={i}>{p}</p>
                ))}
              </div>
            </div>

            <div className="border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5 space-y-3">
              <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-cyan-400">
                <Cpu className="w-4 h-4" />
                <span>2. How It Works Under the Hood in the Kernel</span>
              </div>
              <div className="space-y-2.5 text-sm text-[var(--text-secondary)] leading-relaxed">
                {activeHelper.howItWorksUnderTheHood.map((p, i) => (
                  <p key={i}>{p}</p>
                ))}
              </div>
            </div>
          </div>

          {/* Why Use Instead Of Comparison + Register Mapping */}
          <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
            <div className="md:col-span-7 border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5 space-y-3">
              <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-amber-400">
                <GitCompare className="w-4 h-4" />
                <span>3. Why Use {activeHelper.name} Instead Of Alternatives?</span>
              </div>
              <div className="p-3 border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-mono">
                <span className="text-[var(--text-muted)] uppercase block mb-0.5">
                  Alternative Compared Against:
                </span>
                <span className="text-amber-400 font-bold">
                  {activeHelper.whyUseInsteadOf.alternative}
                </span>
              </div>
              <p className="text-sm text-[var(--text-secondary)] leading-relaxed">
                {activeHelper.whyUseInsteadOf.explanation}
              </p>
            </div>

            <div className="md:col-span-5 border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5 space-y-3">
              <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-cyan-400">
                <Cpu className="w-4 h-4" />
                <span>4. eBPF Register Calling Convention</span>
              </div>
              <div className="space-y-2">
                {activeHelper.registerMapping.map((rm) => (
                  <div
                    key={rm.reg}
                    className="p-2.5 border border-[var(--border-subtle)] bg-[var(--bg-elevated)] flex items-start justify-between gap-3 text-xs font-mono"
                  >
                    <span className="font-bold text-cyan-400 shrink-0">{rm.reg}</span>
                    <span className="text-[var(--text-secondary)] text-right">{rm.meaning}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Verifier Safety Contract */}
          <div className="border border-emerald-500/30 bg-emerald-500/5 p-5 space-y-3">
            <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-emerald-400">
              <ShieldCheck className="w-4 h-4" />
              <span>5. Static Verifier Safety Contract &amp; Mandatory Null/Bounds Checks</span>
            </div>
            <ul className="space-y-2 text-sm text-[var(--text-secondary)]">
              {activeHelper.verifierSafetyContract.map((rule, idx) => (
                <li key={idx} className="flex items-start gap-2.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  <span>{rule}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* C Code Example & Go Control Plane Note */}
          <div className="border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5 space-y-4">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-emerald-400">
                <Code2 className="w-4 h-4" />
                <span>6. Idiomatic Kernel C Usage &amp; Go cilium/ebpf Integration</span>
              </div>
            </div>

            <SyntaxHighlighter
              code={activeHelper.cExample}
              language="c"
              title={`${activeHelper.name.replace(/\(\)/, '')}_example.bpf.c`}
              badgeText="Verified Kernel C Pattern"
            />

            <div className="p-3.5 border border-cyan-500/30 bg-cyan-500/5 text-xs font-mono">
              <span className="font-bold text-cyan-400 uppercase mr-2">
                Go (cilium/ebpf) Control-Plane Note:
              </span>
              <span className="text-[var(--text-secondary)]">{activeHelper.goNote}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
