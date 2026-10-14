import React, { useState, useMemo } from 'react';
import {
  Search,
  Braces,
  Sparkles,
  GitCompare,
  ShieldCheck,
  Code2,
  BookOpen,
  CheckCircle2,
  FileCode2
} from 'lucide-react';
import { EBPF_MACROS_CATALOG } from '../data/helpersAndMacrosData';
import { EbpfMacroCategory, EbpfMacroReferenceItem } from '../types/ebpf';
import { SyntaxHighlighter } from './SyntaxHighlighter';

const MACRO_CATEGORIES: ('ALL' | EbpfMacroCategory)[] = [
  'ALL',
  'SEC() Hook Directives',
  'CO-RE Struct Reading Macros',
  'Kprobe & Trampoline Argument Macros',
  'BTF Map Definition & Compiler Macros'
];

export const MacrosReferenceView: React.FC = () => {
  const [selectedCategory, setSelectedCategory] = useState<'ALL' | EbpfMacroCategory>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedMacroId, setSelectedMacroId] = useState<string>(EBPF_MACROS_CATALOG[0].id);
  const [showMobileMacroList, setShowMobileMacroList] = useState<boolean>(false);

  const filteredMacros = useMemo(() => {
    return EBPF_MACROS_CATALOG.filter((m) => {
      const matchesCategory = selectedCategory === 'ALL' || m.category === selectedCategory;
      const q = searchQuery.trim().toLowerCase();
      if (!q) return matchesCategory;
      const matchesQuery =
        m.name.toLowerCase().includes(q) ||
        m.shortSummary.toLowerCase().includes(q) ||
        m.syntax.toLowerCase().includes(q) ||
        m.headerFile.toLowerCase().includes(q);
      return matchesCategory && matchesQuery;
    });
  }, [selectedCategory, searchQuery]);

  const activeMacro: EbpfMacroReferenceItem = useMemo(() => {
    const found = filteredMacros.find((m) => m.id === selectedMacroId);
    if (found) return found;
    return filteredMacros[0] || EBPF_MACROS_CATALOG[0];
  }, [filteredMacros, selectedMacroId]);

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-amber-400 mb-1">
              <Braces className="w-3.5 h-3.5" />
              <span>LIBBPF / CILIUM EBPF C MACROS, SEC() &amp; CO-RE DIRECTIVES</span>
            </div>
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-[var(--text-primary)]">
              eBPF C Macros, <code className="font-mono text-amber-400">SEC()</code> Directives &amp; BTF Annotations ({EBPF_MACROS_CATALOG.length} Macros)
            </h1>
            <p className="text-sm text-[var(--text-secondary)] mt-1 max-w-4xl">
              Demystify every macro from <code className="font-mono text-cyan-400">&lt;bpf/bpf_helpers.h&gt;</code>,{' '}
              <code className="font-mono text-emerald-400">&lt;bpf/bpf_tracing.h&gt;</code>, and{' '}
              <code className="font-mono text-amber-400">&lt;bpf/bpf_core_read.h&gt;</code>. Inspect side-by-side preprocessor expansions showing what you write versus what the Clang BPF compiler and ELF loader actually see.
            </p>
          </div>

          <div className="grid grid-cols-3 gap-2 shrink-0">
            <div className="border border-[var(--border-subtle)] bg-[var(--bg-elevated)] px-3 py-2">
              <div className="text-[10px] font-mono uppercase text-[var(--text-muted)]">Macros &amp; SEC</div>
              <div className="text-lg font-mono font-bold text-amber-400">{EBPF_MACROS_CATALOG.length}</div>
            </div>
            <div className="border border-[var(--border-subtle)] bg-[var(--bg-elevated)] px-3 py-2">
              <div className="text-[10px] font-mono uppercase text-[var(--text-muted)]">CO-RE Ready</div>
              <div className="text-lg font-mono font-bold text-cyan-400">BTF Reloc</div>
            </div>
            <div className="border border-[var(--border-subtle)] bg-[var(--bg-elevated)] px-3 py-2">
              <div className="text-[10px] font-mono uppercase text-[var(--text-muted)]">CPU ABIs</div>
              <div className="text-xs font-mono font-bold text-emerald-400 mt-1">x86 / ARM64</div>
            </div>
          </div>
        </div>

        {/* Category Filter & Search */}
        <div className="mt-5 pt-4 border-t border-[var(--border-subtle)] flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between">
          <div className="flex flex-wrap gap-1.5">
            {MACRO_CATEGORIES.map((category) => {
              const active = selectedCategory === category;
              const count =
                category === 'ALL'
                  ? EBPF_MACROS_CATALOG.length
                  : EBPF_MACROS_CATALOG.filter((m) => m.category === category).length;
              return (
                <button
                  key={category}
                  onClick={() => setSelectedCategory(category)}
                  className={`px-3 py-1.5 text-xs font-mono border transition-colors cursor-pointer ${
                    active
                      ? 'border-amber-500 bg-amber-500/15 text-amber-400 font-semibold'
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
              placeholder="Search macro (e.g. BPF_CORE_READ, BPF_KPROBE, SEC, __uint)..."
              className="w-full pl-9 pr-3 py-1.5 text-xs font-mono bg-[var(--bg-elevated)] border border-[var(--border-subtle)] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:outline-none focus:border-amber-500"
            />
          </div>
        </div>
      </div>

      {/* Mobile Quick Macro Switcher Bar (Visible only on mobile < lg) */}
      <div className="lg:hidden p-3.5 border border-amber-500/30 bg-amber-500/5 rounded-lg">
        <div className="flex items-center justify-between gap-2">
          <div className="min-w-0 flex-1">
            <div className="text-[10px] font-mono uppercase text-amber-400">
              Active Macro · {activeMacro.category}
            </div>
            <div className="text-xs font-mono font-bold text-[var(--text-primary)] truncate">
              {activeMacro.name}
            </div>
          </div>

          <button
            type="button"
            onClick={() => setShowMobileMacroList(!showMobileMacroList)}
            className="min-h-[44px] px-3 py-1.5 text-xs font-mono font-semibold border border-amber-500/40 bg-[var(--bg-elevated)] text-amber-400 flex items-center gap-1.5 shrink-0 shadow-xs cursor-pointer"
          >
            <span>{showMobileMacroList ? 'Hide Macros' : `Switch (${filteredMacros.length})`}</span>
          </button>
        </div>

        {/* Expandable Mobile Macro List */}
        {showMobileMacroList && (
          <div className="mt-3 space-y-1.5 max-h-[320px] overflow-y-auto p-1.5 border border-[var(--border-subtle)] bg-[var(--bg-elevated)] rounded">
            {filteredMacros.map((m) => {
              const isSelected = m.id === activeMacro.id;
              return (
                <button
                  key={m.id}
                  type="button"
                  onClick={() => {
                    setSelectedMacroId(m.id);
                    setShowMobileMacroList(false);
                  }}
                  className={`w-full min-h-[44px] text-left p-2.5 border transition-all flex items-center justify-between gap-2 cursor-pointer ${
                    isSelected
                      ? 'border-amber-500 bg-amber-500/15 text-amber-400 font-bold'
                      : 'border-transparent hover:border-[var(--border-subtle)] text-[var(--text-primary)]'
                  }`}
                >
                  <div className="min-w-0">
                    <div className="text-xs font-mono font-bold truncate">{m.name}</div>
                    <div className="text-[10px] font-mono text-[var(--text-muted)] truncate">{m.category}</div>
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* Main Split View */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Sidebar (Always visible on desktop, hidden on mobile) */}
        <div className="hidden lg:block lg:col-span-3 space-y-1.5 max-h-[1150px] overflow-y-auto pr-1">
          {filteredMacros.map((macro) => {
            const isSelected = macro.id === activeMacro.id;
            return (
              <button
                key={macro.id}
                onClick={() => setSelectedMacroId(macro.id)}
                className={`w-full text-left p-3 border transition-all cursor-pointer ${
                  isSelected
                    ? 'border-amber-500 bg-amber-500/10'
                    : 'border-[var(--border-subtle)] bg-[var(--bg-surface)] hover:bg-[var(--bg-elevated)]'
                }`}
              >
                <div className="flex items-center justify-between gap-2 mb-1">
                  <span className="font-mono text-xs sm:text-sm font-bold text-[var(--text-primary)]">
                    {macro.name}
                  </span>
                </div>
                <div className="text-[10px] font-mono uppercase tracking-wider text-amber-400 mb-1">
                  {macro.category}
                </div>
                <p className="text-xs text-[var(--text-secondary)] line-clamp-2">
                  {macro.shortSummary}
                </p>
              </button>
            );
          })}
        </div>

        {/* Right Detail Panel */}
        <div className="lg:col-span-9 space-y-6">
          {/* Header & Syntax Card */}
          <div className="border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5 space-y-4">
            <div className="flex flex-wrap items-center gap-2">
              <span className="px-2 py-0.5 text-xs font-mono font-bold border border-amber-500/40 bg-amber-500/10 text-amber-400">
                {activeMacro.category}
              </span>
              <span className="px-2 py-0.5 text-xs font-mono border border-cyan-500/40 bg-cyan-500/10 text-cyan-400 flex items-center gap-1">
                <FileCode2 className="w-3.5 h-3.5" />
                {activeMacro.headerFile}
              </span>
            </div>

            <div>
              <h2 className="text-2xl font-bold font-mono text-[var(--text-primary)]">
                {activeMacro.name}
              </h2>
              <p className="text-sm text-[var(--text-secondary)] mt-1">
                {activeMacro.shortSummary}
              </p>
            </div>

            <div className="border border-[var(--border-subtle)] bg-[var(--bg-elevated)] p-3">
              <div className="text-[10px] font-mono uppercase text-[var(--text-muted)] mb-1">
                Macro Syntax &amp; Invocation Pattern
              </div>
              <code className="text-xs sm:text-sm font-mono text-amber-400 break-all">
                {activeMacro.syntax}
              </code>
            </div>
          </div>

          {/* 1. What Is It & Purpose */}
          <div className="border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5 space-y-3">
            <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-amber-400">
              <BookOpen className="w-4 h-4" />
              <span>1. What {activeMacro.name} Is &amp; Why It Exists</span>
            </div>
            <div className="space-y-3 text-sm text-[var(--text-secondary)] leading-relaxed">
              {activeMacro.whatIsItAndPurpose.map((p, idx) => (
                <p key={idx}>{p}</p>
              ))}
            </div>
          </div>

          {/* 2. Side-by-Side Preprocessor Expansion */}
          <div className="border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5 space-y-4">
            <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-cyan-400">
              <Sparkles className="w-4 h-4" />
              <span>2. Under-the-Hood Preprocessor Expansion (What You Write vs. What Clang Sees)</span>
            </div>

            <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
              <SyntaxHighlighter
                code={activeMacro.underTheHoodExpansion.whatYouWrite}
                language="c"
                title="1. Clean Macro Invocation (What You Write)"
                badgeText="High-Level eBPF C"
              />
              <SyntaxHighlighter
                code={activeMacro.underTheHoodExpansion.whatCompilerSees}
                language="c"
                title="2. Expanded C / Compiler Attributes (Under the Hood)"
                badgeText="Expanded Preprocessor Output"
              />
            </div>

            <div className="p-3.5 border border-cyan-500/30 bg-cyan-500/5 text-xs text-[var(--text-secondary)] leading-relaxed">
              <span className="font-mono font-bold text-cyan-400 uppercase mr-2">
                How the Expansion Works:
              </span>
              {activeMacro.underTheHoodExpansion.explanation}
            </div>
          </div>

          {/* 3. Why Use Instead Of Raw Code + 4. Verifier & Portability Notes */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5 space-y-3">
              <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-amber-400">
                <GitCompare className="w-4 h-4" />
                <span>3. Why Use {activeMacro.name} Instead Of Raw Code?</span>
              </div>
              <div className="p-3 border border-[var(--border-subtle)] bg-[var(--bg-elevated)] text-xs font-mono">
                <span className="text-[var(--text-muted)] uppercase block mb-0.5">
                  Fragile Raw Alternative:
                </span>
                <span className="text-rose-400 font-bold">
                  {activeMacro.whyUseInsteadOfRawCode.rawAlternative}
                </span>
              </div>
              <p className="text-sm text-[var(--text-secondary)] leading-relaxed">
                {activeMacro.whyUseInsteadOfRawCode.rationale}
              </p>
            </div>

            <div className="border border-emerald-500/30 bg-emerald-500/5 p-5 space-y-3">
              <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-emerald-400">
                <ShieldCheck className="w-4 h-4" />
                <span>4. Verifier &amp; Cross-Architecture Portability Rules</span>
              </div>
              <ul className="space-y-2.5 text-sm text-[var(--text-secondary)]">
                {activeMacro.verifierAndPortabilityNotes.map((note, idx) => (
                  <li key={idx} className="flex items-start gap-2.5">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <span>{note}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* 5. Complete C + Go Example */}
          <div className="border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-5 space-y-4">
            <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-cyan-400">
              <Code2 className="w-4 h-4" />
              <span>5. Complete Kernel C &amp; Go (cilium/ebpf) Reference Pattern</span>
            </div>
            <SyntaxHighlighter
              code={activeMacro.cAndGoExample}
              language="c"
              title={`${activeMacro.id}_reference.bpf.c`}
              badgeText="C + Go cilium/ebpf Pattern"
            />
          </div>
        </div>
      </div>
    </div>
  );
};
