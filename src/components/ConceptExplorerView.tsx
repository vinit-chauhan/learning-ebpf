import React, { useState } from 'react';
import {
  BookOpen,
  CheckCircle2,
  ChevronRight,
  Cpu,
  Layers,
  Play,
  Search,
  ShieldCheck,
  Terminal,
  ArrowRight,
  HelpCircle,
  Check,
  X
} from 'lucide-react';
import { CONCEPT_TOPICS } from '../data/conceptsData';
import { ConceptCategory, ConceptTopic } from '../types/ebpf';
import { SyntaxHighlighter } from './SyntaxHighlighter';

interface ConceptExplorerViewProps {
  completedConcepts: string[];
  onToggleConceptComplete: (id: string) => void;
  onOpenTutorial: (tutorialId: string) => void;
  onOpenSimulatorPreset: (presetId: string) => void;
}

interface ArchNode {
  id: string;
  space: 'USERSPACE' | 'BOUNDARY' | 'KERNEL';
  title: string;
  subtitle: string;
  latencyOrLimit: string;
  description: string;
  registersOrStructs: string[];
}

const ARCH_NODES: ArchNode[] = [
  {
    id: 'go-loader',
    space: 'USERSPACE',
    title: '01. Go Control Plane (cilium/ebpf)',
    subtitle: 'bpf2go · ELF Loader · RingBuf Reader',
    latencyOrLimit: 'Pure Go (CGO_ENABLED=0)',
    description:
      'Parses the compiled Clang ELF .o bytecode embedded in the Go binary, compares .BTF.ext field relocations against the host /sys/kernel/btf/vmlinux, and manages program & map file descriptors.',
    registersOrStructs: [
      'ebpf.CollectionSpec (ELF parser)',
      'link.Tracepoint / link.AttachXDP / link.Kprobe',
      'ringbuf.NewReader(objs.Events)'
    ]
  },
  {
    id: 'bpf-syscall',
    space: 'BOUNDARY',
    title: '02. bpf() System Call Boundary',
    subtitle: 'BPF_MAP_CREATE · BPF_PROG_LOAD',
    latencyOrLimit: 'CAP_BPF + CAP_PERFMON / CAP_NET_ADMIN',
    description:
      'The single multiplexed Linux system call that creates persistent BPF maps in kernel memory, submits relocated eBPF instructions for verification, and returns anonymous file descriptors.',
    registersOrStructs: [
      'union bpf_attr (syscall payload)',
      'BPF_MAP_CREATE -> map_fd',
      'BPF_PROG_LOAD -> prog_fd'
    ]
  },
  {
    id: 'verifier-jit',
    space: 'KERNEL',
    title: '03. eBPF Static Verifier & Native JIT',
    subtitle: 'CFG DAG Check · Register Bounds · x86_64/ARM64 JIT',
    latencyOrLimit: 'Max 1M Verified Insns · 512B Stack',
    description:
      'Simulates every possible branch path before attachment. Rejects unbounded loops, out-of-bounds packet reads, and unchecked NULL map pointers. Once verified, the JIT compiles bytecode into native CPU instructions.',
    registersOrStructs: [
      'R0: return value & helper result',
      'R1–R5: helper arguments (scratch)',
      'R6–R9: callee-saved registers',
      'R10: read-only 512B stack frame pointer'
    ]
  },
  {
    id: 'kernel-hooks',
    space: 'KERNEL',
    title: '04. Kernel Hook Points',
    subtitle: 'XDP · TC · Kprobe · Tracepoint · Uprobe · LSM',
    latencyOrLimit: '15–80ns Execution Time',
    description:
      'Event-driven attachment points inside the NIC driver (XDP), networking stack (TC), kernel functions (kprobes/fentry), stable events (tracepoints), userspace binaries (uprobes), or VFS security hooks (LSM).',
    registersOrStructs: [
      'struct xdp_md (XDP raw packet)',
      'struct __sk_buff (TC socket buffer)',
      'struct pt_regs (Kprobe/Uprobe CPU regs)',
      'struct file / inode (BPF LSM objects)'
    ]
  },
  {
    id: 'bpf-maps',
    space: 'KERNEL',
    title: '05. BPF Maps & Ring Buffers',
    subtitle: 'Per-CPU Array · LRU Hash · MPSC RingBuf',
    latencyOrLimit: 'Zero-Copy Shared Memory',
    description:
      'Persistent in-kernel data structures that aggregate metrics without context switches (Hash, Per-CPU Array, LPM Trie) or stream globally ordered binary event records to Go via memory-mapped Ring Buffers.',
    registersOrStructs: [
      'BPF_MAP_TYPE_RINGBUF (MPSC event queue)',
      'BPF_MAP_TYPE_PERCPU_ARRAY (L1 cache local)',
      'BPF_MAP_TYPE_LRU_HASH (auto-evicting state)',
      'BPF_MAP_TYPE_LPM_TRIE (CIDR subnet matcher)'
    ]
  }
];

const CATEGORIES: ('All' | ConceptCategory)[] = [
  'All',
  'Foundations & Architecture',
  'Kernel Hook Subsystems',
  'BPF Maps & Ring Buffers',
  'Verifier, JIT & CO-RE',
  'Go cilium/ebpf Control Plane'
];

export const ConceptExplorerView: React.FC<ConceptExplorerViewProps> = ({
  completedConcepts,
  onToggleConceptComplete,
  onOpenTutorial,
  onOpenSimulatorPreset
}) => {
  const [selectedCategory, setSelectedCategory] = useState<'All' | ConceptCategory>('All');
  const [searchQuery, setSearchQuery] = useState('');
  const [activeTopicId, setActiveTopicId] = useState<string>(CONCEPT_TOPICS[0].id);
  const [activeArchNodeId, setActiveArchNodeId] = useState<string>(ARCH_NODES[2].id);
  const [activeSectionTab, setActiveSectionTab] = useState<'all' | 'what' | 'how' | 'why'>('all');
  const [quizAnswers, setQuizAnswers] = useState<Record<string, number>>({});

  const filteredTopics = CONCEPT_TOPICS.filter((t) => {
    const matchesCat = selectedCategory === 'All' || t.category === selectedCategory;
    const q = searchQuery.trim().toLowerCase();
    const matchesSearch =
      !q ||
      t.title.toLowerCase().includes(q) ||
      t.subtitle.toLowerCase().includes(q) ||
      t.summary.toLowerCase().includes(q) ||
      t.whyUseInsteadOf.alternativeTech.toLowerCase().includes(q);
    return matchesCat && matchesSearch;
  });

  const activeTopic: ConceptTopic =
    CONCEPT_TOPICS.find((t) => t.id === activeTopicId) || CONCEPT_TOPICS[0];

  const activeArchNode =
    ARCH_NODES.find((n) => n.id === activeArchNodeId) || ARCH_NODES[0];

  const selectedQuizOption = quizAnswers[activeTopic.id];
  const isQuizCorrect = selectedQuizOption === activeTopic.comprehensionCheck.correctIndex;
  const isCompleted = completedConcepts.includes(activeTopic.id);

  return (
    <div className="space-y-8">
      {/* Interactive End-to-End Architecture Flow Banner */}
      <section className="border border-slate-200 dark:border-slate-800 rounded-xl bg-white dark:bg-[#111827] p-6">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 pb-5 border-b border-slate-200 dark:border-slate-800">
          <div>
            <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400 mb-1">
              <span>Interactive Mental Model</span>
              <span aria-hidden="true">·</span>
              <span>User Space vs. Linux Kernel Execution Flow</span>
              <span aria-hidden="true">·</span>
              <span>Click any subsystem node to inspect internals</span>
            </div>
            <h2 className="text-xl font-semibold text-slate-900 dark:text-slate-100">
              How eBPF Bridges Go User Space and the Linux Kernel
            </h2>
          </div>
          <div className="flex items-center gap-3 text-xs font-mono tabular-nums text-slate-600 dark:text-slate-400">
            <span>
              Completed Chapters: <strong className="text-slate-900 dark:text-white">{completedConcepts.length}/{CONCEPT_TOPICS.length}</strong>
            </span>
          </div>
        </div>

        {/* 5-Stage Interactive Pipeline Nodes */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-3 mt-5">
          {ARCH_NODES.map((node, index) => {
            const isSelected = node.id === activeArchNodeId;
            return (
              <button
                key={node.id}
                onClick={() => setActiveArchNodeId(node.id)}
                className={`text-left p-3.5 rounded-lg border transition-all relative ${
                  isSelected
                    ? 'border-sky-500 bg-sky-500/8 dark:bg-sky-500/12'
                    : 'border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 bg-slate-50/60 dark:bg-slate-900/50'
                }`}
              >
                <div className="flex items-center justify-between text-[11px] font-mono mb-1.5">
                  <span
                    className={
                      node.space === 'USERSPACE'
                        ? 'text-amber-600 dark:text-amber-400 font-semibold'
                        : node.space === 'BOUNDARY'
                        ? 'text-purple-600 dark:text-purple-400 font-semibold'
                        : 'text-sky-600 dark:text-sky-400 font-semibold'
                    }
                  >
                    [{node.space}]
                  </span>
                  {index < ARCH_NODES.length - 1 && (
                    <ArrowRight className="w-3.5 h-3.5 text-slate-400 hidden md:block" />
                  )}
                </div>
                <div className="text-xs font-semibold text-slate-900 dark:text-slate-100 mb-1">
                  {node.title}
                </div>
                <div className="text-[11px] text-slate-500 dark:text-slate-400">
                  {node.subtitle}
                </div>
              </button>
            );
          })}
        </div>

        {/* Selected Node Technical Inspector */}
        <div className="mt-4 pt-4 border-t border-slate-200 dark:border-slate-800 grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          <div className="lg:col-span-7 space-y-2">
            <div className="flex items-center gap-2 text-xs font-mono text-sky-600 dark:text-sky-400">
              <span>Selected Subsystem: {activeArchNode.title}</span>
              <span aria-hidden="true">·</span>
              <span>{activeArchNode.latencyOrLimit}</span>
            </div>
            <p className="text-sm text-slate-700 dark:text-slate-300 leading-relaxed">
              {activeArchNode.description}
            </p>
          </div>
          <div className="lg:col-span-5 bg-slate-50 dark:bg-[#0B0F17] border border-slate-200 dark:border-slate-800 rounded-lg p-3.5">
            <div className="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2 font-mono">
              Key Kernel Constructs & Registers
            </div>
            <ul className="space-y-1 text-xs font-mono text-slate-600 dark:text-slate-400">
              {activeArchNode.registersOrStructs.map((item, idx) => (
                <li key={idx} className="flex items-center gap-2">
                  <span className="text-sky-500">→</span>
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </section>

      {/* Filter Bar & Search */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-x-auto">
          {CATEGORIES.map((cat) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                selectedCategory === cat
                  ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>

        <div className="relative w-full md:w-72">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search XDP, CO-RE, Verifier, RingBuf..."
            className="w-full pl-9 pr-3 py-1.5 text-xs bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg text-slate-900 dark:text-slate-100 placeholder:text-slate-400 focus:outline-none focus:border-sky-500"
          />
        </div>
      </div>

      {/* Main Encyclopedia Split Layout: Sidebar Chapters + Deep-Dive Reader */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* Left Chapter List (4 cols) */}
        <div className="lg:col-span-4 space-y-2">
          <div className="text-xs font-semibold text-slate-500 dark:text-slate-400 px-1 mb-2">
            Concept Reference Chapters ({filteredTopics.length})
          </div>
          {filteredTopics.map((topic) => {
            const isSelected = topic.id === activeTopic.id;
            const done = completedConcepts.includes(topic.id);
            return (
              <button
                key={topic.id}
                onClick={() => setActiveTopicId(topic.id)}
                className={`w-full text-left p-4 rounded-xl border transition-all ${
                  isSelected
                    ? 'border-sky-500 bg-white dark:bg-[#111827] shadow-xs'
                    : 'border-slate-200 dark:border-slate-800/80 bg-slate-50/50 dark:bg-slate-900/40 hover:bg-white dark:hover:bg-[#111827]'
                }`}
              >
                <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 mb-1 font-mono tabular-nums">
                  <span>
                    Chapter {topic.index} · {topic.readTime}
                  </span>
                  {done && (
                    <span className="text-emerald-600 dark:text-emerald-400 font-medium flex items-center gap-1">
                      <Check className="w-3.5 h-3.5" /> Read
                    </span>
                  )}
                </div>
                <div className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-1">
                  {topic.title}
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-400 line-clamp-2">
                  {topic.subtitle}
                </p>
              </button>
            );
          })}
        </div>

        {/* Right Deep-Dive Concept Article Reader (8 cols) */}
        <article className="lg:col-span-8 border border-slate-200 dark:border-slate-800 rounded-xl bg-white dark:bg-[#111827] p-6 lg:p-8 space-y-8">
          {/* Article Header */}
          <div className="border-b border-slate-200 dark:border-slate-800 pb-6 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 dark:text-slate-400 font-mono">
              <div className="flex items-center gap-2">
                <span>Chapter {activeTopic.index}</span>
                <span aria-hidden="true">·</span>
                <span>{activeTopic.category}</span>
                <span aria-hidden="true">·</span>
                <span>{activeTopic.minKernel}</span>
                <span aria-hidden="true">·</span>
                <span>{activeTopic.readTime}</span>
              </div>
              <button
                onClick={() => onToggleConceptComplete(activeTopic.id)}
                className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-sans font-medium border transition-colors whitespace-nowrap shrink-0 ${
                  isCompleted
                    ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
                    : 'border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:border-slate-400'
                }`}
              >
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>{isCompleted ? 'Completed Chapter' : 'Mark as Read'}</span>
              </button>
            </div>

            <h1 className="text-2xl lg:text-3xl font-bold text-slate-900 dark:text-white tracking-tight">
              {activeTopic.title}
            </h1>
            <p className="text-base text-slate-600 dark:text-slate-300 leading-relaxed">
              {activeTopic.summary}
            </p>

            {/* Quick Section Jump Filter */}
            <div className="flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-900 rounded-lg w-fit">
              {[
                { id: 'all', label: 'Full Read-Through' },
                { id: 'what', label: '1. What is X?' },
                { id: 'how', label: '2. How X Works' },
                { id: 'why', label: '3. Why Use X Instead of Y?' }
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveSectionTab(tab.id as any)}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                    activeSectionTab === tab.id
                      ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          </div>

          {/* SECTION 1: WHAT IS X? */}
          {(activeSectionTab === 'all' || activeSectionTab === 'what') && (
            <section className="space-y-4">
              <div className="text-xs font-mono text-sky-600 dark:text-sky-400 font-semibold">
                01. Conceptual Foundation — What is It?
              </div>
              <h2 className="text-xl font-semibold text-slate-900 dark:text-white">
                {activeTopic.whatIsIt.heading}
              </h2>
              <div className="space-y-3 text-[15px] text-slate-700 dark:text-slate-300 leading-relaxed">
                {activeTopic.whatIsIt.paragraphs.map((p, i) => (
                  <p key={i}>{p}</p>
                ))}
              </div>

              {/* Mental Model Box */}
              <div className="p-4 rounded-lg bg-slate-50 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 space-y-1.5">
                <div className="text-xs font-semibold text-slate-900 dark:text-slate-200">
                  Systems Engineering Mental Model
                </div>
                <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
                  {activeTopic.whatIsIt.mentalModelAnalogy}
                </p>
              </div>

              {/* Key Takeaways */}
              <div className="space-y-2 pt-2">
                <div className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                  Core Architectural Facts
                </div>
                <ul className="space-y-2">
                  {activeTopic.whatIsIt.keyTakeaways.map((item, idx) => (
                    <li
                      key={idx}
                      className="flex items-start gap-2.5 text-sm text-slate-700 dark:text-slate-300"
                    >
                      <span className="text-sky-500 font-mono font-bold mt-0.5">•</span>
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </section>
          )}

          {/* SECTION 2: HOW X WORKS UNDER THE HOOD */}
          {(activeSectionTab === 'all' || activeSectionTab === 'how') && (
            <section className="space-y-5 pt-4 border-t border-slate-200 dark:border-slate-800">
              <div className="text-xs font-mono text-sky-600 dark:text-sky-400 font-semibold">
                02. Internal Mechanics — How It Works
              </div>
              <h2 className="text-xl font-semibold text-slate-900 dark:text-white">
                {activeTopic.howItWorks.heading}
              </h2>
              <div className="space-y-3 text-[15px] text-slate-700 dark:text-slate-300 leading-relaxed">
                {activeTopic.howItWorks.paragraphs.map((p, i) => (
                  <p key={i}>{p}</p>
                ))}
              </div>

              {/* Step-by-step Execution Pipeline */}
              <div className="space-y-2.5">
                <div className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                  Step-by-Step Execution Lifecycle
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {activeTopic.howItWorks.lifecycleSteps.map((ls) => (
                    <div
                      key={ls.step}
                      className="p-3.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-900/50 space-y-1"
                    >
                      <div className="flex items-center justify-between text-xs font-mono">
                        <span className="font-semibold text-slate-900 dark:text-white">
                          Step {ls.step}: {ls.title}
                        </span>
                        <span className="text-sky-600 dark:text-sky-400">[{ls.actor}]</span>
                      </div>
                      <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                        {ls.detail}
                      </p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Syntax Highlighted Code Example */}
              <div className="pt-2">
                <SyntaxHighlighter
                  code={activeTopic.howItWorks.codeSnippet}
                  language={activeTopic.howItWorks.codeLanguage}
                  title={activeTopic.howItWorks.codeTitle}
                  badgeText={activeTopic.howItWorks.codeLanguage === 'c' ? 'Kernel eBPF C' : 'Userspace Go (cilium/ebpf)'}
                />
              </div>
            </section>
          )}

          {/* SECTION 3: WHY DO WE USE X INSTEAD OF Y? */}
          {(activeSectionTab === 'all' || activeSectionTab === 'why') && (
            <section className="space-y-5 pt-4 border-t border-slate-200 dark:border-slate-800">
              <div className="text-xs font-mono text-amber-600 dark:text-amber-400 font-semibold">
                03. Architectural Trade-Offs — Why Use X Instead of Y?
              </div>
              <h2 className="text-xl font-semibold text-slate-900 dark:text-white">
                {activeTopic.whyUseInsteadOf.heading}
              </h2>
              <div className="space-y-3 text-[15px] text-slate-700 dark:text-slate-300 leading-relaxed">
                {activeTopic.whyUseInsteadOf.rationaleParagraphs.map((p, i) => (
                  <p key={i}>{p}</p>
                ))}
              </div>

              {/* Quantitative Comparison Table */}
              <div className="border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="bg-slate-100 dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300">
                      <th className="py-2.5 px-4 font-semibold">Engineering Dimension</th>
                      <th className="py-2.5 px-4 font-semibold text-sky-700 dark:text-sky-400">
                        {activeTopic.whyUseInsteadOf.primaryTech}
                      </th>
                      <th className="py-2.5 px-4 font-semibold text-slate-600 dark:text-slate-400">
                        {activeTopic.whyUseInsteadOf.alternativeTech}
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200 dark:divide-slate-800 tabular-nums">
                    {activeTopic.whyUseInsteadOf.comparisonTable.map((row, idx) => (
                      <tr key={idx} className="hover:bg-slate-50 dark:hover:bg-slate-900/40">
                        <td className="py-3 px-4 font-medium text-slate-900 dark:text-slate-200">
                          {row.dimension}
                        </td>
                        <td className="py-3 px-4 text-slate-700 dark:text-slate-300">
                          {row.winner === 'primary' && (
                            <span className="text-emerald-600 dark:text-emerald-400 font-mono mr-1">
                              ✓
                            </span>
                          )}
                          {row.primaryChoice}
                        </td>
                        <td className="py-3 px-4 text-slate-600 dark:text-slate-400">
                          {row.winner === 'alternative' && (
                            <span className="text-emerald-600 dark:text-emerald-400 font-mono mr-1">
                              ✓
                            </span>
                          )}
                          {row.alternativeChoice}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* When to Choose Which */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-900/40 space-y-2">
                  <div className="text-xs font-semibold text-emerald-700 dark:text-emerald-400">
                    When to Choose {activeTopic.whyUseInsteadOf.primaryTech}
                  </div>
                  <ul className="space-y-1.5 text-xs text-slate-700 dark:text-slate-300">
                    {activeTopic.whyUseInsteadOf.whenToUsePrimary.map((w, i) => (
                      <li key={i} className="flex items-start gap-2">
                        <span className="text-emerald-500 font-bold">✓</span>
                        <span>{w}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-900/40 space-y-2">
                  <div className="text-xs font-semibold text-amber-700 dark:text-amber-400">
                    When {activeTopic.whyUseInsteadOf.alternativeTech} Fits Better
                  </div>
                  <ul className="space-y-1.5 text-xs text-slate-700 dark:text-slate-300">
                    {activeTopic.whyUseInsteadOf.whenToUseAlternative.map((w, i) => (
                      <li key={i} className="flex items-start gap-2">
                        <span className="text-amber-500 font-bold">→</span>
                        <span>{w}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </section>
          )}

          {/* SECTION 4: INTERACTIVE COMPREHENSION CHECK & NEXT ACTIONS */}
          <section className="pt-6 border-t border-slate-200 dark:border-slate-800 space-y-4">
            <div className="p-5 rounded-xl bg-slate-50 dark:bg-[#0B0F17] border border-slate-200 dark:border-slate-800 space-y-4">
              <div className="flex items-center gap-2 text-xs font-mono text-sky-600 dark:text-sky-400">
                <HelpCircle className="w-4 h-4" />
                <span>Interactive Concept Check</span>
              </div>
              <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
                {activeTopic.comprehensionCheck.question}
              </h3>
              <div className="space-y-2">
                {activeTopic.comprehensionCheck.options.map((opt, idx) => {
                  const isPicked = selectedQuizOption === idx;
                  const isRight = idx === activeTopic.comprehensionCheck.correctIndex;
                  return (
                    <button
                      key={idx}
                      onClick={() => {
                        setQuizAnswers((prev) => ({ ...prev, [activeTopic.id]: idx }));
                        if (idx === activeTopic.comprehensionCheck.correctIndex && !isCompleted) {
                          onToggleConceptComplete(activeTopic.id);
                        }
                      }}
                      className={`w-full text-left p-3 rounded-lg border text-xs transition-colors flex items-start justify-between gap-3 ${
                        isPicked
                          ? isRight
                            ? 'border-emerald-500 bg-emerald-500/10 text-slate-900 dark:text-white'
                            : 'border-red-500 bg-red-500/10 text-slate-900 dark:text-white'
                          : 'border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 text-slate-700 dark:text-slate-300'
                      }`}
                    >
                      <span>{opt}</span>
                      {isPicked && (
                        <span className="shrink-0 font-mono font-semibold">
                          {isRight ? '✓ Correct' : '✕ Try Again'}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>

              {selectedQuizOption !== undefined && (
                <div
                  className={`p-3 rounded-lg text-xs leading-relaxed ${
                    isQuizCorrect
                      ? 'bg-emerald-500/10 text-emerald-800 dark:text-emerald-300 border border-emerald-500/30'
                      : 'bg-amber-500/10 text-amber-800 dark:text-amber-300 border border-amber-500/30'
                  }`}
                >
                  <strong>Explanation:</strong> {activeTopic.comprehensionCheck.explanation}
                </div>
              )}
            </div>

            {/* Hands-on Action Buttons */}
            <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
              <div className="flex items-center gap-3">
                <button
                  onClick={() => onOpenTutorial(activeTopic.relatedTutorialId)}
                  className="px-4 py-2 text-xs font-medium text-white bg-sky-600 hover:bg-sky-500 rounded-lg transition-colors flex items-center gap-2 whitespace-nowrap shrink-0"
                >
                  <BookOpen className="w-3.5 h-3.5" />
                  <span>Practice in Guided Tutorial</span>
                </button>
                <button
                  onClick={() => onOpenSimulatorPreset(activeTopic.simulatorPresetId)}
                  className="px-4 py-2 text-xs font-medium text-slate-700 dark:text-slate-200 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-lg transition-colors flex items-center gap-2 whitespace-nowrap shrink-0"
                >
                  <Play className="w-3.5 h-3.5" />
                  <span>Open in Live Kernel Simulator</span>
                </button>
              </div>
            </div>
          </section>
        </article>
      </div>
    </div>
  );
};
