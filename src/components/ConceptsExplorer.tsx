import React, { useState } from 'react';
import {
  BookOpen,
  CheckCircle2,
  ChevronRight,
  Cpu,
  Layers,
  Play,
  HelpCircle,
  ArrowRight,
  Search
} from 'lucide-react';
import { CONCEPT_TOPICS } from '../data/conceptsData';
import { ConceptCategory, ConceptTopic } from '../types/ebpf';
import { SyntaxHighlighter } from './SyntaxHighlighter';

interface ConceptsExplorerProps {
  completedTopicIds: string[];
  onMarkTopicCompleted: (topicId: string) => void;
  onOpenTutorial: (tutorialId: string) => void;
  onOpenSimulatorPreset: (presetId: string) => void;
}

const CATEGORIES: ('All' | ConceptCategory)[] = [
  'All',
  'Foundations & Architecture',
  'Kernel Hook Subsystems',
  'BPF Maps & Ring Buffers',
  'Verifier, JIT & CO-RE',
  'Go cilium/ebpf Control Plane'
];

const KERNEL_HOOK_MAP = [
  {
    id: 'XDP',
    name: 'XDP (eXpress Data Path)',
    space: 'NIC Driver RX Queue',
    latency: '~15–25 ns',
    verdictCapable: 'Yes (XDP_DROP, XDP_PASS, XDP_TX, XDP_REDIRECT)',
    contextStruct: 'struct xdp_md *ctx',
    useCase: 'Line-rate DDoS scrubbing, L4 load balancing before sk_buff allocation.'
  },
  {
    id: 'TC',
    name: 'TC (Traffic Control / TCX)',
    space: 'L2/L3 Stack (Ingress & Egress)',
    latency: '~35–60 ns',
    verdictCapable: 'Yes (TC_ACT_OK, TC_ACT_SHOT, TC_ACT_REDIRECT)',
    contextStruct: 'struct __sk_buff *skb',
    useCase: 'Kubernetes CNI pod policy, Egress filtering, packet QoS marking.'
  },
  {
    id: 'tracepoint',
    name: 'Static Tracepoints',
    space: 'Syscalls, Scheduler, VFS, Block I/O',
    latency: '~30–45 ns',
    verdictCapable: 'Observational only (Read-only)',
    contextStruct: 'struct trace_event_raw_*',
    useCase: 'Stable cross-kernel auditing of syscalls (execve, openat) and scheduler switches.'
  },
  {
    id: 'kprobe',
    name: 'Kprobes / Kretprobes / Fentry',
    space: 'Any Kernel Function (~70,000 symbols)',
    latency: '~25 ns (fentry) / ~90 ns (kprobe)',
    verdictCapable: 'Observational (unless paired with error injection)',
    contextStruct: 'struct pt_regs *ctx',
    useCase: 'Measuring internal kernel function latency (e.g., tcp_v4_connect).'
  },
  {
    id: 'uprobe',
    name: 'Uprobes / Uretprobes',
    space: 'Userspace Binaries & Shared Libraries',
    latency: '~800–1,800 ns (User→Kernel Trap)',
    verdictCapable: 'Observational',
    contextStruct: 'struct pt_regs *ctx',
    useCase: 'Plaintext TLS capture (libssl.so SSL_write), Go/C heap profiling, bash auditing.'
  },
  {
    id: 'lsm',
    name: 'BPF LSM (Security Modules)',
    space: 'Kernel Security Enforcement Gatekeepers',
    latency: '~30–50 ns',
    verdictCapable: 'Yes (Return -EPERM to block inline)',
    contextStruct: 'BTF Typed Kernel Objects (struct file *)',
    useCase: 'TOCTOU-immune container escape prevention and mandatory access control.'
  }
];

export const ConceptsExplorer: React.FC<ConceptsExplorerProps> = ({
  completedTopicIds,
  onMarkTopicCompleted,
  onOpenTutorial,
  onOpenSimulatorPreset
}) => {
  const [selectedCategory, setSelectedCategory] = useState<'All' | ConceptCategory>('All');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTopicId, setSelectedTopicId] = useState<string>(CONCEPT_TOPICS[0].id);
  const [activeReadTab, setActiveReadTab] = useState<'what' | 'how' | 'why' | 'quiz'>('what');
  const [activeLifecycleStep, setActiveLifecycleStep] = useState<number>(0);
  const [selectedQuizOption, setSelectedQuizOption] = useState<Record<string, number>>({});
  const [selectedHookId, setSelectedHookId] = useState<string>('XDP');

  const filteredTopics = CONCEPT_TOPICS.filter((topic) => {
    const matchesCategory = selectedCategory === 'All' || topic.category === selectedCategory;
    const q = searchQuery.trim().toLowerCase();
    const matchesSearch =
      !q ||
      topic.title.toLowerCase().includes(q) ||
      topic.subtitle.toLowerCase().includes(q) ||
      topic.summary.toLowerCase().includes(q) ||
      topic.whyUseInsteadOf.primaryTech.toLowerCase().includes(q) ||
      topic.whyUseInsteadOf.alternativeTech.toLowerCase().includes(q);
    return matchesCategory && matchesSearch;
  });

  const activeTopic: ConceptTopic =
    CONCEPT_TOPICS.find((t) => t.id === selectedTopicId) || CONCEPT_TOPICS[0];

  const handleSelectTopic = (topicId: string) => {
    setSelectedTopicId(topicId);
    setActiveLifecycleStep(0);
  };

  const currentLifecycleSteps = activeTopic.howItWorks.lifecycleSteps;
  const clampedStepIdx = Math.min(activeLifecycleStep, currentLifecycleSteps.length - 1);
  const currentStepObj = currentLifecycleSteps[clampedStepIdx];

  const chosenQuizIndex = selectedQuizOption[activeTopic.id];
  const isQuizCorrect = chosenQuizIndex === activeTopic.comprehensionCheck.correctIndex;

  const selectedHook =
    KERNEL_HOOK_MAP.find((h) => h.id === selectedHookId) || KERNEL_HOOK_MAP[0];

  return (
    <div className="space-y-8">
      {/* Top Interactive Architecture Overview Banner */}
      <section className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-6 border-b border-slate-200 dark:border-slate-800">
          <div>
            <div className="text-xs font-medium text-sky-600 dark:text-sky-400">
              Interactive Architecture & Encyclopedia · 12 Deep-Dive Chapters
            </div>
            <h1 className="text-2xl sm:text-3xl font-semibold text-slate-900 dark:text-slate-100 mt-1">
              Linux eBPF Mental Models, Internals & Architectural Trade-Offs
            </h1>
            <p className="text-sm text-slate-600 dark:text-slate-400 mt-1 max-w-3xl">
              Explore how eBPF programs cross from Go userspace into the Linux kernel, inspect hook execution points from the NIC driver to the syscall boundary, and study every core concept through structured <strong>What is X?</strong>, <strong>How X Works</strong>, and <strong>Why Use X Instead of Y?</strong> guides.
            </p>
          </div>
          <div className="flex items-center gap-3 shrink-0">
            <div className="text-right">
              <div className="text-xs text-slate-500 dark:text-slate-400">Encyclopedia Mastery</div>
              <div className="text-sm font-mono font-semibold text-slate-900 dark:text-slate-100 tabular-nums">
                {completedTopicIds.length} / {CONCEPT_TOPICS.length} Chapters Completed
              </div>
            </div>
          </div>
        </div>

        {/* Interactive Kernel Hook Subsystem Pipeline */}
        <div className="mt-6">
          <div className="flex items-center justify-between gap-4 mb-3">
            <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              Interactive Linux Kernel Hook Pipeline (Click any subsystem to inspect execution context)
            </h2>
            <span className="text-xs text-slate-500 dark:text-slate-400">
              User Space (Go cilium/ebpf) ↔ Kernel Space (Verified JIT Bytecode)
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5">
            {KERNEL_HOOK_MAP.map((hook, idx) => {
              const isSelected = hook.id === selectedHookId;
              return (
                <button
                  key={hook.id}
                  type="button"
                  onClick={() => setSelectedHookId(hook.id)}
                  className={`text-left p-3 rounded-lg border transition-all ${
                    isSelected
                      ? 'border-sky-500 bg-sky-50/70 dark:bg-sky-950/40'
                      : 'border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-950/60 hover:border-slate-300 dark:hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 dark:text-slate-400">
                    <span>0{idx + 1}. HOOK</span>
                    <span className="tabular-nums">{hook.latency}</span>
                  </div>
                  <div className="font-semibold text-xs text-slate-900 dark:text-slate-100 mt-1 truncate">
                    {hook.name}
                  </div>
                  <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5 truncate">
                    {hook.space}
                  </div>
                </button>
              );
            })}
          </div>

          {/* Selected Hook Detail Bar */}
          <div className="mt-3 p-4 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 grid grid-cols-1 md:grid-cols-4 gap-4 text-xs">
            <div>
              <span className="text-slate-500 dark:text-slate-400 block">Selected Hook Point</span>
              <span className="font-semibold text-slate-900 dark:text-slate-100 mt-0.5 block">
                {selectedHook.name} ({selectedHook.space})
              </span>
            </div>
            <div>
              <span className="text-slate-500 dark:text-slate-400 block">C Context Argument</span>
              <code className="font-mono text-sky-600 dark:text-sky-400 mt-0.5 block">
                {selectedHook.contextStruct}
              </code>
            </div>
            <div>
              <span className="text-slate-500 dark:text-slate-400 block">Inline Drop / Block Capable?</span>
              <span className="font-medium text-slate-800 dark:text-slate-200 mt-0.5 block">
                {selectedHook.verdictCapable}
              </span>
            </div>
            <div>
              <span className="text-slate-500 dark:text-slate-400 block">Primary Production Use Case</span>
              <span className="text-slate-700 dark:text-slate-300 mt-0.5 block">
                {selectedHook.useCase}
              </span>
            </div>
          </div>
        </div>
      </section>

      {/* Category Filter & Search Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-1.5 p-1 rounded-lg bg-slate-200/70 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 overflow-x-auto">
          {CATEGORIES.map((category) => (
            <button
              key={category}
              type="button"
              onClick={() => setSelectedCategory(category)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                selectedCategory === category
                  ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
              }`}
            >
              {category}
            </button>
          ))}
        </div>

        <div className="relative w-full md:w-72 shrink-0">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search concepts (e.g. RingBuf, CO-RE, LSM)..."
            className="w-full pl-9 pr-3 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 placeholder:text-slate-400 focus:outline-none focus:border-sky-500"
          />
        </div>
      </div>

      {/* Main Encyclopedia Split Layout: Left Chapter Index (32%) + Right Read-Through Study Reader (68%) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Chapter List */}
        <div className="lg:col-span-4 space-y-2">
          {filteredTopics.map((topic) => {
            const isSelected = topic.id === activeTopic.id;
            const isCompleted = completedTopicIds.includes(topic.id);

            return (
              <button
                key={topic.id}
                type="button"
                onClick={() => handleSelectTopic(topic.id)}
                className={`w-full text-left p-4 rounded-xl border transition-all ${
                  isSelected
                    ? 'border-sky-500 bg-white dark:bg-slate-900 shadow-xs'
                    : 'border-slate-200 dark:border-slate-800 bg-white/60 dark:bg-slate-900/50 hover:border-slate-300 dark:hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between gap-2 text-xs text-slate-500 dark:text-slate-400">
                  <div className="flex items-center gap-1.5 truncate">
                    <span className="font-mono font-semibold text-sky-600 dark:text-sky-400">
                      Chapter {topic.index}
                    </span>
                    <span aria-hidden="true">·</span>
                    <span className="truncate">{topic.readTime}</span>
                    <span aria-hidden="true">·</span>
                    <span className="font-mono text-[11px]">{topic.minKernel}</span>
                  </div>
                  {isCompleted && (
                    <span className="text-emerald-600 dark:text-emerald-400 font-medium flex items-center gap-1 shrink-0">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Read</span>
                    </span>
                  )}
                </div>

                <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mt-1.5 leading-snug">
                  {topic.title}
                </h3>

                <p className="text-xs text-slate-600 dark:text-slate-400 mt-1 line-clamp-2">
                  {topic.subtitle}
                </p>

                <div className="mt-2.5 pt-2 border-t border-slate-100 dark:border-slate-800/80 flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400">
                  <span>
                    Why <strong>{topic.whyUseInsteadOf.primaryTech}</strong> vs.{' '}
                    {topic.whyUseInsteadOf.alternativeTech}
                  </span>
                  <ChevronRight className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                </div>
              </button>
            );
          })}
        </div>

        {/* Right Study Reader */}
        <div className="lg:col-span-8 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden">
          {/* Chapter Header */}
          <div className="p-6 border-b border-slate-200 dark:border-slate-800">
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 dark:text-slate-400">
              <div className="flex items-center gap-2">
                <span className="font-mono font-semibold text-sky-600 dark:text-sky-400">
                  Chapter {activeTopic.index}
                </span>
                <span aria-hidden="true">·</span>
                <span>{activeTopic.category}</span>
                <span aria-hidden="true">·</span>
                <span>{activeTopic.readTime}</span>
                <span aria-hidden="true">·</span>
                <span className="font-mono">{activeTopic.minKernel}</span>
              </div>

              <button
                type="button"
                onClick={() => onMarkTopicCompleted(activeTopic.id)}
                className={`px-3 py-1 rounded text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                  completedTopicIds.includes(activeTopic.id)
                    ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30'
                    : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700'
                }`}
              >
                {completedTopicIds.includes(activeTopic.id)
                  ? '✓ Completed Chapter'
                  : 'Mark Chapter Complete'}
              </button>
            </div>

            <h2 className="text-2xl font-semibold text-slate-900 dark:text-slate-100 mt-2">
              {activeTopic.title}
            </h2>
            <p className="text-sm text-slate-600 dark:text-slate-300 mt-1.5 leading-relaxed">
              {activeTopic.summary}
            </p>

            {/* Sub-Navigation Segmented Control for Read-Through Sections */}
            <div className="mt-5 flex items-center gap-1 p-1 rounded-lg bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 overflow-x-auto">
              <button
                type="button"
                onClick={() => setActiveReadTab('what')}
                className={`flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                  activeReadTab === 'what'
                    ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                <BookOpen className="w-3.5 h-3.5 text-sky-500" />
                <span>1. What Is It?</span>
              </button>
              <button
                type="button"
                onClick={() => setActiveReadTab('how')}
                className={`flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                  activeReadTab === 'how'
                    ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                <Cpu className="w-3.5 h-3.5 text-amber-500" />
                <span>2. How Does It Work?</span>
              </button>
              <button
                type="button"
                onClick={() => setActiveReadTab('why')}
                className={`flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                  activeReadTab === 'why'
                    ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                <Layers className="w-3.5 h-3.5 text-emerald-500" />
                <span>3. Why Use X Instead of Y?</span>
              </button>
              <button
                type="button"
                onClick={() => setActiveReadTab('quiz')}
                className={`flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                  activeReadTab === 'quiz'
                    ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                <HelpCircle className="w-3.5 h-3.5 text-fuchsia-500" />
                <span>4. Knowledge Check</span>
              </button>
            </div>
          </div>

          {/* Section Content Body */}
          <div className="p-6 space-y-6">
            {/* TAB 1: WHAT IS IT? */}
            {activeReadTab === 'what' && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
                    {activeTopic.whatIsIt.heading}
                  </h3>
                  <div className="mt-3 space-y-3.5 text-[15px] leading-[1.7] text-slate-700 dark:text-slate-300">
                    {activeTopic.whatIsIt.paragraphs.map((p, idx) => (
                      <p key={idx}>{p}</p>
                    ))}
                  </div>
                </div>

                {/* Mental Model Callout */}
                <div className="p-5 rounded-xl bg-sky-50/70 dark:bg-sky-950/25 border border-sky-200/80 dark:border-sky-900/60">
                  <div className="text-xs font-semibold text-sky-700 dark:text-sky-300">
                    Mental Model & Engineering Analogy
                  </div>
                  <p className="text-sm text-slate-800 dark:text-slate-200 mt-1.5 leading-relaxed">
                    {activeTopic.whatIsIt.mentalModelAnalogy}
                  </p>
                </div>

                {/* Key Takeaways */}
                <div className="p-5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                  <h4 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                    Core Architectural Takeaways
                  </h4>
                  <ul className="mt-3 space-y-2.5 text-sm text-slate-700 dark:text-slate-300">
                    {activeTopic.whatIsIt.keyTakeaways.map((item, i) => (
                      <li key={i} className="flex items-start gap-2.5">
                        <span className="font-mono text-xs font-semibold text-sky-600 dark:text-sky-400 mt-0.5">
                          0{i + 1}.
                        </span>
                        <span className="leading-relaxed">{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="flex items-center justify-end pt-2">
                  <button
                    type="button"
                    onClick={() => setActiveReadTab('how')}
                    className="flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-sky-600 hover:bg-sky-500 rounded-lg transition-colors"
                  >
                    <span>Next: How Does It Work Under the Hood?</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            )}

            {/* TAB 2: HOW DOES IT WORK? */}
            {activeReadTab === 'how' && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
                    {activeTopic.howItWorks.heading}
                  </h3>
                  <div className="mt-3 space-y-3.5 text-[15px] leading-[1.7] text-slate-700 dark:text-slate-300">
                    {activeTopic.howItWorks.paragraphs.map((p, idx) => (
                      <p key={idx}>{p}</p>
                    ))}
                  </div>
                </div>

                {/* Interactive Step-by-Step Kernel Flow Animator */}
                <div className="p-5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                  <div className="flex items-center justify-between gap-4 mb-4">
                    <div>
                      <div className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                        Step-by-Step Execution Flow (Click any step to inspect)
                      </div>
                      <div className="text-xs text-slate-500 dark:text-slate-400">
                        Traces execution across User Space, Syscall, Verifier, Hook, and BPF Map
                      </div>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <button
                        type="button"
                        onClick={() =>
                          setActiveLifecycleStep((prev) =>
                            prev > 0 ? prev - 1 : currentLifecycleSteps.length - 1
                          )
                        }
                        className="px-2.5 py-1 text-xs font-medium rounded border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-200/60 dark:hover:bg-slate-800"
                      >
                        Prev Step
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          setActiveLifecycleStep((prev) =>
                            (prev + 1) % currentLifecycleSteps.length
                          )
                        }
                        className="px-2.5 py-1 text-xs font-medium rounded bg-sky-600 text-white hover:bg-sky-500"
                      >
                        Next Step
                      </button>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
                    {currentLifecycleSteps.map((s, idx) => {
                      const isCurrent = idx === clampedStepIdx;
                      return (
                        <button
                          key={s.step}
                          type="button"
                          onClick={() => setActiveLifecycleStep(idx)}
                          className={`text-left p-3 rounded-lg border transition-all ${
                            isCurrent
                              ? 'border-sky-500 bg-white dark:bg-slate-900 shadow-xs'
                              : 'border-slate-200 dark:border-slate-800 bg-white/50 dark:bg-slate-900/40 hover:border-slate-300 dark:hover:border-slate-700'
                          }`}
                        >
                          <div className="flex items-center justify-between text-[11px] font-mono">
                            <span className="font-semibold text-sky-600 dark:text-sky-400">
                              STEP {s.step}
                            </span>
                            <span className="text-slate-500 dark:text-slate-400">[{s.actor}]</span>
                          </div>
                          <div className="text-xs font-semibold text-slate-900 dark:text-slate-100 mt-1">
                            {s.title}
                          </div>
                        </button>
                      );
                    })}
                  </div>

                  {currentStepObj && (
                    <div className="mt-3 p-4 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                      <div className="flex items-center gap-2 text-xs font-mono text-sky-600 dark:text-sky-400">
                        <span>STEP {currentStepObj.step}</span>
                        <span aria-hidden="true">·</span>
                        <span>[{currentStepObj.actor}]</span>
                        <span aria-hidden="true">·</span>
                        <span className="font-sans font-semibold text-slate-900 dark:text-slate-100">
                          {currentStepObj.title}
                        </span>
                      </div>
                      <p className="text-sm text-slate-700 dark:text-slate-300 mt-1.5 leading-relaxed">
                        {currentStepObj.detail}
                      </p>
                    </div>
                  )}
                </div>

                {/* Syntax Highlighted Implementation Pattern */}
                <div>
                  <div className="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2">
                    Canonical Code Pattern ({activeTopic.howItWorks.codeLanguage.toUpperCase()})
                  </div>
                  <SyntaxHighlighter
                    code={activeTopic.howItWorks.codeSnippet}
                    language={activeTopic.howItWorks.codeLanguage}
                    title={activeTopic.howItWorks.codeTitle}
                    subtitle={activeTopic.minKernel}
                  />
                </div>

                <div className="flex items-center justify-end pt-2">
                  <button
                    type="button"
                    onClick={() => setActiveReadTab('why')}
                    className="flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-sky-600 hover:bg-sky-500 rounded-lg transition-colors"
                  >
                    <span>Next: Why Use {activeTopic.whyUseInsteadOf.primaryTech} Instead of Alternatives?</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            )}

            {/* TAB 3: WHY USE X INSTEAD OF Y? */}
            {activeReadTab === 'why' && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
                    {activeTopic.whyUseInsteadOf.heading}
                  </h3>
                  <div className="mt-3 space-y-3.5 text-[15px] leading-[1.7] text-slate-700 dark:text-slate-300">
                    {activeTopic.whyUseInsteadOf.rationaleParagraphs.map((p, idx) => (
                      <p key={idx}>{p}</p>
                    ))}
                  </div>
                </div>

                {/* Head-to-Head Architectural Comparison Matrix */}
                <div className="rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="bg-slate-50 dark:bg-slate-950 border-b border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400">
                        <th className="py-3 px-4 font-semibold">Architectural Dimension</th>
                        <th className="py-3 px-4 font-semibold text-sky-700 dark:text-sky-300">
                          {activeTopic.whyUseInsteadOf.primaryTech}
                        </th>
                        <th className="py-3 px-4 font-semibold">
                          {activeTopic.whyUseInsteadOf.alternativeTech}
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                      {activeTopic.whyUseInsteadOf.comparisonTable.map((row, idx) => (
                        <tr
                          key={idx}
                          className="hover:bg-slate-50/70 dark:hover:bg-slate-800/30 transition-colors"
                        >
                          <td className="py-3 px-4 font-medium text-slate-900 dark:text-slate-100">
                            {row.dimension}
                          </td>
                          <td className="py-3 px-4 text-slate-800 dark:text-slate-200">
                            {row.winner === 'primary' && (
                              <span className="text-emerald-600 dark:text-emerald-400 font-semibold mr-1.5">
                                ✓
                              </span>
                            )}
                            {row.primaryChoice}
                          </td>
                          <td className="py-3 px-4 text-slate-600 dark:text-slate-400">
                            {row.winner === 'alternative' && (
                              <span className="text-amber-600 dark:text-amber-400 font-semibold mr-1.5">
                                ★
                              </span>
                            )}
                            {row.alternativeChoice}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {/* Decision Rules: When to Choose Primary vs Alternative */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-4 rounded-xl bg-emerald-50/60 dark:bg-emerald-950/20 border border-emerald-200/80 dark:border-emerald-900/50">
                    <div className="text-xs font-semibold text-emerald-800 dark:text-emerald-300">
                      When to Choose {activeTopic.whyUseInsteadOf.primaryTech}
                    </div>
                    <ul className="mt-2 space-y-1.5 text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                      {activeTopic.whyUseInsteadOf.whenToUsePrimary.map((item, idx) => (
                        <li key={idx}>• {item}</li>
                      ))}
                    </ul>
                  </div>

                  <div className="p-4 rounded-xl bg-amber-50/60 dark:bg-amber-950/20 border border-amber-200/80 dark:border-amber-900/50">
                    <div className="text-xs font-semibold text-amber-800 dark:text-amber-300">
                      When to Choose {activeTopic.whyUseInsteadOf.alternativeTech}
                    </div>
                    <ul className="mt-2 space-y-1.5 text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                      {activeTopic.whyUseInsteadOf.whenToUseAlternative.map((item, idx) => (
                        <li key={idx}>• {item}</li>
                      ))}
                    </ul>
                  </div>
                </div>

                <div className="flex items-center justify-end pt-2">
                  <button
                    type="button"
                    onClick={() => setActiveReadTab('quiz')}
                    className="flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-sky-600 hover:bg-sky-500 rounded-lg transition-colors"
                  >
                    <span>Next: Verify Your Understanding</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            )}

            {/* TAB 4: COMPREHENSION CHECK QUIZ */}
            {activeReadTab === 'quiz' && (
              <div className="space-y-6">
                <div className="p-5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                  <div className="text-xs font-semibold text-sky-600 dark:text-sky-400">
                    Chapter {activeTopic.index} Comprehension Check
                  </div>
                  <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100 mt-1.5">
                    {activeTopic.comprehensionCheck.question}
                  </h3>

                  <div className="mt-4 space-y-2.5">
                    {activeTopic.comprehensionCheck.options.map((optionText, idx) => {
                      const isChosen = chosenQuizIndex === idx;
                      const isRightOption = idx === activeTopic.comprehensionCheck.correctIndex;

                      let borderStyle =
                        'border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 hover:border-slate-300 dark:hover:border-slate-700';
                      if (chosenQuizIndex !== undefined) {
                        if (isRightOption) {
                          borderStyle =
                            'border-emerald-500 bg-emerald-50/70 dark:bg-emerald-950/30 text-emerald-900 dark:text-emerald-200';
                        } else if (isChosen) {
                          borderStyle =
                            'border-red-500 bg-red-50/70 dark:bg-red-950/30 text-red-900 dark:text-red-200';
                        }
                      }

                      return (
                        <button
                          key={idx}
                          type="button"
                          onClick={() => {
                            setSelectedQuizOption((prev) => ({
                              ...prev,
                              [activeTopic.id]: idx
                            }));
                            if (idx === activeTopic.comprehensionCheck.correctIndex) {
                              onMarkTopicCompleted(activeTopic.id);
                            }
                          }}
                          className={`w-full text-left p-3.5 rounded-lg border text-xs leading-relaxed transition-all flex items-start gap-3 ${borderStyle}`}
                        >
                          <span className="font-mono font-semibold text-slate-500 dark:text-slate-400 shrink-0">
                            {String.fromCharCode(65 + idx)}.
                          </span>
                          <span className="text-slate-800 dark:text-slate-200">{optionText}</span>
                        </button>
                      );
                    })}
                  </div>

                  {chosenQuizIndex !== undefined && (
                    <div
                      className={`mt-4 p-4 rounded-lg border text-xs leading-relaxed ${
                        isQuizCorrect
                          ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-800 dark:text-emerald-200'
                          : 'bg-amber-500/10 border-amber-500/30 text-amber-800 dark:text-amber-200'
                      }`}
                    >
                      <div className="font-semibold mb-1">
                        {isQuizCorrect
                          ? '✓ Correct! Chapter marked as completed.'
                          : '✕ Not quite—review the kernel mechanics below:'}
                      </div>
                      <p>{activeTopic.comprehensionCheck.explanation}</p>
                    </div>
                  )}
                </div>

                {/* Action Bridge to Hands-On Tutorial & Live Simulator */}
                <div className="p-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div>
                    <div className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                      Put This Concept Into Practice
                    </div>
                    <p className="text-xs text-slate-600 dark:text-slate-400 mt-0.5">
                      Jump directly to the guided C + Go lab or experiment with live verifier checks in the Kernel Simulator.
                    </p>
                  </div>
                  <div className="flex items-center gap-2.5 shrink-0">
                    <button
                      type="button"
                      onClick={() => onOpenTutorial(activeTopic.relatedTutorialId)}
                      className="px-3.5 py-2 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors whitespace-nowrap"
                    >
                      Open Step-by-Step Tutorial
                    </button>
                    <button
                      type="button"
                      onClick={() => onOpenSimulatorPreset(activeTopic.simulatorPresetId)}
                      className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold rounded-lg bg-sky-600 hover:bg-sky-500 text-white transition-colors whitespace-nowrap"
                    >
                      <Play className="w-3.5 h-3.5" />
                      <span>Launch in Simulator</span>
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
