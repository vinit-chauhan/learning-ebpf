import React, { useState, useEffect } from 'react';
import {
  CheckCircle2,
  Play,
  ShieldAlert,
  ShieldCheck,
  BookOpen,
  Code2,
  ArrowRight
} from 'lucide-react';
import { TUTORIAL_LESSONS } from '../data/tutorialsData';
import { SkillTier, TutorialLesson } from '../types/ebpf';
import { SyntaxHighlighter } from './SyntaxHighlighter';

interface TutorialsViewProps {
  selectedTutorialId: string;
  onSelectTutorial: (tutorialId: string) => void;
  completedTutorials?: string[];
  completedTutorialIds?: string[];
  onToggleTutorialComplete?: (tutorialId: string) => void;
  onToggleCompleteTutorial?: (tutorialId: string) => void;
  onOpenSimulatorPreset: (presetId: string) => void;
}

const PIPELINE_NODES: {
  id: 'userspace' | 'syscall' | 'verifier' | 'hook' | 'map' | 'ringbuf';
  label: string;
  sub: string;
}[] = [
  { id: 'userspace', label: '1. Go Loader', sub: 'cilium/ebpf + bpf2go' },
  { id: 'syscall', label: '2. bpf() Syscall', sub: 'BPF_PROG_LOAD' },
  { id: 'verifier', label: '3. Static Verifier', sub: 'CFG & Bounds Proof' },
  { id: 'hook', label: '4. Kernel Hook', sub: 'JIT Execution' },
  { id: 'map', label: '5. BPF Maps', sub: 'Hash / Per-CPU State' },
  { id: 'ringbuf', label: '6. RingBuffer', sub: 'Zero-Copy Stream' }
];

function expandRange(range: [number, number]): number[] {
  const lines: number[] = [];
  for (let i = range[0]; i <= range[1]; i++) {
    lines.push(i);
  }
  return lines;
}

export const TutorialsView: React.FC<TutorialsViewProps> = ({
  selectedTutorialId,
  onSelectTutorial,
  completedTutorials,
  completedTutorialIds,
  onToggleTutorialComplete,
  onToggleCompleteTutorial,
  onOpenSimulatorPreset
}) => {
  const completedIds = completedTutorials ?? completedTutorialIds ?? [];
  const handleToggleComplete =
    onToggleTutorialComplete ?? onToggleCompleteTutorial ?? (() => {});

  const [tierFilter, setTierFilter] = useState<'all' | SkillTier>('all');
  const [activeStepIndex, setActiveStepIndex] = useState<number>(0);
  const [challengeMode, setChallengeMode] = useState<'buggy' | 'fixed'>('buggy');
  const [showConceptGuide, setShowConceptGuide] = useState<boolean>(true);
  const [showMobileList, setShowMobileList] = useState<boolean>(false);

  const activeLesson: TutorialLesson =
    TUTORIAL_LESSONS.find((t) => t.id === selectedTutorialId) || TUTORIAL_LESSONS[0];

  useEffect(() => {
    setActiveStepIndex(0);
    setChallengeMode('buggy');
  }, [activeLesson.id]);

  const filteredLessons = TUTORIAL_LESSONS.filter(
    (l) => tierFilter === 'all' || l.tier === tierFilter
  );

  const currentStep =
    activeLesson.steps[Math.min(activeStepIndex, activeLesson.steps.length - 1)] ||
    activeLesson.steps[0];

  const cHighlightedLines = expandRange(currentStep.cHighlightLines);
  const goHighlightedLines = expandRange(currentStep.goHighlightLines);
  const isCompleted = completedIds.includes(activeLesson.id);

  const beginnerCount = TUTORIAL_LESSONS.filter((l) => l.tier === 'beginner').length;
  const intermediateCount = TUTORIAL_LESSONS.filter((l) => l.tier === 'intermediate').length;
  const advancedCount = TUTORIAL_LESSONS.filter((l) => l.tier === 'advanced').length;

  return (
    <div className="space-y-6">
      {/* Header & Skill Tier Filter Bar */}
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4 sm:p-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="text-xs font-medium text-sky-600 dark:text-sky-400 font-mono">
              Guided Tracing Curriculum · {TUTORIAL_LESSONS.length} Labs Across Beginner, Mid-Level &amp; Advanced
            </div>
            <h1 className="text-xl sm:text-2xl md:text-3xl font-semibold text-slate-900 dark:text-slate-100 mt-1">
              Step-by-Step eBPF Tracing &amp; Networking Tutorials (C + Go)
            </h1>
            <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 mt-1 max-w-3xl">
              Master kernel C probes paired with idiomatic Go (<code className="font-mono text-xs">github.com/cilium/ebpf</code>) loaders. Each lab includes a concept deep-dive, synchronized code-to-kernel checkpoints, and an interactive Verifier debugging challenge.
            </p>
          </div>

          <div className="flex items-center gap-1.5 p-1 rounded-lg bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 shrink-0 overflow-x-auto">
            {(
              [
                { id: 'all', label: `All (${TUTORIAL_LESSONS.length})` },
                { id: 'beginner', label: `Beginner (${beginnerCount})` },
                { id: 'intermediate', label: `Mid-Level (${intermediateCount})` },
                { id: 'advanced', label: `Advanced (${advancedCount})` }
              ] as const
            ).map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setTierFilter(tab.id)}
                className={`min-h-[38px] px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  tierFilter === tab.id
                    ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* Mobile Quick Lab Switcher (Visible only on mobile < lg) */}
        <div className="mt-4 pt-4 border-t border-slate-200 dark:border-slate-800 lg:hidden">
          <div className="flex items-center justify-between gap-2 p-3 rounded-lg border border-sky-500/30 bg-sky-50/50 dark:bg-sky-950/20">
            <div className="min-w-0 flex-1">
              <div className="text-[10px] font-mono uppercase text-sky-600 dark:text-sky-400">
                Active Lab {activeLesson.index} of {TUTORIAL_LESSONS.length}
              </div>
              <div className="text-xs font-semibold text-slate-900 dark:text-white truncate">
                {activeLesson.title}
              </div>
            </div>

            <button
              type="button"
              onClick={() => setShowMobileList(!showMobileList)}
              className="min-h-[44px] px-3 py-1.5 text-xs font-medium rounded-md bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-200 flex items-center gap-1.5 shrink-0 shadow-xs cursor-pointer"
            >
              <span>{showMobileList ? 'Hide Labs' : 'Switch Lab'}</span>
            </button>
          </div>

          {/* Expandable Mobile Lab Selector List */}
          {showMobileList && (
            <div className="mt-2 space-y-1.5 max-h-[320px] overflow-y-auto p-1.5 border border-slate-200 dark:border-slate-800 rounded-lg bg-slate-50 dark:bg-slate-900">
              {filteredLessons.map((lesson) => {
                const isSelected = lesson.id === activeLesson.id;
                const done = completedIds.includes(lesson.id);

                return (
                  <button
                    key={lesson.id}
                    type="button"
                    onClick={() => {
                      onSelectTutorial(lesson.id);
                      setShowMobileList(false);
                    }}
                    className={`w-full min-h-[44px] text-left p-2.5 rounded-lg border transition-all flex items-center justify-between gap-2 cursor-pointer ${
                      isSelected
                        ? 'border-sky-500 bg-white dark:bg-slate-800 text-sky-600 dark:text-sky-400 font-semibold shadow-xs'
                        : 'border-transparent hover:border-slate-200 dark:hover:border-slate-700 hover:bg-white dark:hover:bg-slate-800/60 text-slate-800 dark:text-slate-200'
                    }`}
                  >
                    <div className="min-w-0">
                      <div className="text-xs font-mono font-medium truncate">
                        Lab {lesson.index}: {lesson.title}
                      </div>
                      <div className="text-[10px] text-slate-500 dark:text-slate-400">
                        {lesson.tier} · {lesson.hookType} · {lesson.duration}
                      </div>
                    </div>
                    {done && <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0" />}
                  </button>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Main Layout: Left Curriculum Sidebar (3 cols on desktop) + Right Interactive Lab Studio (9 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Sidebar: 21 Tutorials List (Always visible on desktop, hidden on mobile) */}
        <div className="hidden lg:block lg:col-span-3 space-y-2 max-h-[1200px] overflow-y-auto pr-1">
          {filteredLessons.map((lesson) => {
            const isSelected = lesson.id === activeLesson.id;
            const done = completedIds.includes(lesson.id);

            return (
              <button
                key={lesson.id}
                type="button"
                onClick={() => onSelectTutorial(lesson.id)}
                className={`w-full text-left p-3.5 rounded-xl border transition-all cursor-pointer ${
                  isSelected
                    ? 'border-sky-500 bg-white dark:bg-slate-900 shadow-xs'
                    : 'border-slate-200 dark:border-slate-800 bg-white/60 dark:bg-slate-900/50 hover:border-slate-300 dark:hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between gap-2 text-[11px] text-slate-500 dark:text-slate-400">
                  <div className="flex items-center gap-1.5 truncate">
                    <span className="font-mono font-semibold text-sky-600 dark:text-sky-400">
                      Lab {lesson.index}
                    </span>
                    <span aria-hidden="true">·</span>
                    <span className="capitalize">{lesson.tier}</span>
                    <span aria-hidden="true">·</span>
                    <span className="font-mono">{lesson.hookType}</span>
                  </div>
                  {done && <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 shrink-0" />}
                </div>

                <div className="text-xs font-semibold text-slate-900 dark:text-slate-100 mt-1 leading-snug">
                  {lesson.title}
                </div>

                <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-1.5 flex items-center gap-1.5">
                  <span>{lesson.duration}</span>
                  <span aria-hidden="true">·</span>
                  <span className="font-mono">{lesson.minKernel}</span>
                </div>
              </button>
            );
          })}
        </div>

        {/* Right Interactive Tutorial Workspace */}
        <div className="lg:col-span-9 space-y-6">
          {/* Active Lab Header & Action Bar */}
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6">
            <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-slate-500 dark:text-slate-400">
              <div className="flex items-center gap-2">
                <span className="font-mono font-semibold text-sky-600 dark:text-sky-400">
                  Tutorial {activeLesson.index}
                </span>
                <span aria-hidden="true">·</span>
                <span className="capitalize">{activeLesson.tier} Tier</span>
                <span aria-hidden="true">·</span>
                <span>Hook: {activeLesson.hookType}</span>
                <span aria-hidden="true">·</span>
                <span>{activeLesson.duration}</span>
                <span aria-hidden="true">·</span>
                <span className="font-mono">{activeLesson.minKernel}</span>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => handleToggleComplete(activeLesson.id)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                    isCompleted
                      ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30'
                      : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700'
                  }`}
                >
                  {isCompleted ? '✓ Lab Completed' : 'Mark Lab Complete'}
                </button>
                <button
                  type="button"
                  onClick={() => onOpenSimulatorPreset(activeLesson.simulatorPresetId)}
                  className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-sky-600 hover:bg-sky-500 text-white transition-colors whitespace-nowrap shrink-0"
                >
                  <Play className="w-3.5 h-3.5" />
                  <span>Load in Kernel Simulator</span>
                </button>
              </div>
            </div>

            <h2 className="text-xl sm:text-2xl font-semibold text-slate-900 dark:text-slate-100 mt-2">
              {activeLesson.title}
            </h2>
            <p className="text-sm text-slate-600 dark:text-slate-300 mt-1 leading-relaxed">
              {activeLesson.summary}
            </p>

            {/* Learning Objectives */}
            <div className="mt-4 pt-4 border-t border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="text-xs font-semibold text-slate-800 dark:text-slate-200">
                  What You Will Master in This Lab:
                </div>
                <div className="flex flex-wrap gap-x-6 gap-y-1 text-xs text-slate-600 dark:text-slate-400">
                  {activeLesson.learningObjectives.map((obj, idx) => (
                    <span key={idx}>• {obj}</span>
                  ))}
                </div>
              </div>
              <button
                type="button"
                onClick={() => setShowConceptGuide(!showConceptGuide)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800 text-xs font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 shrink-0"
              >
                <BookOpen className="w-3.5 h-3.5 text-sky-500" />
                <span>{showConceptGuide ? 'Hide Concept Read-Through' : 'Show Concept Read-Through'}</span>
              </button>
            </div>

            {/* Concept Read-Through (What / How / Why) */}
            {showConceptGuide && (
              <div className="mt-5 pt-5 border-t border-slate-200 dark:border-slate-800 grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                  <div className="text-xs font-semibold text-sky-600 dark:text-sky-400">
                    1. {activeLesson.conceptGuide.whatIsTitle}
                  </div>
                  <p className="text-xs text-slate-700 dark:text-slate-300 mt-1.5 leading-relaxed">
                    {activeLesson.conceptGuide.whatIsContent}
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                  <div className="text-xs font-semibold text-amber-600 dark:text-amber-400">
                    2. {activeLesson.conceptGuide.howItWorksTitle}
                  </div>
                  <p className="text-xs text-slate-700 dark:text-slate-300 mt-1.5 leading-relaxed">
                    {activeLesson.conceptGuide.howItWorksContent}
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                  <div className="text-xs font-semibold text-emerald-600 dark:text-emerald-400">
                    3. {activeLesson.conceptGuide.whyUseInsteadTitle}
                  </div>
                  <p className="text-xs text-slate-700 dark:text-slate-300 mt-1.5 leading-relaxed">
                    {activeLesson.conceptGuide.whyUseInsteadContent}
                  </p>
                  <div className="mt-2.5 pt-2 border-t border-slate-200 dark:border-slate-800 text-[11px] font-mono text-slate-600 dark:text-slate-400">
                    Perf Delta: {activeLesson.conceptGuide.comparisonHighlight.overheadDelta}
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Interactive Step-by-Step Checkpoint Controller & Kernel Pipeline Visualizer */}
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <div className="text-xs font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                  <Code2 className="w-4 h-4 text-sky-500" />
                  <span>Interactive Walkthrough Checkpoints (Synchronized C + Go Highlighting)</span>
                </div>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  Select each checkpoint below to highlight the corresponding C kernel lines, Go control-plane lines, and kernel subsystem stage.
                </p>
              </div>

              <div className="flex items-center gap-1.5 shrink-0">
                {activeLesson.steps.map((step, idx) => (
                  <button
                    key={step.stepNumber}
                    type="button"
                    onClick={() => setActiveStepIndex(idx)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                      activeStepIndex === idx
                        ? 'bg-sky-600 text-white'
                        : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700'
                    }`}
                  >
                    Step {step.stepNumber}
                  </button>
                ))}
              </div>
            </div>

            {/* Visual Kernel Pipeline Stage Bar */}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
              {PIPELINE_NODES.map((node) => {
                const isActiveNode = currentStep.activePipelineNode === node.id;
                return (
                  <div
                    key={node.id}
                    className={`p-2.5 rounded-lg border text-xs transition-all ${
                      isActiveNode
                        ? 'border-sky-500 bg-sky-500/10 text-slate-900 dark:text-white'
                        : 'border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-950/60 text-slate-500 dark:text-slate-400'
                    }`}
                  >
                    <div className="font-semibold truncate">{node.label}</div>
                    <div className="text-[11px] font-mono opacity-80 truncate">{node.sub}</div>
                  </div>
                );
              })}
            </div>

            {/* Active Checkpoint Explanation Card */}
            <div className="p-4 rounded-xl bg-sky-50/60 dark:bg-sky-950/25 border border-sky-200/80 dark:border-sky-900/60 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="text-xs font-mono font-semibold text-sky-700 dark:text-sky-300">
                  CHECKPOINT 0{currentStep.stepNumber} · C LINES {currentStep.cHighlightLines[0]}–{currentStep.cHighlightLines[1]} · GO LINES {currentStep.goHighlightLines[0]}–{currentStep.goHighlightLines[1]}
                </div>
                <div className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                  {currentStep.title}
                </div>
                <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                  {currentStep.explanation}
                </p>
                <div className="text-xs font-medium text-emerald-700 dark:text-emerald-400 pt-1">
                  Key Kernel Insight: {currentStep.keyInsight}
                </div>
              </div>

              {activeStepIndex < activeLesson.steps.length - 1 && (
                <button
                  type="button"
                  onClick={() => setActiveStepIndex((prev) => prev + 1)}
                  className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold shrink-0 whitespace-nowrap"
                >
                  <span>Next Checkpoint</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {/* Side-by-Side Syntax Highlighted Kernel C + Userspace Go */}
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
              <SyntaxHighlighter
                code={activeLesson.cCode}
                language="c"
                title={activeLesson.cFileName}
                subtitle="Kernel Space (Restricted C + BTF)"
                highlightedLines={cHighlightedLines}
              />
              <SyntaxHighlighter
                code={activeLesson.goCode}
                language="go"
                title={activeLesson.goFileName}
                subtitle="User Space (Go + github.com/cilium/ebpf)"
                highlightedLines={goHighlightedLines}
              />
            </div>
          </div>

          {/* Interactive Verifier Challenge Section */}
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <div className="text-xs font-semibold text-amber-600 dark:text-amber-400">
                  Hands-On Verifier Diagnostic Lab
                </div>
                <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100 mt-0.5">
                  {activeLesson.verifierChallenge.title}
                </h3>
                <p className="text-xs text-slate-600 dark:text-slate-400 mt-0.5">
                  {activeLesson.verifierChallenge.prompt}
                </p>
              </div>

              <div className="flex items-center gap-1.5 p-1 rounded-lg bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 shrink-0">
                <button
                  type="button"
                  onClick={() => setChallengeMode('buggy')}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors whitespace-nowrap ${
                    challengeMode === 'buggy'
                      ? 'bg-red-600 text-white'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  <ShieldAlert className="w-3.5 h-3.5" />
                  <span>1. Inspect Buggy Code (Rejected)</span>
                </button>
                <button
                  type="button"
                  onClick={() => setChallengeMode('fixed')}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors whitespace-nowrap ${
                    challengeMode === 'fixed'
                      ? 'bg-emerald-600 text-white'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  <ShieldCheck className="w-3.5 h-3.5" />
                  <span>2. Apply Verifier Fix (Verified ✓)</span>
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <SyntaxHighlighter
                code={
                  challengeMode === 'buggy'
                    ? activeLesson.verifierChallenge.buggySnippet
                    : activeLesson.verifierChallenge.fixedSnippet
                }
                language="c"
                title={
                  challengeMode === 'buggy'
                    ? 'unsafe_snippet.bpf.c (Rejected by Verifier)'
                    : 'verified_snippet.bpf.c (Passes Static Analysis)'
                }
              />

              <div
                className={`rounded-lg border p-4 font-mono text-xs flex flex-col justify-between ${
                  challengeMode === 'buggy'
                    ? 'border-red-500/40 bg-red-950/20 text-red-700 dark:text-red-300'
                    : 'border-emerald-500/40 bg-emerald-950/20 text-emerald-800 dark:text-emerald-300'
                }`}
              >
                <div>
                  <div className="font-semibold mb-2 flex items-center justify-between">
                    <span>
                      {challengeMode === 'buggy'
                        ? '✕ Kernel Static Verifier Output (BPF_PROG_LOAD = -EACCES)'
                        : '✓ Kernel Static Verifier Output (BPF_PROG_LOAD = Safe)'}
                    </span>
                  </div>
                  <pre className="whitespace-pre-wrap leading-relaxed text-[11.5px]">
                    {challengeMode === 'buggy'
                      ? activeLesson.verifierChallenge.verifierErrorOutput
                      : activeLesson.verifierChallenge.verifierPassOutput}
                  </pre>
                </div>

                <div className="mt-4 pt-3 border-t border-current/20 font-sans text-xs text-slate-700 dark:text-slate-300">
                  <span className="font-semibold">Why This Happens: </span>
                  {activeLesson.verifierChallenge.explanation}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
