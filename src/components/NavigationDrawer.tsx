import React, { useEffect, useState } from 'react';
import {
  X,
  BookOpen,
  GraduationCap,
  Terminal,
  Wrench,
  Braces,
  Cpu,
  FolderGit2,
  Moon,
  Sun,
  RotateCcw,
  CheckCircle2,
  ChevronRight,
  Sparkles,
  Layers
} from 'lucide-react';
import { CONCEPT_TOPICS } from '../data/conceptsData';
import { TUTORIAL_LESSONS } from '../data/tutorialsData';
import { TRACEABLE_SYSCALLS } from '../data/syscallsData';
import { BPF_HELPERS_CATALOG, EBPF_MACROS_CATALOG } from '../data/helpersAndMacrosData';

export type ActiveSection =
  | 'concepts'
  | 'tutorials'
  | 'syscalls'
  | 'helpers'
  | 'macros'
  | 'simulator'
  | 'templates';

interface NavigationDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  activeSection: ActiveSection;
  onSelectSection: (section: ActiveSection) => void;
  isDarkMode: boolean;
  onToggleTheme: () => void;
  completedConceptsCount: number;
  completedTutorialsCount: number;
  onResetProgress: () => void;
  onLaunchSimulator: () => void;
}

interface NavSectionItem {
  id: ActiveSection;
  title: string;
  subtitle: string;
  badge: string;
  badgeColor: string;
  icon: React.ComponentType<{ className?: string }>;
}

export const NavigationDrawer: React.FC<NavigationDrawerProps> = ({
  isOpen,
  onClose,
  activeSection,
  onSelectSection,
  isDarkMode,
  onToggleTheme,
  completedConceptsCount,
  completedTutorialsCount,
  onResetProgress,
  onLaunchSimulator
}) => {
  const [confirmReset, setConfirmReset] = useState(false);

  // Close on Escape key press
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  // Lock body scroll when drawer is open on mobile
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
      setConfirmReset(false);
    }
    return () => {
      document.body.style.overflow = '';
    };
  }, [isOpen]);

  const navItems: NavSectionItem[] = [
    {
      id: 'concepts',
      title: 'Concepts & Architecture',
      subtitle: 'What is X? · How it works · Why use instead of Y?',
      badge: `${CONCEPT_TOPICS.length} Chapters`,
      badgeColor: 'text-sky-600 dark:text-sky-400 bg-sky-50 dark:bg-sky-950/60 border-sky-200 dark:border-sky-800',
      icon: BookOpen
    },
    {
      id: 'tutorials',
      title: 'Step-by-Step Tutorials',
      subtitle: 'Hands-on C probes & Go cilium/ebpf loaders',
      badge: `${TUTORIAL_LESSONS.length} Guided Labs`,
      badgeColor: 'text-indigo-600 dark:text-indigo-400 bg-indigo-50 dark:bg-indigo-950/60 border-indigo-200 dark:border-indigo-800',
      icon: GraduationCap
    },
    {
      id: 'syscalls',
      title: 'Linux System Calls Catalog',
      subtitle: 'Syscall ABI, __user pointers, kernel structures & errnos',
      badge: `${TRACEABLE_SYSCALLS.length} Syscalls`,
      badgeColor: 'text-cyan-600 dark:text-cyan-400 bg-cyan-50 dark:bg-cyan-950/60 border-cyan-200 dark:border-cyan-800',
      icon: Terminal
    },
    {
      id: 'helpers',
      title: 'BPF Helpers & Kfuncs',
      subtitle: 'Register calling convention, Verifier safety contracts & kfuncs',
      badge: `${BPF_HELPERS_CATALOG.length} Core APIs`,
      badgeColor: 'text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/60 border-emerald-200 dark:border-emerald-800',
      icon: Wrench
    },
    {
      id: 'macros',
      title: 'eBPF Macros & SEC() Directives',
      subtitle: 'Under-the-hood macro expansions & BTF CO-RE annotations',
      badge: `${EBPF_MACROS_CATALOG.length} Macros`,
      badgeColor: 'text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/60 border-amber-200 dark:border-amber-800',
      icon: Braces
    },
    {
      id: 'simulator',
      title: 'Kernel Simulator',
      subtitle: 'Live event pipeline, maps inspector & verifier diagnostics',
      badge: 'Interactive Lab',
      badgeColor: 'text-teal-600 dark:text-teal-400 bg-teal-50 dark:bg-teal-950/60 border-teal-200 dark:border-teal-800',
      icon: Cpu
    },
    {
      id: 'templates',
      title: 'Production Project Templates',
      subtitle: 'Multi-file cloud-native architectures (Tetragon, Cilium, Katran)',
      badge: '6 Templates',
      badgeColor: 'text-violet-600 dark:text-violet-400 bg-violet-50 dark:bg-violet-950/60 border-violet-200 dark:border-violet-800',
      icon: FolderGit2
    }
  ];

  if (!isOpen) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Navigation Menu"
      className="fixed inset-0 z-50 overflow-hidden"
    >
      {/* Backdrop */}
      <div
        onClick={onClose}
        className="fixed inset-0 bg-black/60 dark:bg-black/80 backdrop-blur-xs transition-opacity animate-in fade-in duration-200"
      />

      {/* Slide-out Drawer Container */}
      <div className="fixed inset-y-0 left-0 w-full max-w-sm sm:max-w-md bg-white dark:bg-[#0B0F17] border-r border-slate-200 dark:border-slate-800 shadow-2xl flex flex-col z-10 animate-in slide-in-from-left duration-250">
        {/* Drawer Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/40">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-sky-600 text-white flex items-center justify-center font-bold font-mono text-sm shadow-xs">
              KP
            </div>
            <div>
              <div className="text-base font-bold tracking-tight text-slate-900 dark:text-white font-display">
                KernelPulse
              </div>
              <div className="text-[11px] text-slate-500 dark:text-slate-400 font-mono">
                eBPF Linux Academy &amp; Reference Hub
              </div>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            aria-label="Close navigation menu"
            className="min-h-[44px] min-w-[44px] flex items-center justify-center rounded-lg text-slate-500 hover:text-slate-900 dark:hover:text-white hover:bg-slate-200/60 dark:hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Quick Launch CTA Button */}
        <div className="p-4 border-b border-slate-200 dark:border-slate-800 bg-sky-500/5">
          <button
            type="button"
            onClick={() => {
              onLaunchSimulator();
              onClose();
            }}
            className="w-full min-h-[44px] px-4 py-2.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white font-medium text-xs flex items-center justify-center gap-2 shadow-xs transition-colors cursor-pointer"
          >
            <Cpu className="w-4 h-4" />
            <span>Launch Interactive Kernel Simulator</span>
          </button>
        </div>

        {/* Navigation Section List */}
        <div className="flex-1 overflow-y-auto p-3 sm:p-4 space-y-1.5 divide-y divide-transparent">
          <div className="px-2 py-1 text-[11px] font-mono uppercase tracking-wider text-slate-400 dark:text-slate-500">
            Curriculum &amp; Reference Hub
          </div>

          {navItems.map((item) => {
            const isActive = activeSection === item.id;
            const IconComponent = item.icon;

            return (
              <button
                key={item.id}
                type="button"
                onClick={() => {
                  onSelectSection(item.id);
                  onClose();
                }}
                className={`w-full min-h-[52px] text-left p-3 rounded-xl border transition-all flex items-start gap-3 cursor-pointer ${
                  isActive
                    ? 'border-sky-500 bg-sky-50/70 dark:bg-sky-950/30 text-sky-950 dark:text-sky-100 shadow-xs'
                    : 'border-transparent hover:border-slate-200 dark:hover:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-900/60 text-slate-800 dark:text-slate-200'
                }`}
              >
                <div
                  className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 mt-0.5 ${
                    isActive
                      ? 'bg-sky-600 text-white'
                      : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300'
                  }`}
                >
                  <IconComponent className="w-4 h-4" />
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2 mb-0.5">
                    <span className="text-sm font-semibold truncate text-slate-900 dark:text-white">
                      {item.title}
                    </span>
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded border shrink-0 ${item.badgeColor}`}
                    >
                      {item.badge}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 dark:text-slate-400 line-clamp-1">
                    {item.subtitle}
                  </p>
                </div>

                <ChevronRight
                  className={`w-4 h-4 shrink-0 mt-2 transition-transform ${
                    isActive ? 'text-sky-600 dark:text-sky-400 translate-x-0.5' : 'text-slate-400 opacity-60'
                  }`}
                />
              </button>
            );
          })}
        </div>

        {/* Progress Tracker Card */}
        <div className="p-4 border-t border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-900/40">
          <div className="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2 flex items-center gap-1.5 font-mono">
            <Sparkles className="w-3.5 h-3.5 text-sky-500" />
            <span>Learning Milestones</span>
          </div>

          <div className="grid grid-cols-2 gap-2 text-xs font-mono">
            <div className="p-2 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700">
              <div className="text-[10px] text-slate-500 dark:text-slate-400 uppercase">Concepts Read</div>
              <div className="text-sm font-bold text-slate-900 dark:text-white">
                {completedConceptsCount} / {CONCEPT_TOPICS.length}
              </div>
            </div>
            <div className="p-2 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700">
              <div className="text-[10px] text-slate-500 dark:text-slate-400 uppercase">Labs Completed</div>
              <div className="text-sm font-bold text-slate-900 dark:text-white">
                {completedTutorialsCount} / {TUTORIAL_LESSONS.length}
              </div>
            </div>
          </div>
        </div>

        {/* Drawer Footer Controls */}
        <div className="p-4 border-t border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0B0F17] flex items-center justify-between gap-3">
          <button
            type="button"
            onClick={onToggleTheme}
            className="flex-1 min-h-[44px] flex items-center justify-center gap-2 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors cursor-pointer"
          >
            {isDarkMode ? (
              <>
                <Sun className="w-4 h-4 text-amber-400" />
                <span>Switch to Light</span>
              </>
            ) : (
              <>
                <Moon className="w-4 h-4 text-slate-700" />
                <span>Switch to Dark</span>
              </>
            )}
          </button>

          {!confirmReset ? (
            <button
              type="button"
              onClick={() => setConfirmReset(true)}
              className="min-h-[44px] px-3 py-2 rounded-lg text-slate-500 hover:text-slate-900 dark:hover:text-white text-xs font-medium flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
              title="Reset reading progress"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Reset</span>
            </button>
          ) : (
            <div className="flex items-center gap-1">
              <button
                type="button"
                onClick={() => {
                  onResetProgress();
                  setConfirmReset(false);
                }}
                className="min-h-[44px] px-2.5 py-1.5 text-xs font-semibold text-white bg-rose-600 rounded-lg hover:bg-rose-500 cursor-pointer"
              >
                Confirm
              </button>
              <button
                type="button"
                onClick={() => setConfirmReset(false)}
                className="min-h-[44px] px-2 py-1.5 text-xs text-slate-500 hover:text-slate-900 dark:hover:text-white cursor-pointer"
              >
                Cancel
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
