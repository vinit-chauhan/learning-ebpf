/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import {
  Moon,
  Sun,
  RotateCcw,
  Menu,
  Compass,
  BookOpen,
  GraduationCap,
  Terminal,
  Cpu,
  ChevronDown
} from 'lucide-react';
import { ConceptExplorerView } from './components/ConceptExplorerView';
import { TutorialsView } from './components/TutorialsView';
import { KernelSimulatorView } from './components/KernelSimulatorView';
import { ProjectTemplatesView } from './components/ProjectTemplatesView';
import { SyscallsReferenceView } from './components/SyscallsReferenceView';
import { HelpersReferenceView } from './components/HelpersReferenceView';
import { MacrosReferenceView } from './components/MacrosReferenceView';
import { NavigationDrawer, ActiveSection } from './components/NavigationDrawer';
import { CONCEPT_TOPICS } from './data/conceptsData';
import { TUTORIAL_LESSONS } from './data/tutorialsData';
import { SIMULATOR_PRESETS } from './data/simulatorAndTemplatesData';
import { TRACEABLE_SYSCALLS } from './data/syscallsData';
import { BPF_HELPERS_CATALOG, EBPF_MACROS_CATALOG } from './data/helpersAndMacrosData';

export default function App() {
  const [activeSection, setActiveSection] = useState<ActiveSection>('concepts');
  const [isNavDrawerOpen, setIsNavDrawerOpen] = useState<boolean>(false);
  const [isDarkMode, setIsDarkMode] = useState<boolean>(() => {
    try {
      const saved = localStorage.getItem('kernelpulse_theme');
      return saved ? saved === 'dark' : true;
    } catch {
      return true;
    }
  });

  const [completedConcepts, setCompletedConcepts] = useState<string[]>(() => {
    try {
      const raw = localStorage.getItem('kernelpulse_completed_concepts');
      return raw ? JSON.parse(raw) : ['ebpf-architecture-fundamentals'];
    } catch {
      return ['ebpf-architecture-fundamentals'];
    }
  });

  const [completedTutorials, setCompletedTutorials] = useState<string[]>(() => {
    try {
      const raw = localStorage.getItem('kernelpulse_completed_tutorials');
      return raw ? JSON.parse(raw) : ['tut-beg-01-execve'];
    } catch {
      return ['tut-beg-01-execve'];
    }
  });

  const [selectedTutorialId, setSelectedTutorialId] = useState<string>(TUTORIAL_LESSONS[0].id);
  const [selectedPresetId, setSelectedPresetId] = useState<string>(SIMULATOR_PRESETS[0].id);

  useEffect(() => {
    const root = document.documentElement;
    if (isDarkMode) {
      root.classList.add('dark');
      localStorage.setItem('kernelpulse_theme', 'dark');
    } else {
      root.classList.remove('dark');
      localStorage.setItem('kernelpulse_theme', 'light');
    }
  }, [isDarkMode]);

  useEffect(() => {
    localStorage.setItem('kernelpulse_completed_concepts', JSON.stringify(completedConcepts));
  }, [completedConcepts]);

  useEffect(() => {
    localStorage.setItem('kernelpulse_completed_tutorials', JSON.stringify(completedTutorials));
  }, [completedTutorials]);

  const handleToggleConceptComplete = (id: string) => {
    setCompletedConcepts((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
    );
  };

  const handleToggleTutorialComplete = (id: string) => {
    setCompletedTutorials((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
    );
  };

  const handleOpenTutorial = (tutorialId: string) => {
    setSelectedTutorialId(tutorialId);
    setActiveSection('tutorials');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleOpenSimulatorPreset = (presetId: string) => {
    setSelectedPresetId(presetId);
    setActiveSection('simulator');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const sectionLabels: Record<ActiveSection, string> = {
    concepts: 'Concepts & Flows',
    tutorials: 'Tutorials',
    syscalls: 'Linux Syscalls',
    helpers: 'BPF Helpers & Kfuncs',
    macros: 'eBPF Macros & SEC()',
    simulator: 'Kernel Simulator',
    templates: 'Project Templates'
  };

  return (
    <div className="min-h-screen bg-[#F8FAFC] dark:bg-[#0B0F17] text-slate-900 dark:text-slate-100 transition-colors pb-16 md:pb-0">
      {/* Navigation Drawer for Tabs across Mobile & Desktop */}
      <NavigationDrawer
        isOpen={isNavDrawerOpen}
        onClose={() => setIsNavDrawerOpen(false)}
        activeSection={activeSection}
        onSelectSection={setActiveSection}
        isDarkMode={isDarkMode}
        onToggleTheme={() => setIsDarkMode(!isDarkMode)}
        completedConceptsCount={completedConcepts.length}
        completedTutorialsCount={completedTutorials.length}
        onResetProgress={() => {
          setCompletedConcepts([]);
          setCompletedTutorials([]);
        }}
        onLaunchSimulator={() => handleOpenSimulatorPreset(selectedPresetId)}
      />

      {/* Top Header Bar */}
      <header className="sticky top-0 z-30 flex items-center justify-between gap-3 px-3 sm:px-6 py-2.5 sm:py-3.5 border-b border-slate-200 dark:border-slate-800 bg-white/95 dark:bg-[#0B0F17]/95 backdrop-blur-xs">
        {/* Left Slot: Hamburger Button (active in BOTH mobile and desktop) + Wordmark + Current Active Tab */}
        <div className="flex items-center gap-2 sm:gap-3 shrink-0">
          <button
            type="button"
            onClick={() => setIsNavDrawerOpen(true)}
            aria-label="Open tabs navigation menu"
            className="min-h-[44px] px-3 py-1.5 flex items-center justify-center gap-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-100/80 dark:bg-slate-800/80 text-slate-700 dark:text-slate-200 hover:text-sky-600 dark:hover:text-sky-400 hover:border-sky-500/40 hover:bg-sky-500/10 transition-colors cursor-pointer"
            title="Open Menu (All Tabs & Curriculum)"
          >
            <Menu className="w-5 h-5 shrink-0" />
            <span className="text-xs font-mono font-medium">Tabs</span>
          </button>

          <a
            href="#concepts"
            onClick={(e) => {
              e.preventDefault();
              setActiveSection('concepts');
            }}
            className="text-base sm:text-lg font-bold tracking-tight text-slate-900 dark:text-white font-display whitespace-nowrap shrink-0 hover:text-sky-600 dark:hover:text-sky-400 transition-colors"
          >
            KernelPulse
          </a>

          {/* Current Active Section Badge (click to open hamburger drawer) */}
          <div className="flex items-center gap-1.5 pl-2 sm:pl-3 border-l border-slate-200 dark:border-slate-800">
            <button
              type="button"
              onClick={() => setIsNavDrawerOpen(true)}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-mono font-medium rounded-md bg-sky-50 dark:bg-sky-950/60 text-sky-600 dark:text-sky-400 border border-sky-200 dark:border-sky-800/60 hover:bg-sky-100 dark:hover:bg-sky-900/40 cursor-pointer transition-colors"
              title="Click to view all tabs"
            >
              <span className="max-w-[120px] sm:max-w-none truncate">{sectionLabels[activeSection]}</span>
              <ChevronDown className="w-3.5 h-3.5 opacity-60 shrink-0" />
            </button>
          </div>
        </div>

        {/* Right Slot: Quick actions (Theme switch & Simulator launch) */}
        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => setIsDarkMode(!isDarkMode)}
            aria-label={isDarkMode ? 'Switch to light mode' : 'Switch to dark mode'}
            className="min-h-[44px] min-w-[44px] flex items-center justify-center rounded-lg border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
            title={isDarkMode ? 'Light Mode' : 'Dark Mode'}
          >
            {isDarkMode ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4 text-slate-700" />}
          </button>

          <button
            type="button"
            onClick={() => setActiveSection('simulator')}
            className="hidden sm:flex min-h-[44px] items-center px-3.5 py-2 text-xs font-medium text-white bg-sky-600 hover:bg-sky-500 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer shadow-xs"
          >
            Launch Simulator
          </button>
        </div>
      </header>

      {/* Workspace Context Bar: Curriculum Summary, Light/Dark Mode Toggle & Progress Reset */}
      <div className="border-b border-slate-200 dark:border-slate-800 bg-slate-100/70 dark:bg-[#111827]/70 px-3 sm:px-6 py-2.5">
        <div className="max-w-[1400px] mx-auto flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
          <div className="flex flex-wrap items-center gap-2 text-slate-600 dark:text-slate-400 font-mono tabular-nums">
            <span className="font-semibold text-slate-800 dark:text-slate-200">Go + Kernel C Academy</span>
            <span aria-hidden="true">·</span>
            <span>
              Concepts: <strong className="text-slate-900 dark:text-white">{completedConcepts.length}/{CONCEPT_TOPICS.length}</strong>
            </span>
            <span aria-hidden="true">·</span>
            <span>
              Labs: <strong className="text-slate-900 dark:text-white">{completedTutorials.length}/{TUTORIAL_LESSONS.length}</strong>
            </span>
            <span aria-hidden="true" className="hidden sm:inline">·</span>
            <span className="hidden sm:inline">
              Ref: <strong className="text-slate-900 dark:text-white">{TRACEABLE_SYSCALLS.length} Syscalls · {BPF_HELPERS_CATALOG.length} Helpers · {EBPF_MACROS_CATALOG.length} Macros</strong>
            </span>
          </div>

          <div className="flex items-center justify-between sm:justify-end gap-2 shrink-0">
            <button
              type="button"
              onClick={() => setIsNavDrawerOpen(true)}
              className="min-h-[38px] px-2.5 py-1 text-xs font-mono text-sky-600 dark:text-sky-400 hover:underline flex items-center gap-1 cursor-pointer"
            >
              <Compass className="w-3.5 h-3.5" />
              <span>Browse All Tabs</span>
            </button>

            <button
              type="button"
              onClick={() => {
                setCompletedConcepts([]);
                setCompletedTutorials([]);
              }}
              className="min-h-[38px] px-2.5 py-1 text-slate-500 hover:text-slate-900 dark:hover:text-white flex items-center gap-1 transition-colors cursor-pointer text-xs"
              title="Reset saved learning progress"
            >
              <RotateCcw className="w-3 h-3" />
              <span>Reset</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Content Container (1440px Desktop Presence + Mobile Clearance) */}
      <main className="max-w-[1400px] mx-auto px-3 sm:px-6 pt-4 pb-24 md:py-8">
        {activeSection === 'concepts' && (
          <ConceptExplorerView
            completedConcepts={completedConcepts}
            onToggleConceptComplete={handleToggleConceptComplete}
            onOpenTutorial={handleOpenTutorial}
            onOpenSimulatorPreset={handleOpenSimulatorPreset}
          />
        )}

        {activeSection === 'tutorials' && (
          <TutorialsView
            selectedTutorialId={selectedTutorialId}
            onSelectTutorial={setSelectedTutorialId}
            completedTutorials={completedTutorials}
            completedTutorialIds={completedTutorials}
            onToggleTutorialComplete={handleToggleTutorialComplete}
            onToggleCompleteTutorial={handleToggleTutorialComplete}
            onOpenSimulatorPreset={handleOpenSimulatorPreset}
          />
        )}

        {activeSection === 'syscalls' && (
          <SyscallsReferenceView onNavigateToTutorial={handleOpenTutorial} />
        )}

        {activeSection === 'helpers' && <HelpersReferenceView />}

        {activeSection === 'macros' && <MacrosReferenceView />}

        {activeSection === 'simulator' && (
          <KernelSimulatorView
            selectedPresetId={selectedPresetId}
            onSelectPreset={setSelectedPresetId}
          />
        )}

        {activeSection === 'templates' && (
          <ProjectTemplatesView
            onOpenSimulatorPreset={handleOpenSimulatorPreset}
          />
        )}
      </main>

      {/* Clean Minimal Footer */}
      <footer className="border-t border-slate-200 dark:border-slate-800 mt-16 py-6 px-6 text-xs text-slate-500 dark:text-slate-400">
        <div className="max-w-[1400px] mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div>
            KernelPulse — Complete Interactive eBPF Encyclopedia, Reference Hub &amp; Kernel Simulator
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <button type="button" onClick={() => setActiveSection('concepts')} className="hover:underline cursor-pointer">
              {CONCEPT_TOPICS.length} Concept Chapters
            </button>
            <span aria-hidden="true">·</span>
            <button type="button" onClick={() => setActiveSection('tutorials')} className="hover:underline cursor-pointer">
              {TUTORIAL_LESSONS.length} Step-by-Step Labs
            </button>
            <span aria-hidden="true">·</span>
            <button type="button" onClick={() => setActiveSection('syscalls')} className="hover:underline cursor-pointer">
              {TRACEABLE_SYSCALLS.length} Syscalls
            </button>
            <span aria-hidden="true">·</span>
            <button type="button" onClick={() => setActiveSection('helpers')} className="hover:underline cursor-pointer">
              {BPF_HELPERS_CATALOG.length} BPF Helpers
            </button>
            <span aria-hidden="true">·</span>
            <button type="button" onClick={() => setActiveSection('macros')} className="hover:underline cursor-pointer">
              {EBPF_MACROS_CATALOG.length} eBPF Macros
            </button>
            <span aria-hidden="true">·</span>
            <button type="button" onClick={() => setActiveSection('templates')} className="hover:underline cursor-pointer">
              6 Production Templates
            </button>
          </div>
        </div>
      </footer>

      {/* Mobile Ergonomic Fixed Bottom Tab Bar (Pattern 1) */}
      <nav
        aria-label="Mobile Bottom Navigation"
        className="md:hidden fixed bottom-0 left-0 right-0 z-40 bg-white/95 dark:bg-[#0B0F17]/95 backdrop-blur-md border-t border-slate-200 dark:border-slate-800 grid grid-cols-5 items-center h-15 px-1 shadow-lg"
      >
        <button
          type="button"
          onClick={() => setActiveSection('concepts')}
          className={`flex flex-col items-center justify-center min-h-[44px] py-1 transition-colors cursor-pointer ${
            activeSection === 'concepts'
              ? 'text-sky-600 dark:text-sky-400 font-semibold'
              : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
          }`}
        >
          <BookOpen className="w-4 h-4" />
          <span className="text-[10px] tracking-tight mt-0.5">Concepts</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveSection('tutorials')}
          className={`flex flex-col items-center justify-center min-h-[44px] py-1 transition-colors cursor-pointer ${
            activeSection === 'tutorials'
              ? 'text-sky-600 dark:text-sky-400 font-semibold'
              : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
          }`}
        >
          <GraduationCap className="w-4 h-4" />
          <span className="text-[10px] tracking-tight mt-0.5">Tutorials</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveSection('syscalls')}
          className={`flex flex-col items-center justify-center min-h-[44px] py-1 transition-colors cursor-pointer ${
            activeSection === 'syscalls'
              ? 'text-sky-600 dark:text-sky-400 font-semibold'
              : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
          }`}
        >
          <Terminal className="w-4 h-4" />
          <span className="text-[10px] tracking-tight mt-0.5">Syscalls</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveSection('simulator')}
          className={`flex flex-col items-center justify-center min-h-[44px] py-1 transition-colors cursor-pointer ${
            activeSection === 'simulator'
              ? 'text-sky-600 dark:text-sky-400 font-semibold'
              : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
          }`}
        >
          <Cpu className="w-4 h-4" />
          <span className="text-[10px] tracking-tight mt-0.5">Simulator</span>
        </button>

        <button
          type="button"
          onClick={() => setIsNavDrawerOpen(true)}
          className="flex flex-col items-center justify-center min-h-[44px] py-1 text-slate-500 dark:text-slate-400 hover:text-sky-600 dark:hover:text-sky-400 transition-colors cursor-pointer"
        >
          <Menu className="w-4 h-4" />
          <span className="text-[10px] tracking-tight mt-0.5 font-medium">All Tabs</span>
        </button>
      </nav>
    </div>
  );
}
