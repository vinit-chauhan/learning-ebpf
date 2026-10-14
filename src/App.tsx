/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import { Moon, Sun, RotateCcw } from 'lucide-react';
import { ConceptExplorerView } from './components/ConceptExplorerView';
import { TutorialsView } from './components/TutorialsView';
import { KernelSimulatorView } from './components/KernelSimulatorView';
import { ProjectTemplatesView } from './components/ProjectTemplatesView';
import { CONCEPT_TOPICS } from './data/conceptsData';
import { TUTORIAL_LESSONS } from './data/tutorialsData';
import { SIMULATOR_PRESETS } from './data/simulatorAndTemplatesData';

type ActiveSection = 'concepts' | 'tutorials' | 'simulator' | 'templates';

export default function App() {
  const [activeSection, setActiveSection] = useState<ActiveSection>('concepts');
  const [isDarkMode, setIsDarkMode] = useState<boolean>(() => {
    const saved = localStorage.getItem('kernelpulse_theme');
    return saved ? saved === 'dark' : true;
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
      return raw ? JSON.parse(raw) : [];
    } catch {
      return [];
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

  return (
    <div className="min-h-screen bg-[#F8FAFC] dark:bg-[#0B0F17] text-slate-900 dark:text-slate-100 transition-colors">
      {/* Strict 3-Zone Top Bar Contract */}
      <header className="sticky top-0 z-30 flex items-center justify-between gap-8 px-6 py-4 border-b border-slate-200 dark:border-slate-800 bg-white/95 dark:bg-[#0B0F17]/95 backdrop-blur-xs">
        {/* Zone 1: Single text element wordmark */}
        <a
          href="#concepts"
          onClick={(e) => {
            e.preventDefault();
            setActiveSection('concepts');
          }}
          className="text-lg font-bold tracking-tight text-slate-900 dark:text-white font-display whitespace-nowrap shrink-0"
        >
          KernelPulse
        </a>

        {/* Zone 2: 4 concise single-line text navigation links */}
        <nav className="flex items-center gap-6 text-sm font-medium text-slate-600 dark:text-slate-300 overflow-x-auto">
          <a
            href="#concepts"
            onClick={(e) => {
              e.preventDefault();
              setActiveSection('concepts');
            }}
            className={`transition-colors whitespace-nowrap shrink-0 ${
              activeSection === 'concepts'
                ? 'text-sky-600 dark:text-sky-400 underline underline-offset-8 decoration-2'
                : 'hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            Concepts & Flows
          </a>
          <a
            href="#tutorials"
            onClick={(e) => {
              e.preventDefault();
              setActiveSection('tutorials');
            }}
            className={`transition-colors whitespace-nowrap shrink-0 ${
              activeSection === 'tutorials'
                ? 'text-sky-600 dark:text-sky-400 underline underline-offset-8 decoration-2'
                : 'hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            Tutorials
          </a>
          <a
            href="#simulator"
            onClick={(e) => {
              e.preventDefault();
              setActiveSection('simulator');
            }}
            className={`transition-colors whitespace-nowrap shrink-0 ${
              activeSection === 'simulator'
                ? 'text-sky-600 dark:text-sky-400 underline underline-offset-8 decoration-2'
                : 'hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            Kernel Simulator
          </a>
          <a
            href="#templates"
            onClick={(e) => {
              e.preventDefault();
              setActiveSection('templates');
            }}
            className={`transition-colors whitespace-nowrap shrink-0 ${
              activeSection === 'templates'
                ? 'text-sky-600 dark:text-sky-400 underline underline-offset-8 decoration-2'
                : 'hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            Project Templates
          </a>
        </nav>

        {/* Zone 3: 1 primary action button */}
        <div className="flex items-center shrink-0">
          <button
            onClick={() => setActiveSection('simulator')}
            className="px-4 py-2 text-xs font-medium text-white bg-sky-600 hover:bg-sky-500 rounded-lg transition-colors whitespace-nowrap shrink-0"
          >
            Launch Simulator
          </button>
        </div>
      </header>

      {/* Workspace Context Bar: Curriculum Summary, Light/Dark Mode Toggle & Progress Reset */}
      <div className="border-b border-slate-200 dark:border-slate-800 bg-slate-100/70 dark:bg-[#111827]/70 px-6 py-2.5">
        <div className="max-w-[1400px] mx-auto flex flex-wrap items-center justify-between gap-4 text-xs">
          <div className="flex flex-wrap items-center gap-2 text-slate-600 dark:text-slate-400 font-mono tabular-nums">
            <span>Go (cilium/ebpf) + Kernel C Academy</span>
            <span aria-hidden="true">·</span>
            <span>
              Concepts Read: <strong className="text-slate-900 dark:text-white">{completedConcepts.length}/{CONCEPT_TOPICS.length}</strong>
            </span>
            <span aria-hidden="true">·</span>
            <span>
              Tutorials Completed: <strong className="text-slate-900 dark:text-white">{completedTutorials.length}/{TUTORIAL_LESSONS.length}</strong>
            </span>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => setIsDarkMode(!isDarkMode)}
              className="flex items-center gap-1.5 px-3 py-1 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-200 hover:border-slate-400 transition-colors whitespace-nowrap shrink-0"
            >
              {isDarkMode ? (
                <>
                  <Sun className="w-3.5 h-3.5 text-amber-400" />
                  <span>Light Mode</span>
                </>
              ) : (
                <>
                  <Moon className="w-3.5 h-3.5 text-slate-700" />
                  <span>Dark Mode</span>
                </>
              )}
            </button>

            <button
              onClick={() => {
                setCompletedConcepts([]);
                setCompletedTutorials([]);
              }}
              className="flex items-center gap-1 px-2.5 py-1 rounded-md text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors whitespace-nowrap shrink-0"
              title="Reset saved learning progress"
            >
              <RotateCcw className="w-3 h-3" />
              <span>Reset Progress</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Content Container (1440px Desktop Presence) */}
      <main className="max-w-[1400px] mx-auto px-6 py-8">
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
            onToggleTutorialComplete={handleToggleTutorialComplete}
            onOpenSimulatorPreset={handleOpenSimulatorPreset}
          />
        )}

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
            KernelPulse — Complete Interactive eBPF Encyclopedia, Tracing Curriculum & Kernel Simulator
          </div>
          <div className="flex items-center gap-4">
            <button onClick={() => setActiveSection('concepts')} className="hover:underline">
              10 Concept Chapters
            </button>
            <span aria-hidden="true">·</span>
            <button onClick={() => setActiveSection('tutorials')} className="hover:underline">
              15 Step-by-Step Labs
            </button>
            <span aria-hidden="true">·</span>
            <button onClick={() => setActiveSection('templates')} className="hover:underline">
              6 Production Templates
            </button>
          </div>
        </div>
      </footer>
    </div>
  );
}
