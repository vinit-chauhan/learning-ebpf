import React, { useState } from 'react';
import {
  ArrowRight,
  CheckCircle2,
  Code2,
  FileCode,
  Layers,
  Play,
  Shield,
  Terminal
} from 'lucide-react';
import { PROJECT_TEMPLATES } from '../data/simulatorAndTemplatesData';
import { ProjectTemplate } from '../types/ebpf';
import { SyntaxHighlighter } from './SyntaxHighlighter';

interface ProjectTemplatesViewProps {
  onOpenSimulatorPreset: (presetId: string) => void;
}

const DOMAINS = [
  'All',
  'Cloud-Native Networking',
  'Runtime Security',
  'Performance Engineering'
] as const;

export const ProjectTemplatesView: React.FC<ProjectTemplatesViewProps> = ({
  onOpenSimulatorPreset
}) => {
  const [selectedDomain, setSelectedDomain] = useState<(typeof DOMAINS)[number]>('All');
  const [activeTemplateId, setActiveTemplateId] = useState<string>(PROJECT_TEMPLATES[0].id);
  const [activeFileIdx, setActiveFileIdx] = useState<number>(0);
  const [showMobileTemplateList, setShowMobileTemplateList] = useState<boolean>(false);

  const filteredTemplates = PROJECT_TEMPLATES.filter(
    (t) => selectedDomain === 'All' || t.domain === selectedDomain
  );

  const activeTemplate: ProjectTemplate =
    PROJECT_TEMPLATES.find((t) => t.id === activeTemplateId) || PROJECT_TEMPLATES[0];

  const activeFile = activeTemplate.files[activeFileIdx] || activeTemplate.files[0];

  const handleSelectTemplate = (id: string) => {
    setActiveTemplateId(id);
    setActiveFileIdx(0);
    setShowMobileTemplateList(false);
  };

  return (
    <div className="space-y-6 sm:space-y-8">
      {/* Top Domain Filter Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
        <div className="flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-x-auto max-w-full">
          {DOMAINS.map((dom) => (
            <button
              key={dom}
              onClick={() => setSelectedDomain(dom)}
              className={`min-h-[38px] px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                selectedDomain === dom
                  ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
              }`}
            >
              {dom === 'All' ? `All Templates (${PROJECT_TEMPLATES.length})` : dom}
            </button>
          ))}
        </div>

        <div className="text-xs text-slate-500 dark:text-slate-400">
          Production-ready C + Go (<code className="font-mono">cilium/ebpf</code>) starter architectures
        </div>
      </div>

      {/* Mobile Quick Template Switcher Bar (Visible only on mobile < lg) */}
      <div className="lg:hidden p-3.5 border border-sky-500/30 bg-sky-500/5 rounded-xl">
        <div className="flex items-center justify-between gap-2">
          <div className="min-w-0 flex-1">
            <div className="text-[10px] font-mono uppercase text-sky-500 dark:text-sky-400">
              Template {activeTemplate.index} · {activeTemplate.domain}
            </div>
            <div className="text-xs font-semibold text-slate-900 dark:text-white truncate">
              {activeTemplate.title}
            </div>
          </div>

          <button
            type="button"
            onClick={() => setShowMobileTemplateList(!showMobileTemplateList)}
            className="min-h-[44px] px-3 py-1.5 text-xs font-mono font-semibold border border-sky-500/40 bg-white dark:bg-slate-900 text-sky-600 dark:text-sky-400 rounded-lg flex items-center gap-1.5 shrink-0 shadow-xs cursor-pointer"
          >
            <span>{showMobileTemplateList ? 'Hide Templates' : `Switch (${filteredTemplates.length})`}</span>
          </button>
        </div>

        {/* Expandable Mobile Template List */}
        {showMobileTemplateList && (
          <div className="mt-3 space-y-1.5 max-h-[320px] overflow-y-auto p-1.5 border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-lg">
            {filteredTemplates.map((tpl) => {
              const isSelected = tpl.id === activeTemplate.id;
              return (
                <button
                  key={tpl.id}
                  type="button"
                  onClick={() => handleSelectTemplate(tpl.id)}
                  className={`w-full min-h-[44px] text-left p-2.5 rounded-md border transition-all flex items-center justify-between gap-2 cursor-pointer ${
                    isSelected
                      ? 'border-sky-500 bg-sky-500/10 text-sky-950 dark:text-sky-200 font-semibold'
                      : 'border-slate-200 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800/50 text-slate-700 dark:text-slate-300'
                  }`}
                >
                  <div className="min-w-0">
                    <div className="text-xs font-mono truncate">
                      {tpl.index}. {tpl.title}
                    </div>
                    <div className="text-[10px] text-slate-500 dark:text-slate-400">
                      {tpl.domain} · {tpl.hookTypes.join(', ')}
                    </div>
                  </div>
                  {isSelected && (
                    <span className="text-[10px] font-mono text-sky-500 shrink-0">ACTIVE</span>
                  )}
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* Desktop Template Selector Grid (hidden on mobile if user has collapsed it) */}
      <div className={`grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 ${showMobileTemplateList ? 'hidden lg:grid' : 'hidden lg:grid'}`}>
        {filteredTemplates.map((tpl) => {
          const isSelected = tpl.id === activeTemplate.id;
          return (
            <button
              key={tpl.id}
              onClick={() => handleSelectTemplate(tpl.id)}
              className={`text-left p-5 rounded-xl border transition-all flex flex-col justify-between cursor-pointer ${
                isSelected
                  ? 'border-sky-500 bg-white dark:bg-[#111827] shadow-xs'
                  : 'border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-900/40 hover:bg-white dark:hover:bg-[#111827]'
              }`}
            >
              <div className="space-y-2">
                <div className="text-xs font-mono text-slate-500 dark:text-slate-400">
                  {tpl.index} · {tpl.domain} · {tpl.hookTypes.join(' + ')}
                </div>
                <h3 className="text-sm font-semibold text-slate-900 dark:text-white leading-snug">
                  {tpl.title}
                </h3>
                <p className="text-xs text-slate-600 dark:text-slate-400 line-clamp-2">
                  {tpl.summary}
                </p>
              </div>
              <div className="pt-4 mt-3 border-t border-slate-200/70 dark:border-slate-800/80 flex items-center justify-between text-xs font-mono text-sky-600 dark:text-sky-400">
                <span>{tpl.minKernel}</span>
                <span>Inspect Architecture →</span>
              </div>
            </button>
          );
        })}
      </div>

      {/* Active Template Deep-Dive Blueprint & Multi-File Code Viewer */}
      <div className="border border-slate-200 dark:border-slate-800 rounded-xl bg-white dark:bg-[#111827] p-6 lg:p-8 space-y-8">
        {/* Header & Simulator CTA */}
        <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-6 border-b border-slate-200 dark:border-slate-800 pb-6">
          <div className="space-y-2 max-w-3xl">
            <div className="text-xs font-mono text-sky-600 dark:text-sky-400">
              Template {activeTemplate.index} · {activeTemplate.domain} · Hooks: {activeTemplate.hookTypes.join(', ')} · {activeTemplate.minKernel}
            </div>
            <h2 className="text-2xl font-bold text-slate-900 dark:text-white">
              {activeTemplate.title}
            </h2>
            <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
              {activeTemplate.problemSolved}
            </p>
            <div className="text-xs text-slate-500 dark:text-slate-400 pt-1">
              <strong>Real-World Lineage:</strong> {activeTemplate.realWorldInspiration}
            </div>
          </div>

          <button
            onClick={() => onOpenSimulatorPreset(activeTemplate.simulatorPresetId)}
            className="px-4 py-2.5 text-xs font-medium text-white bg-sky-600 hover:bg-sky-500 rounded-lg transition-colors flex items-center gap-2 whitespace-nowrap shrink-0"
          >
            <Play className="w-3.5 h-3.5" />
            <span>Launch Template in Live Simulator</span>
          </button>
        </div>

        {/* 4-Stage Architecture Data-Flow Diagram */}
        <div className="space-y-3">
          <div className="text-xs font-mono font-semibold text-slate-700 dark:text-slate-300">
            End-to-End Kernel-to-Userspace Architecture Pipeline
          </div>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            {activeTemplate.architectureFlow.map((stage, i) => (
              <div
                key={i}
                className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-[#0B0F17] space-y-1.5"
              >
                <div className="text-xs font-mono font-semibold text-sky-600 dark:text-sky-400">
                  {stage.stage}
                </div>
                <div className="text-xs font-semibold text-slate-900 dark:text-white font-mono">
                  {stage.component}
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                  {stage.description}
                </p>
              </div>
            ))}
          </div>
        </div>

        {/* Multi-File Source Code Explorer */}
        <div className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-x-auto max-w-full">
              {activeTemplate.files.map((file, idx) => (
                <button
                  key={file.filename}
                  onClick={() => setActiveFileIdx(idx)}
                  className={`min-h-[36px] px-3 py-1.5 text-xs font-mono font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    activeFileIdx === idx
                      ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-xs'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  {file.filename}
                </button>
              ))}
            </div>
            <span className="text-xs text-slate-500 dark:text-slate-400">
              {activeFile.description}
            </span>
          </div>

          <SyntaxHighlighter
            code={activeFile.content}
            language={activeFile.language}
            title={activeFile.filename}
            badgeText={activeFile.description}
          />
        </div>

        {/* Production Deployment & Hardening Checklist */}
        <div className="p-5 rounded-xl bg-slate-50 dark:bg-[#0B0F17] border border-slate-200 dark:border-slate-800 space-y-2.5">
          <div className="text-xs font-mono font-semibold text-emerald-600 dark:text-emerald-400">
            Production Deployment & Kernel Hardening Checklist
          </div>
          <ul className="space-y-2 text-xs text-slate-700 dark:text-slate-300">
            {activeTemplate.productionChecklist.map((item, idx) => (
              <li key={idx} className="flex items-start gap-2.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
};
