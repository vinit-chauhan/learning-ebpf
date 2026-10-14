export type SkillTier = 'beginner' | 'intermediate' | 'advanced';

export type HookCategory =
  | 'XDP'
  | 'TC'
  | 'kprobe'
  | 'kretprobe'
  | 'tracepoint'
  | 'uprobe'
  | 'lsm'
  | 'sched';

export type ConceptCategory =
  | 'Foundations & Architecture'
  | 'Kernel Hook Subsystems'
  | 'BPF Maps & Ring Buffers'
  | 'Verifier, JIT & CO-RE'
  | 'Go cilium/ebpf Control Plane';

export interface TradeOffRow {
  dimension: string;
  primaryChoice: string;
  alternativeChoice: string;
  winner: 'primary' | 'alternative' | 'tie';
}

export interface ConceptTopic {
  id: string;
  index: string;
  title: string;
  subtitle: string;
  category: ConceptCategory;
  readTime: string;
  minKernel: string;
  summary: string;
  whatIsIt: {
    heading: string;
    paragraphs: string[];
    keyTakeaways: string[];
    mentalModelAnalogy: string;
  };
  howItWorks: {
    heading: string;
    paragraphs: string[];
    lifecycleSteps: {
      step: string;
      actor: 'USERSPACE' | 'SYSCALL' | 'VERIFIER' | 'KERNEL_HOOK' | 'BPF_MAP';
      title: string;
      detail: string;
    }[];
    codeLanguage: 'c' | 'go';
    codeTitle: string;
    codeSnippet: string;
  };
  whyUseInsteadOf: {
    heading: string;
    primaryTech: string;
    alternativeTech: string;
    rationaleParagraphs: string[];
    comparisonTable: TradeOffRow[];
    whenToUsePrimary: string[];
    whenToUseAlternative: string[];
  };
  comprehensionCheck: {
    question: string;
    options: string[];
    correctIndex: number;
    explanation: string;
  };
  relatedTutorialId: string;
  simulatorPresetId: string;
}

export interface TutorialStep {
  stepNumber: number;
  title: string;
  explanation: string;
  activePipelineNode: 'userspace' | 'syscall' | 'verifier' | 'hook' | 'map' | 'ringbuf';
  cHighlightLines: [number, number];
  goHighlightLines: [number, number];
  keyInsight: string;
}

export interface TutorialLesson {
  id: string;
  index: string;
  title: string;
  tier: SkillTier;
  hookType: HookCategory;
  duration: string;
  minKernel: string;
  summary: string;
  learningObjectives: string[];
  conceptGuide: {
    whatIsTitle: string;
    whatIsContent: string;
    howItWorksTitle: string;
    howItWorksContent: string;
    whyUseInsteadTitle: string;
    whyUseInsteadContent: string;
    comparisonHighlight: {
      chosenApproach: string;
      alternativeApproach: string;
      overheadDelta: string;
      stabilityNote: string;
    };
  };
  cFileName: string;
  cCode: string;
  goFileName: string;
  goCode: string;
  steps: TutorialStep[];
  verifierChallenge: {
    title: string;
    prompt: string;
    buggySnippet: string;
    fixedSnippet: string;
    verifierErrorOutput: string;
    verifierPassOutput: string;
    explanation: string;
  };
  simulatorPresetId: string;
}

export interface SafetyToggleConfig {
  id: 'packetBoundsCheck' | 'nullMapPointerCheck' | 'boundedLoopCheck' | 'stackSizeLimitCheck';
  label: string;
  description: string;
  cLineNumber: number;
  buggyLineReplacement: string;
  verifierErrorLog: string[];
  failedRegisterState: Record<string, string>;
}

export interface BpfMapEntry {
  key: string;
  rawHexKey: string;
  value: string;
  numericValue: number;
  cpuCore: number;
  updatedAt: string;
}

export interface KernelSimulatedEvent {
  id: string;
  timestamp: string;
  cpu: number;
  pid: number;
  comm: string;
  hookPoint: HookCategory;
  eventType: string;
  verdict: 'XDP_PASS' | 'XDP_DROP' | 'ALLOW' | 'BLOCK' | 'TRACED';
  latencyNs: number;
  details: string;
  srcIp?: string;
  dstPort?: number;
}

export interface SimulatorPreset {
  id: string;
  name: string;
  hookPoint: HookCategory;
  category: 'Networking' | 'Security' | 'Observability';
  description: string;
  mapName: string;
  mapType: 'BPF_MAP_TYPE_HASH' | 'BPF_MAP_TYPE_PERCPU_ARRAY' | 'BPF_MAP_TYPE_RINGBUF' | 'BPF_MAP_TYPE_LPM_TRIE';
  cCode: string;
  goCode: string;
  bpfBytecode: string[];
  safetyToggles: SafetyToggleConfig[];
  initialMapEntries: BpfMapEntry[];
  initialLatencyHistogram: { bucketLabel: string; rangeUs: string; count: number }[];
}

export interface ProjectTemplateFile {
  filename: string;
  language: 'c' | 'go' | 'makefile' | 'dockerfile';
  description: string;
  content: string;
}

export interface ProjectTemplate {
  id: string;
  index: string;
  title: string;
  domain: 'Cloud-Native Networking' | 'Runtime Security' | 'Performance Engineering';
  hookTypes: HookCategory[];
  difficulty: SkillTier;
  minKernel: string;
  summary: string;
  realWorldInspiration: string;
  problemSolved: string;
  architectureFlow: {
    stage: string;
    component: string;
    description: string;
  }[];
  productionChecklist: string[];
  files: ProjectTemplateFile[];
  simulatorPresetId: string;
}
