import React, { useState } from 'react';
import { Check, Copy, AlertTriangle } from 'lucide-react';

interface SyntaxHighlighterProps {
  code: string;
  language: 'c' | 'go' | 'bpf-asm' | 'makefile' | 'dockerfile';
  title?: string;
  subtitle?: string;
  badgeText?: string;
  highlightRange?: [number, number] | null;
  highlightedLines?: number[];
  errorLineNumber?: number | null;
  errorMessage?: string | null;
  onLineClick?: (lineNumber: number) => void;
  selectedLine?: number | null;
  maxHeight?: string;
}

interface Token {
  type: 'keyword' | 'type' | 'function' | 'macro' | 'string' | 'comment' | 'number' | 'operator' | 'plain';
  value: string;
}

const C_KEYWORDS = new Set([
  'if', 'else', 'for', 'while', 'return', 'struct', 'union', 'enum', 'typedef',
  'static', 'inline', 'const', 'volatile', 'sizeof', 'switch', 'case', 'default', 'break', 'goto'
]);

const C_TYPES = new Set([
  'void', 'char', 'short', 'int', 'long', 'unsigned', 'signed', 'bool',
  '__u8', '__u16', '__u32', '__u64', '__s8', '__s16', '__s32', '__s64',
  '__be16', '__be32', '__be64', 'u8', 'u16', 'u32', 'u64', 'pid_t', 'size_t',
  'xdp_md', 'pt_regs', '__sk_buff', 'ethhdr', 'iphdr', 'tcphdr', 'udphdr',
  'trace_event_raw_sys_enter', 'task_struct', 'file', 'sock'
]);

const C_MACROS = new Set([
  'SEC', 'BPF_MAP_TYPE_HASH', 'BPF_MAP_TYPE_ARRAY', 'BPF_MAP_TYPE_PERCPU_ARRAY',
  'BPF_MAP_TYPE_RINGBUF', 'BPF_MAP_TYPE_PERF_EVENT_ARRAY', 'BPF_MAP_TYPE_LPM_TRIE',
  'BPF_ANY', 'XDP_PASS', 'XDP_DROP', 'XDP_TX', 'XDP_ABORTED', 'XDP_REDIRECT',
  'TC_ACT_OK', 'TC_ACT_SHOT', 'ETH_P_IP', 'IPPROTO_TCP', 'IPPROTO_UDP', 'IPPROTO_ICMP',
  'BPF_CORE_READ', 'BPF_KPROBE', 'BPF_KRETPROBE', 'BPF_PROG', '__uint', '__type', '__always_inline'
]);

const GO_KEYWORDS = new Set([
  'package', 'import', 'func', 'var', 'const', 'type', 'struct', 'interface',
  'map', 'chan', 'go', 'defer', 'return', 'if', 'else', 'for', 'range', 'select',
  'switch', 'case', 'default', 'break', 'continue', 'nil', 'true', 'false'
]);

const GO_TYPES = new Set([
  'uint8', 'uint16', 'uint32', 'uint64', 'int8', 'int16', 'int32', 'int64',
  'int', 'uint', 'byte', 'rune', 'string', 'bool', 'error', 'uintptr',
  'CollectionSpec', 'Map', 'Program', 'Link', 'Reader', 'Record'
]);

function tokenizeLine(line: string, language: string): Token[] {
  const trimmed = line.trim();
  if (trimmed.startsWith('//') || (language !== 'c' && language !== 'go' && trimmed.startsWith('#'))) {
    return [{ type: 'comment', value: line }];
  }
  if (language === 'c' && trimmed.startsWith('#')) {
    return [{ type: 'macro', value: line }];
  }

  const tokens: Token[] = [];
  const regex = /(\/\/.*$|\/\*[\s\S]*?\*\/|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`[^`]*`|\b0x[0-9a-fA-F]+\b|\b\d+\b|\b[A-Za-z_][A-Za-z0-9_]*\b|[{}()[\].,:;+-/*=&|<>!~?]+)/g;

  let lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(line)) !== null) {
    if (match.index > lastIndex) {
      tokens.push({ type: 'plain', value: line.slice(lastIndex, match.index) });
    }
    const val = match[0];

    if (val.startsWith('//') || val.startsWith('/*')) {
      tokens.push({ type: 'comment', value: val });
    } else if (val.startsWith('"') || val.startsWith("'") || val.startsWith('`')) {
      tokens.push({ type: 'string', value: val });
    } else if (/^(0x[0-9a-fA-F]+|\d+)$/.test(val)) {
      tokens.push({ type: 'number', value: val });
    } else if (/^[A-Za-z_]/.test(val)) {
      const nextChar = line[regex.lastIndex];
      if (language === 'c') {
        if (C_KEYWORDS.has(val)) {
          tokens.push({ type: 'keyword', value: val });
        } else if (C_TYPES.has(val)) {
          tokens.push({ type: 'type', value: val });
        } else if (C_MACROS.has(val) || /^[A-Z][A-Z0-9_]{2,}$/.test(val)) {
          tokens.push({ type: 'macro', value: val });
        } else if (nextChar === '(' || val.startsWith('bpf_')) {
          tokens.push({ type: 'function', value: val });
        } else {
          tokens.push({ type: 'plain', value: val });
        }
      } else if (language === 'go') {
        if (GO_KEYWORDS.has(val)) {
          tokens.push({ type: 'keyword', value: val });
        } else if (GO_TYPES.has(val)) {
          tokens.push({ type: 'type', value: val });
        } else if (nextChar === '(') {
          tokens.push({ type: 'function', value: val });
        } else {
          tokens.push({ type: 'plain', value: val });
        }
      } else if (language === 'bpf-asm') {
        if (/^r([0-9]|10)$/.test(val)) {
          tokens.push({ type: 'type', value: val });
        } else if (['call', 'exit', 'if', 'goto', 'lock'].includes(val)) {
          tokens.push({ type: 'keyword', value: val });
        } else {
          tokens.push({ type: 'plain', value: val });
        }
      } else {
        tokens.push({ type: 'plain', value: val });
      }
    } else {
      tokens.push({ type: 'operator', value: val });
    }

    lastIndex = regex.lastIndex;
  }

  if (lastIndex < line.length) {
    tokens.push({ type: 'plain', value: line.slice(lastIndex) });
  }

  return tokens;
}

const TOKEN_CLASSES: Record<Token['type'], string> = {
  keyword: 'text-purple-600 dark:text-purple-400 font-medium',
  type: 'text-sky-600 dark:text-sky-400',
  function: 'text-amber-600 dark:text-amber-300',
  macro: 'text-emerald-600 dark:text-emerald-400 font-medium',
  string: 'text-teal-700 dark:text-teal-300',
  comment: 'text-slate-400 dark:text-slate-500 italic',
  number: 'text-orange-600 dark:text-orange-400',
  operator: 'text-slate-500 dark:text-slate-400',
  plain: 'text-slate-800 dark:text-slate-200',
};

export const SyntaxHighlighter: React.FC<SyntaxHighlighterProps> = ({
  code,
  language,
  title,
  subtitle,
  badgeText,
  highlightRange,
  highlightedLines,
  errorLineNumber,
  errorMessage,
  onLineClick,
  selectedLine,
  maxHeight = 'max-h-[520px]',
}) => {
  const [copied, setCopied] = useState(false);
  const lines = code.split('\n');
  const effectiveBadge = badgeText || subtitle;

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  return (
    <div className="border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden bg-slate-50/80 dark:bg-[#0B0F17]">
      {title && (
        <div className="flex items-center justify-between px-4 py-2.5 border-b border-slate-200 dark:border-slate-800 bg-slate-100/80 dark:bg-slate-900/90">
          <div className="flex items-center gap-2 text-xs font-mono text-slate-700 dark:text-slate-300">
            <span className="font-semibold">{title}</span>
            {effectiveBadge && (
              <>
                <span aria-hidden="true" className="text-slate-400">·</span>
                <span className="text-slate-500 dark:text-slate-400">{effectiveBadge}</span>
              </>
            )}
          </div>
          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded transition-colors whitespace-nowrap shrink-0"
            title="Copy source code"
          >
            {copied ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-500" />
                <span>Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copy Code</span>
              </>
            )}
          </button>
        </div>
      )}

      <div className={`overflow-x-auto overflow-y-auto ${maxHeight} py-3 text-xs leading-relaxed font-mono tabular-nums`}>
        {lines.map((line, idx) => {
          const lineNum = idx + 1;
          const isHighlighted =
            (highlightRange && lineNum >= highlightRange[0] && lineNum <= highlightRange[1]) ||
            (highlightedLines && highlightedLines.includes(lineNum));
          const isErrorLine = errorLineNumber === lineNum;
          const isSelected = selectedLine === lineNum;
          const tokens = tokenizeLine(line, language);

          return (
            <React.Fragment key={lineNum}>
              <div
                onClick={() => onLineClick && onLineClick(lineNum)}
                className={`flex items-start px-4 py-0.5 transition-colors ${
                  onLineClick ? 'cursor-pointer' : ''
                } ${
                  isErrorLine
                    ? 'bg-red-500/15 dark:bg-red-950/60'
                    : isHighlighted || isSelected
                    ? 'bg-sky-500/12 dark:bg-sky-950/50'
                    : 'hover:bg-slate-200/50 dark:hover:bg-slate-800/40'
                }`}
              >
                <span
                  className={`w-9 shrink-0 select-none pr-3 text-right ${
                    isErrorLine
                      ? 'text-red-600 dark:text-red-400 font-bold'
                      : isHighlighted || isSelected
                      ? 'text-sky-600 dark:text-sky-400 font-semibold'
                      : 'text-slate-400 dark:text-slate-600'
                  }`}
                >
                  {lineNum}
                </span>
                <span className="whitespace-pre flex-1">
                  {tokens.length === 0 ? ' ' : tokens.map((tok, tIdx) => (
                    <span key={tIdx} className={TOKEN_CLASSES[tok.type]}>
                      {tok.value}
                    </span>
                  ))}
                </span>
              </div>
              {isErrorLine && errorMessage && (
                <div className="flex items-center gap-2 px-12 py-1.5 bg-red-100/90 dark:bg-red-950/90 text-red-800 dark:text-red-300 text-[11px] font-mono border-y border-red-300 dark:border-red-800/80">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0 text-red-600 dark:text-red-400" />
                  <span>VERIFIER REJECTION: {errorMessage}</span>
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
};
