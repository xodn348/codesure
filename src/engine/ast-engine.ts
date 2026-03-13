import type { Finding } from '../types.js';
import { SOURCES, SINKS } from '../data/sources-sinks.js';
import { safeTruncate } from './sanitize.js';

interface TaintBinding {
  sourceName: string;
  hops: number;
  chain: string[];
}

const IDENTIFIER_REGEX = /[A-Za-z_$][\w$]*/g;
const VARIABLE_DECLARATION_REGEX = /^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+?)\s*;?\s*$/;
const VARIABLE_ASSIGNMENT_REGEX = /^\s*([A-Za-z_$][\w$]*)\s*=\s*(.+?)\s*;?\s*$/;

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function findMatchingSource(expression: string): string | undefined {
  const normalized = expression.trim();

  for (const source of SOURCES) {
    if (normalized === source) {
      return source;
    }

    if (normalized.startsWith(`${source}.`) || normalized.startsWith(`${source}[`)) {
      return source;
    }
  }

  return undefined;
}

function getTaintedIdentifiers(expression: string, taintMap: Map<string, TaintBinding>): string[] {
  const identifiers = expression.match(IDENTIFIER_REGEX) ?? [];
  const tainted = new Set<string>();

  for (const identifier of identifiers) {
    if (taintMap.has(identifier)) {
      tainted.add(identifier);
    }
  }

  return [...tainted];
}

function createFinding(params: {
  line: string;
  lineNumber: number;
  filePath?: string;
  sourceName: string;
  sinkName: string;
  hopCount: number;
  evidenceChain: string[];
  columnHint: string;
}): Finding {
  const column = Math.max(0, params.line.indexOf(params.columnHint));

  return {
    id: `ast-taint-L${params.lineNumber}`,
    severity: 'high',
    category: 'vulnerability',
    confidence: 85,
    rule_id: 'ast.taint.source-to-sink',
    message: `Taint flows from ${params.sourceName} to ${params.sinkName} via ${params.hopCount}-hop assignment`,
    location: {
      file: params.filePath,
      line: params.lineNumber,
      column,
    },
    snippet: safeTruncate(params.line.trim(), 200),
    evidence_chain: params.evidenceChain,
  };
}

function tryTrackAssignment(target: string, expression: string, taintMap: Map<string, TaintBinding>): void {
  const sourceName = findMatchingSource(expression);
  if (sourceName !== undefined) {
    taintMap.set(target, {
      sourceName,
      hops: 1,
      chain: [target],
    });
    return;
  }

  const taintedIdentifiers = getTaintedIdentifiers(expression, taintMap);
  if (taintedIdentifiers.length === 0) {
    return;
  }

  const parentName = taintedIdentifiers[0] as string;
  const parentTaint = taintMap.get(parentName);
  if (parentTaint === undefined || parentTaint.hops >= 3) {
    return;
  }

  taintMap.set(target, {
    sourceName: parentTaint.sourceName,
    hops: parentTaint.hops + 1,
    chain: [...parentTaint.chain, target],
  });
}

function trackAssignments(line: string, taintMap: Map<string, TaintBinding>): void {
  const declarationMatch = line.match(VARIABLE_DECLARATION_REGEX);
  if (declarationMatch !== null) {
    const [, target = '', expression = ''] = declarationMatch;
    tryTrackAssignment(target, expression, taintMap);
    return;
  }

  const assignmentMatch = line.match(VARIABLE_ASSIGNMENT_REGEX);
  if (assignmentMatch !== null) {
    const [, target = '', expression = ''] = assignmentMatch;
    tryTrackAssignment(target, expression, taintMap);
  }
}

function emitTaintFindings(
  expression: string, sinkName: string, line: string, lineNumber: number,
  taintMap: Map<string, TaintBinding>, filePath: string | undefined,
  findings: Finding[], seen: Set<string>,
): void {
  const directSource = findMatchingSource(expression);
  if (directSource !== undefined) {
    const key = `${lineNumber}:${sinkName}:${directSource}:0`;
    if (!seen.has(key)) {
      findings.push(createFinding({ line, lineNumber, filePath, sourceName: directSource, sinkName, hopCount: 0, evidenceChain: [], columnHint: sinkName }));
      seen.add(key);
    }
    return;
  }

  for (const identifier of getTaintedIdentifiers(expression, taintMap)) {
    const taint = taintMap.get(identifier);
    if (taint === undefined) continue;

    const key = `${lineNumber}:${sinkName}:${taint.sourceName}:${taint.hops}:${taint.chain.join('>')}`;
    if (seen.has(key)) continue;

    findings.push(createFinding({ line, lineNumber, filePath, sourceName: taint.sourceName, sinkName, hopCount: taint.hops, evidenceChain: taint.chain, columnHint: sinkName }));
    seen.add(key);
  }
}

function checkFunctionSink(line: string, sinkName: string, lineNumber: number, taintMap: Map<string, TaintBinding>, filePath: string | undefined, findings: Finding[], seen: Set<string>): void {
  const sinkPattern = sinkName === 'new Function'
    ? /new\s+Function\s*\((.*)\)/
    : new RegExp(`${escapeRegex(sinkName)}\\s*\\((.*)\\)`);

  const match = line.match(sinkPattern);
  if (match === null) return;

  emitTaintFindings(match[1] ?? '', sinkName, line, lineNumber, taintMap, filePath, findings, seen);
}

function checkPropertySink(line: string, lineNumber: number, taintMap: Map<string, TaintBinding>, filePath: string | undefined, findings: Finding[], seen: Set<string>): void {
  const propertyMatch = line.match(/\.(innerHTML|outerHTML)\s*=\s*(.+?)\s*;?\s*$/);
  if (propertyMatch === null) return;

  const sinkName = propertyMatch[1] as string;
  emitTaintFindings(propertyMatch[2] ?? '', sinkName, line, lineNumber, taintMap, filePath, findings, seen);
}

/**
 * Performs 3-hop taint analysis tracking data flow from sources to sinks.
 *
 * Tracks variable assignments from taint sources (e.g. `req.query`, `document.cookie`)
 * through up to 3 assignment hops to dangerous sinks (e.g. `eval()`, `innerHTML`).
 *
 * @param code - Source code to analyze. Returns empty array if empty.
 * @param _language - Language identifier (reserved for future per-language parsing).
 * @param filePath - Optional file path attached to each finding's location.
 * @returns Findings with source-to-sink taint chains and hop counts.
 */
export function scanWithAST(code: string, _language: string, filePath?: string): Finding[] {
  if (code.length === 0) {
    return [];
  }

  const lines = code.split(/\r?\n/);
  const taintMap = new Map<string, TaintBinding>();
  const findings: Finding[] = [];
  const seen = new Set<string>();

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? '';
    const lineNumber = index + 1;

    trackAssignments(line, taintMap);

    for (const sinkName of SINKS) {
      checkFunctionSink(line, sinkName, lineNumber, taintMap, filePath, findings, seen);
    }

    checkPropertySink(line, lineNumber, taintMap, filePath, findings, seen);
  }

  return findings;
}

export const parserPool = {
  getParser: (_language: string) => null,
  release: (_parser: unknown) => {},
};
