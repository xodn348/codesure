import type { Finding } from '../types.js';

function normalizeConfidence(confidence: number): number {
  return Math.max(0, Math.min(100, confidence));
}

function appendEvidenceChain(existingChain: string[] | undefined, contributingRuleIds: string[]): string[] {
  const merged = new Set<string>([...(existingChain ?? []), ...contributingRuleIds]);
  return [...merged];
}

/**
 * Boosts finding confidence based on co-occurring behavioral taxonomy signals.
 *
 * Groups findings by file and applies multipliers when dangerous combinations appear:
 * - EXS + EXM + EXF chain → 2x confidence on EXF findings (full attack chain)
 * - DEF + EXM chain → 1.5x confidence on EXM findings (defense evasion + execution)
 *
 * @param findings - Pre-analyzed findings from earlier pipeline stages.
 * @returns Findings with adjusted confidence scores (capped at 100) and merged evidence chains.
 */
export function analyzeChain(findings: Finding[]): Finding[] {
  const findingsByFile = new Map<string, Finding[]>();

  for (const finding of findings) {
    const file = finding.location.file ?? 'unknown';
    const fileFindings = findingsByFile.get(file) ?? [];
    fileFindings.push({ ...finding });
    findingsByFile.set(file, fileFindings);
  }

  const analyzedFindings: Finding[] = [];

  for (const fileFindings of findingsByFile.values()) {
    const taxonomyInFile = new Set(
      fileFindings
        .map((finding) => finding.taxonomy)
        .filter((taxonomy): taxonomy is NonNullable<Finding['taxonomy']> => taxonomy !== undefined),
    );

    const hasExsExmExfChain = taxonomyInFile.has('EXS') && taxonomyInFile.has('EXM') && taxonomyInFile.has('EXF');
    const hasDefExmChain = taxonomyInFile.has('DEF') && taxonomyInFile.has('EXM');

    const exsExmExfRuleIds = fileFindings
      .filter((finding) => finding.taxonomy === 'EXS' || finding.taxonomy === 'EXM' || finding.taxonomy === 'EXF')
      .map((finding) => finding.rule_id);

    const defExmRuleIds = fileFindings
      .filter((finding) => finding.taxonomy === 'DEF' || finding.taxonomy === 'EXM')
      .map((finding) => finding.rule_id);

    for (const finding of fileFindings) {
      let confidence = finding.confidence;
      let evidenceChain = finding.evidence_chain;

      if (hasExsExmExfChain && finding.taxonomy === 'EXF') {
        confidence *= 2.0;
        evidenceChain = appendEvidenceChain(evidenceChain, exsExmExfRuleIds);
      }

      if (hasDefExmChain && finding.taxonomy === 'EXM') {
        confidence *= 1.5;
        evidenceChain = appendEvidenceChain(evidenceChain, defExmRuleIds);
      }

      const contextMultiplier = finding.path_context?.context_multiplier;
      if (contextMultiplier !== undefined) {
        confidence *= contextMultiplier;
      }

      analyzedFindings.push({
        ...finding,
        confidence: normalizeConfidence(confidence),
        evidence_chain: evidenceChain,
      });
    }
  }

  return analyzedFindings;
}
