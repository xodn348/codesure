export interface Annotation {
  type: 'VULN' | 'MALICIOUS' | 'SAFE';
  cwe?: string;
  severity?: string;
  variant?: string;
  line: number;
}

const ANNOTATION_PATTERN = /^(?:\/\/|#)\s*codesure:\s+(.+)$/;

function parseAnnotationText(text: string): Omit<Annotation, 'line'> | null {
  const trimmed = text.trim();

  if (trimmed.startsWith('VULN')) {
    const parts = trimmed.split(/\s+/);
    const cwe = parts.find((p) => p.startsWith('CWE-'));
    const severity = parts.find((p) => ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(p));
    return { type: 'VULN', cwe, severity };
  }

  if (trimmed.startsWith('MALICIOUS')) {
    const parts = trimmed.split(/\s+/);
    const variant = parts.slice(1).join(' ') || undefined;
    return { type: 'MALICIOUS', variant };
  }

  if (trimmed === 'SAFE') {
    return { type: 'SAFE' };
  }

  return null;
}

export function parseAnnotations(code: string): Annotation[] {
  const lines = code.split('\n');
  const annotations: Annotation[] = [];

  for (let i = 0; i < lines.length; i++) {
    const match = lines[i].match(ANNOTATION_PATTERN);
    if (match) {
      const parsed = parseAnnotationText(match[1]);
      if (parsed) {
        annotations.push({ ...parsed, line: i + 2 });
      }
    }
  }

  return annotations;
}
