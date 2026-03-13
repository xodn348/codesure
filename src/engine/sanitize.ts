/**
 * Surrogate-safe string truncation.
 * Regex strips lone surrogates: high (\uD800-\uDBFF) not followed by low, or low (\uDC00-\uDFFF) not preceded by high.
 * Prevents JSON serialization errors when .slice() splits a surrogate pair (e.g. emoji).
 */
export function safeTruncate(str: string, maxLength: number): string {
  const clean = str.replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g, '');

  if (clean.length <= maxLength) {
    return clean;
  }

  const charAtBoundary = clean.charCodeAt(maxLength - 1);
  const isHighSurrogate = charAtBoundary >= 0xD800 && charAtBoundary <= 0xDBFF;

  return clean.slice(0, isHighSurrogate ? maxLength - 1 : maxLength);
}
