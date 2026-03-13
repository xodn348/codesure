const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

/** Strips lone surrogates: high (\uD800-\uDBFF) without following low, or orphan low (\uDC00-\uDFFF). */
export function stripSurrogates(str: string): string {
  return str.replace(LONE_SURROGATE, '');
}

export function safeTruncate(str: string, maxLength: number): string {
  const clean = stripSurrogates(str);

  if (clean.length <= maxLength) {
    return clean;
  }

  const charAtBoundary = clean.charCodeAt(maxLength - 1);
  const isHighSurrogate = charAtBoundary >= 0xD800 && charAtBoundary <= 0xDBFF;

  return clean.slice(0, isHighSurrogate ? maxLength - 1 : maxLength);
}

/** JSON.stringify + strip any lone surrogate escape sequences (\uD800-\uDFFF) from the output. */
export function safeJsonStringify(value: unknown, indent?: number): string {
  const raw = JSON.stringify(value, null, indent);
  return raw.replace(/\\u[dD][89aAbB][0-9a-fA-F]{2}/g, (match, offset) => {
    const nextEscape = raw.slice(offset + 6, offset + 12);
    const isHighWithLow = /^\\u[dD][c-fC-F][0-9a-fA-F]{2}$/.test(nextEscape);
    if (isHighWithLow) return match;

    const prevEscape = offset >= 6 ? raw.slice(offset - 6, offset) : '';
    const isLowWithHigh = /^\\u[dD][89aAbB][0-9a-fA-F]{2}$/.test(prevEscape);
    if (isLowWithHigh) return match;

    return '';
  });
}
