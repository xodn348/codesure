export const SOURCES = new Set([
  'req.body',
  'req.query',
  'req.params',
  'req.headers',
  'process.argv',
  'process.env',
  'request.args',
  'request.form',
  'request.values',
  'document.cookie',
  'window.location',
  'location.hash',
  'localStorage.getItem',
  'sessionStorage.getItem',
  'input()',
]);

export const SINKS = new Set([
  'eval',
  'new Function',
  'exec',
  'execSync',
  'spawn',
  'spawnSync',
  'child_process.exec',
  'db.query',
  'execute',
  'innerHTML',
  'outerHTML',
  'document.write',
  'pickle.loads',
  'pickle.load',
  'subprocess.call',
  'os.system',
  'fetch',
  'XMLHttpRequest',
]);

/**
 * Callables that neutralize tainted input, clearing taint on their result.
 *
 * Qualifies: well-known HTML/URL escapers, encoders, and coercions that render
 * untrusted data inert (escaping, encoding, or narrowing it to a safe shape).
 * Dotted entries (e.g. `DOMPurify.sanitize`) match method-call forms. Names are
 * matched as call callees by the taint engine, not as substrings.
 */
export const SANITIZERS: Set<string> = new Set([
  'escapeHtml',
  'escape',
  'encodeURIComponent',
  'encodeURI',
  'sanitize',
  'sanitizeHtml',
  'DOMPurify.sanitize',
  'validator.escape',
  'validator.escapeHtml',
  'parameterize',
  'parseInt',
  'parseFloat',
  'Number',
  'JSON.parse',
]);
