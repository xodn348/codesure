# Authoring Detection Rules

CodeSure uses a Semgrep-compatible YAML format for defining security rules. Rules are categorized into two namespaces to distinguish between unintentional vulnerabilities and intentional malicious code.

## Dual Namespace

- **`js.security.*`**: Used for **Vulnerability** rules. These detect common coding errors that could be exploited (e.g., SQL injection, XSS).
- **`js.malicious.*`**: Used for **Malicious** rules. These detect intentional backdoors, data exfiltration, and other malicious behaviors.

## Rule Format

Each rule file contains a list of rules under the `rules` key.

### Annotated Example

```yaml
rules:
  - id: js.security.sql-injection           # Unique identifier (namespace.category.name)
    category: vulnerability                 # 'vulnerability' or 'malicious'
    taxonomy: EXM                           # Abstract taxonomy code (e.g., EXM, NET, FIL)
    severity: high                          # info, low, medium, high, critical
    languages: [javascript, typescript]     # List of supported languages
    pattern: 'SELECT.*\+|INSERT.*\+'        # Regex or AST pattern to match
    message: "Potential SQL injection"      # Description shown to the user
    fix: "Use parameterized queries"        # Optional: suggestion for fixing the issue
    metadata:                               # Optional: extra context
      cwe: CWE-89
      owasp: A03:2021
      confidence: high
```

## Field Reference

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique ID following the namespace convention. |
| `category` | Yes | Either `vulnerability` or `malicious`. |
| `severity` | Yes | `info`, `low`, `medium`, `high`, or `critical`. |
| `languages` | Yes | Array of strings: `javascript`, `typescript`, `python`. |
| `pattern` | Yes | The primary matching pattern (Regex or AST). |
| `message` | Yes | Clear explanation of the finding. |
| `pattern-not` | No | Pattern to exclude from matches (prevents false positives). |
| `taxonomy` | No | Short code for categorization in reports. |
| `fix` | No | Remediation guidance. |
| `metadata.cwe` | No | CWE identifier (e.g., `CWE-89`). |
| `metadata.owasp`| No | OWASP category (e.g., `A03:2021`). |

## Suppression

Developers can suppress a finding by adding an inline comment on the same line or the line above the match:

```javascript
// codesure-ignore: js.security.sql-injection
const query = "SELECT * FROM users WHERE id = " + id;
```

## Test Fixture Annotations

When writing test cases or benchmarks, use the following annotation format to mark expected findings:

```javascript
// codesure: VULN CWE-89 HIGH
const query = "SELECT * FROM users WHERE id = " + id;
```

Format: `// codesure: [CATEGORY] [TAXONOMY/CWE] [SEVERITY]`
- `CATEGORY`: `VULN` (vulnerability) or `MAL` (malicious)
- `TAXONOMY`: e.g., `CWE-89`, `NET`, `EXFIL`
- `SEVERITY`: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
