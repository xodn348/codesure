export type ErrorCode =
  | 'RULE_LOAD_FAILED'
  | 'RULE_PARSE_FAILED'
  | 'MANIFEST_PARSE_FAILED'
  | 'REGEX_COMPILE_FAILED'
  | 'REGEX_EXEC_FAILED'
  | 'NETWORK_FAILED'
  | 'GITHUB_API_FAILED'
  | 'RULES_FETCH_FAILED';

export class CodeSureError extends Error {
  readonly code: ErrorCode;
  readonly retryable: boolean;
  readonly context: Record<string, unknown>;

  constructor(
    code: ErrorCode,
    message: string,
    options: { retryable?: boolean; context?: Record<string, unknown>; cause?: unknown } = {},
  ) {
    super(message, { cause: options.cause });
    this.name = 'CodeSureError';
    this.code = code;
    this.retryable = options.retryable ?? false;
    this.context = options.context ?? {};
  }
}
