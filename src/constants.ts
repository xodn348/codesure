export const DANGEROUS_PERMISSIONS = [
  '<all_urls>',
  'cookies',
  'webRequest',
  'webRequestBlocking',
  'tabs',
  'history',
  'bookmarks',
  'downloads',
  'nativeMessaging',
  'debugger',
];

export const SENSITIVE_VAR_NAMES = [
  'secret', 'token', 'api_key', 'apikey', 'apiKey',
  'credential', 'credentials', 'auth', 'password', 'passwd',
  'private_key', 'privateKey', 'access_key', 'accessKey',
  'authorization', 'bearer',
];

export const ENTROPY_THRESHOLD_SUSPICIOUS = 4.5;
export const ENTROPY_THRESHOLD_HIGH = 5.5;

export const CONTEXT_MULTIPLIERS = {
  production: 1.0,
  test: 0.3,
  vendor: 0.1,
  generated: 0.1,
  docs: 0.1,
} as const;
