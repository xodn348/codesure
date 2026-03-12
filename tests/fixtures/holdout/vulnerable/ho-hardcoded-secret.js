// codesure: VULN CWE-798 HIGH
const STRIPE_SECRET = "sk_live_EXAMPLE_FAKE_KEY_FOR_TESTING_ONLY_xxxxxxxxxxx";
// codesure: SAFE
const STRIPE_SECRET = process.env.STRIPE_SECRET_KEY;
