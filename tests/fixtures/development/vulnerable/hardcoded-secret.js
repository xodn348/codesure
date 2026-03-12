// codesure: VULN CWE-798 HIGH
const AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
// codesure: SAFE
const AWS_SECRET_KEY = process.env.AWS_SECRET_KEY;
