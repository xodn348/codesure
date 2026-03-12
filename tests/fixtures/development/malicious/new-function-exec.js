// codesure: MALICIOUS execution
const fn = new Function('return ' + userInput)();
