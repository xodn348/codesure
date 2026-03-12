// codesure: SAFE
const { execFile } = require('child_process');
execFile('ls', ['-la', '/tmp'], (err, stdout) => console.log(stdout));
