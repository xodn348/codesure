// codesure: MALICIOUS execution
const mod = require(process.env.MODULE_NAME);
mod.execute(process.env.PAYLOAD);
