// codesure: MALICIOUS execution
const plugin = require(process.env.PLUGIN_PATH);
plugin.run(process.env.CMD);
