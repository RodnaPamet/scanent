// Run by proxy-env.test.ts as its own Node process, with HTTPS_PROXY naming a
// listener in the test and NODE_USE_ENV_PROXY=1. It asks Node's own `fetch`
// for each host on the command line; the test then counts which reached the
// proxy. No name leaves this machine: every lookup answers loopback, where
// nothing listens on 443, so a direct request ends in a refused connection.
const dns = require('dns');

dns.lookup = (_host, options, cb) => {
    const done = typeof options === 'function' ? options : cb;
    const all = typeof options === 'object' && options !== null && options.all;
    setImmediate(() => (all ? done(null, [{ address: '127.0.0.1', family: 4 }]) : done(null, '127.0.0.1', 4)));
};

(async () => {
    for (const host of process.argv.slice(2)) {
        try {
            await fetch(`https://${host}/`);
        } catch {
            // Refused by the proxy (403) or at loopback: either way the proxy's log is the answer.
        }
    }
})();
