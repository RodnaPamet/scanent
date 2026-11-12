/**
 * Writes each example under deploy/examples/ from its answers file: the
 * configuration and the env template `scanent init --answers` plans for it,
 * with the signing key's path as the container sees it. Run `npm run build`
 * first, then `npm run docs:examples`.
 *
 * packages/scanner/tests/deploy-templates.test.ts compares the committed files
 * with the same rendering, so an example cannot fall behind the wizard.
 */
const fs = require('node:fs');
const path = require('node:path');

const { parseInitAnswers, planInit, renderEnvTemplate } = require('../packages/scanner/dist/index.js');

const dir = path.join(__dirname, '..', 'deploy', 'examples');
/** Where the quick start, the Compose file and the chart all mount the signing key's directory. */
const SIGNING_KEY_PATH = '/etc/scanent/signing-key.pem';

for (const file of fs.readdirSync(dir).filter((f) => f.endsWith('.answers.json')).sort()) {
    const name = file.slice(0, -'.answers.json'.length);
    const plan = planInit(parseInitAnswers(JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8'))));
    fs.writeFileSync(path.join(dir, `${name}.json`), plan.configText);
    fs.writeFileSync(path.join(dir, `${name}.env`), renderEnvTemplate(plan.credentialNames, SIGNING_KEY_PATH));
    process.stdout.write(`${name}: ${plan.config.sources.length} source(s), ${plan.credentialNames.length} credential name(s)\n`);
}
