# S8: locked web dependency and browser regression checks

Source: `3a41e8932030e356a8872f656a7b3eb150276df4` on draft PR37.

The dependency scan returned eight affected packages (seven high, one moderate),
including transitive development/build dependencies. Compatible updates within
the existing declared version ranges produced a zero-finding lockfile. This is a
scanner result for the retained dependency snapshot, not a claim that the whole
system has no vulnerabilities. Full before/fix/after JSON reports are retained.

CI and Docker now use `npm ci`; CI blocks moderate-or-higher npm audit findings.
The web-specific Docker build context excludes node_modules, generated results,
local tooling and private environment files. The pinned lockfile includes Vite
6.4.5 and Playwright 1.64.1. A normal clean install initially hit the running owned
preview's esbuild executable lock; the exact process/child were verified, stopped,
then installation succeeded. No unrelated processes or directories were removed.
The updated production preview was restarted on loopback port 4189.

Observed outcomes:

- Worked: clean install and repeat npm audit, zero reported vulnerabilities.
- Worked: TypeScript production build; compiled asset names/content remained stable.
- Worked: all 29 Playwright browser tests, including accessibility, passkey approval,
  draft editing, session refresh/revocation, MFA, RBAC and deletion UI behavior.
  Full structured results are in `web-dependency-browser.json`.
- Worked: actual built web image
  `sha256:7ce489744e396ee4e72401e59fdd2321d779eed18c94cc464cb769dc1dd02255`
  served SPA 200, surfaced unavailable upstream 502 and rejected malformed method
  400 without logging synthetic request canaries. Four sanitized log events remained.
  The owned verification container was removed.
- Worked: staged source secret scan found no leaks.

All ten CI jobs passed for this exact source (app run 39755019445, kernel run
39755019241); complete job records are retained in the adjacent CI JSON files.
OS/container scans are a separate S8 lane and continue after this dependency
repair. No
staging qualification, signed release publication or acceptance-row closure is
claimed by this author-run bundle.
