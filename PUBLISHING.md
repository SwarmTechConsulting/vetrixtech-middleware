# Publishing @swarmtechshield/middleware

The package lives on npm as `@swarmtechshield/middleware` and on GitHub as `SwarmTechConsulting/swarmtechshield-middleware`. You can publish a version from your computer (Part A) or from GitHub by publishing a release (Part B, once trusted publishing is set up).

---

## Part A: Publish from your computer

1. Get the latest code (first time: `git clone https://github.com/SwarmTechConsulting/swarmtechshield-middleware.git`, then `cd swarmtechshield-middleware`):
   ```bash
   git checkout main
   git pull
   npm install
   ```
2. Bump the version with **one** command: `patch` for fixes (0.6.0 → 0.6.1), `minor` for changes in behaviour (0.6.x → 0.7.0):
   ```bash
   npm version minor
   ```
   This updates `package.json`, `SDK_VERSION` in `src/client.ts`, the changelog heading and the README's Base44 example, then commits and creates the tag.
3. Publish:
   ```bash
   npm whoami
   npm publish --access public
   ```
   - If `npm whoami` doesn't print your npm username, run `npm login` first.
   - `npm publish` runs the safety checks, the typecheck, the tests and the build before uploading anything. When npm asks you to confirm, follow the link and confirm with your passkey.
4. Push the version commit and tag: `git push --follow-tags`.
5. Check it's live: <https://www.npmjs.com/package/@swarmtechshield/middleware>.
6. In the swarmtech-shield repository, set `MIDDLEWARE_VERSION` in `src/lib/middlewareVersion.js` to the new version. The Base44/Deno install guide reads it from there.

---

## Part B: Publish from GitHub

### One-time setup

On npmjs.com, open the package (profile picture → **Packages** → **@swarmtechshield/middleware**) → **Settings**.

1. Under **Trusted Publisher**, click **GitHub Actions** and fill in exactly:

   | Field | Value |
   |---|---|
   | Organization or user | `SwarmTechConsulting` |
   | Repository | `swarmtechshield-middleware` |
   | Workflow filename | `publish.yml` |
   | Environment name | `npm` |

   Save it. The GitHub environment `npm` and its approval rule already exist.
2. Under **Publishing access**, select **Require two-factor authentication and disallow tokens** and click **Update Package Settings**.

npm notes that a new trusted-publisher setting must complete a publish within 2 days. If it shows as expired, add it again before your next GitHub release.

### Every release

1. Make your changes and run `npm test`. Add a line under `## Unreleased` in `CHANGELOG.md`.
2. Commit them: `git add .` then `git commit -m "describe the change"`.
3. Bump the version: `npm version patch` (or `minor`), as in Part A step 2.
4. Push the commit and the tag: `git push --follow-tags`.
5. On GitHub: **Releases** → **Draft a new release** → **Choose a tag** → pick the tag you just pushed → **Publish release**.
6. Open **Actions**, click the **Publish** run, then **Review deployments** → tick **npm** → **Approve and deploy**.
7. Update `MIDDLEWARE_VERSION` in swarmtech-shield, as in Part A step 6.

In the run's log, the **Show versions** step should print npm 11.5 or newer, and near the end there should be a line about a signed provenance statement.

---

## Keeping SwarmTech Shield and the package in step

**If you change `src/linearRegex.ts`:** the SwarmTech Shield app has an identical copy at `base44/shared/linearRegex.ts` (and a generated console copy, `src/lib/linearRegex.js`). Change both repositories together; `test/linearRegex.test.ts` fails if they differ when both are checked out side by side.

**If you change detection rules:** the Base44 server (`base44/shared/ruleEngine.ts`) and this package have separate engines, and both must give the same verdicts. When you change one, add a case to `test/vectors.json` and make sure both pass it.

---

## If something goes wrong

| Message | What it means | Fix |
|---|---|---|
| `E404 … @swarmtechshield%2fmiddleware` on your computer | You're not a member of the `swarmtechshield` npm organisation, or not logged in as the right user | `npm whoami`, then check the organisation's members on npmjs.com |
| `E404` in the GitHub workflow | npm didn't accept GitHub's login: the trusted publisher fields don't match | Recheck the one-time setup for typos (`swarmtechshield-middleware`, `publish.yml`, environment `npm`) |
| `E403 … cannot publish over the previously published version` | That version already exists | Bump the version (`npm version patch`) |
| `Version mismatch` | `package.json` and `SDK_VERSION` differ | Make them the same |
| `ENEEDAUTH` | Not logged in | `npm login` |
| Workflow: `Tag v… does not match package.json` | The release tag differs from the version | Delete the release, retag with the right version |
| Workflow: provenance or "repository" error | `repository` in package.json doesn't match the GitHub repository | Check it says `SwarmTechConsulting/swarmtechshield-middleware` and that the repository has that name |
