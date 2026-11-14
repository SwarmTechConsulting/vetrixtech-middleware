# Publishing @swarmtechshield/middleware

The package was first published as `@vetrixtech/middleware` (0.1.0) and is now `@swarmtechshield/middleware`. If the new name has never been published to npm, its first version goes out from your computer (Part A), like 0.1.0 did. If it has, skip to Part B. Every version after that is published from GitHub by clicking "Publish release".

The GitHub repository keeps its name, `SwarmTechConsulting/vetrixtech-middleware`. Only the npm package name changes.

---

## Part A: Release 0.5.0 under the new name (once, about 20 min)

### A1. Create the npm organisation

1. Sign in at <https://www.npmjs.com>, click your profile picture (top right) and choose **Add an Organization**.
2. In **Name**, type **`swarmtechshield`**. This becomes the `@swarmtechshield/…` part of the package name.
3. Choose the free **Unlimited public packages** plan and click **Create**. Skip the invite page by clicking **Continue**.
   - If npm says `swarmtechshield` is taken, stop and tell me before doing anything else.

### A2. Get the code

After the 0.5.0 pull request is merged:

```bash
git clone https://github.com/SwarmTechConsulting/vetrixtech-middleware.git
cd vetrixtech-middleware
npm install
npm test
```

`npm test` should finish with `# fail 0`.

### A3. Tag the version

The version is already 0.5.0, so don't run `npm version` this time:

```bash
git tag v0.5.0
git push origin v0.5.0
```

Do **not** create a GitHub release for v0.5.0 yet. A release starts the publish workflow, which can't publish a package npm doesn't know yet.

### A4. Publish from your computer

In the same folder:

```bash
npm whoami
npm publish --access public
```

- If `npm whoami` doesn't print your npm username, run `npm login` first.
- `npm publish` runs the safety checks, the tests and the build before uploading anything. When npm asks you to confirm, follow the link and confirm with your passkey.

Check that it's live: <https://www.npmjs.com/package/@swarmtechshield/middleware>.

### A5. Let GitHub publish future versions

On npmjs.com, open the new package (profile picture → **Packages** → **@swarmtechshield/middleware**) → **Settings**.

1. Under **Trusted Publisher**, click **GitHub Actions** and fill in exactly:

   | Field | Value |
   |---|---|
   | Organization or user | `SwarmTechConsulting` |
   | Repository | `vetrixtech-middleware` |
   | Workflow filename | `publish.yml` |
   | Environment name | `npm` |

   Save it. The GitHub environment `npm` and its approval rule already exist from the old package, so there's nothing to change on GitHub.
2. Under **Publishing access**, select **Require two-factor authentication and disallow tokens** and click **Update Package Settings**.

npm notes that a new trusted-publisher setting must complete a publish within 2 days. Do one GitHub release soon (Part B, with a patch version), or add the setting again later if it shows as expired.

### A6. Point the old package at the new one

```bash
npm deprecate @vetrixtech/middleware "Renamed to @swarmtechshield/middleware. Install that instead; the API is the same."
```

Anyone installing the old name now sees that message. Code already using it keeps working.

### A7. Update the SwarmTech Shield app

In the swarmtech-shield repository, set `MIDDLEWARE_VERSION` in `src/lib/middlewareVersion.js` to the new version. The Base44/Deno install guide reads it from there.

---

## Part B: Every release after that

1. Make your changes and run `npm test`. Add a line under `## Unreleased` in `CHANGELOG.md`.
2. Commit them: `git add .` then `git commit -m "describe the change"`.
3. Bump the version with **one** command: `patch` for fixes (0.2.0 → 0.2.1), `minor` for changes in behaviour (0.2.x → 0.3.0):
   ```bash
   npm version patch
   ```
   This updates `package.json`, `SDK_VERSION` in `src/client.ts`, the changelog heading and the README's Base44 example, then commits and creates the tag.
4. Push the commit and the tag: `git push --follow-tags`.
5. On GitHub: **Releases** → **Draft a new release** → **Choose a tag** → pick the tag you just pushed → **Publish release**.
6. Open **Actions**, click the **Publish** run, then **Review deployments** → tick **npm** → **Approve and deploy**.

In the run's log, the **Show versions** step should print npm 11.5 or newer, and near the end there should be a line about a signed provenance statement.

**If you change `src/linearRegex.ts`:** the SwarmTech Shield app has an identical copy at `base44/shared/linearRegex.ts` (and a generated console copy, `src/lib/linearRegex.js`). Change both repositories together; `test/linearRegex.test.ts` fails if they differ when both are checked out side by side.

**If you change detection rules:** the Base44 server (`base44/shared/ruleEngine.ts`) and this package have separate engines, and both must give the same verdicts. When you change one, add a case to `test/vectors.json` and make sure both pass it.

---

## If something goes wrong

| Message | What it means | Fix |
|---|---|---|
| `E404 … @swarmtechshield%2fmiddleware` on your computer | The `swarmtechshield` organisation doesn't exist on npm, or you're not a member | Part A1 |
| `E404` in the GitHub workflow | npm didn't accept GitHub's login: the trusted publisher fields don't match | Recheck A5 for typos (`publish.yml`, environment `npm`) |
| `E403 … cannot publish over the previously published version` | That version already exists | Bump the version (Part B, step 3) |
| `Version mismatch` | `package.json` and `SDK_VERSION` differ | Make them the same |
| `ENEEDAUTH` | Not logged in | `npm login` |
| Workflow: `Tag v… does not match package.json` | The release tag differs from the version | Delete the release, retag with the right version |
| Workflow: provenance or "repository" error | `repository` in package.json doesn't match the GitHub repository | Check it says `SwarmTechConsulting/vetrixtech-middleware` |
