# Publishing @vetrixtech/middleware

The first release goes out from your computer. After that, every release happens by clicking "Publish release" on GitHub. No passwords or tokens are stored anywhere.

You'll need about 45 minutes the first time. Do the steps in order.

---

## Part A: Accounts (15 min)

### A1. npm account and organisation

1. **Sign up** at <https://www.npmjs.com/signup> (your `swarmtechconsulting@gmail.com` address is fine), then confirm your email from the message npm sends.
2. **Turn on two-factor authentication:**
   1. Click your profile picture (top right) → **Account**.
   2. Under "Two-Factor Authentication", click **Enable 2FA**.
   3. Enter your password and click **Confirm password to continue**.
   4. Choose a method and click **Continue**. The easiest is your computer's built-in sign-in: Touch ID on a Mac, Windows Hello on a PC, or a physical key such as a YubiKey. Give it a name, click **Add security key**, and follow your browser's prompts.
   5. On the recovery-codes page, **save the codes somewhere other than this computer** (a password manager, or printed). Then click **Go back to settings**. You need these if you ever lose access to your second factor.
3. **Create the organisation:**
   1. Click your profile picture → **Add an Organization**.
   2. In **Name**, type **`vetrixtech`**. This becomes the `@vetrixtech/…` part of the package name.
   3. Choose the free **Unlimited public packages** plan and click **Create**.
   4. Skip the invite page (no one to invite yet) and click **Continue**.
   - If npm says `vetrixtech` is taken, stop and tell me. The package would need a new name before anything else.

### A2. Your GitHub name

Your GitHub name is **not** your email. Sign in to <https://github.com>, click your profile picture (top right): the bold name under it is your username. If you'd rather publish under a company name, create a free organisation first (**+** → **New organization**) and use that name.

Below, `SwarmTechConsulting` means that name.

---

## Part B: Put the code on GitHub (15 min)

### B1. Install Node 22

Check with `node -v` in a terminal. You need **v22.14 or newer**. If you don't have it, install the LTS version from <https://nodejs.org>.

### B2. Create an empty repository

On GitHub: **+** → **New repository** →

- Owner: `SwarmTechConsulting`
- Name: **`vetrixtech-middleware`** (exactly this)
- Visibility: **Public**. npm only attaches its "built from this repo" proof to public repositories.
- Don't tick README, .gitignore or licence; the zip already has them.

### B3. Prepare and push

Unzip `vetrixtech-middleware.zip`, open a terminal in that folder, and run:

```bash
npm install
npm run set-repo -- SwarmTechConsulting
npm test
```

`npm test` should finish with `# pass 96` and `# fail 0`. Then:

```bash
git init
git add .
git commit -m "Initial release of @vetrixtech/middleware"
git branch -M main
git remote add origin https://github.com/SwarmTechConsulting/vetrixtech-middleware.git
git push -u origin main
```

On GitHub, the **Actions** tab will show **CI** running the tests. It should go green within a couple of minutes.

---

## Part C: First publish, from your computer (5 min)

In the same folder:

```bash
npm login
npm publish
```

- `npm login` shows a link and asks you to press Enter. Your browser opens npm's sign-in page; sign in there (with your security key if asked), then return to the terminal. Running `npm whoami` should then print your npm username.
- `npm publish` runs the safety checks, all 96 tests and the build before uploading anything. If something is wrong, it stops with a plain message and nothing is published.
- Because 2FA is on, npm asks you to confirm the publish. Follow the link it shows (or the browser window it opens) and confirm with your security key.

Check that it's live: <https://www.npmjs.com/package/@vetrixtech/middleware>.

> A published version can't be changed or reused. A mistake means publishing `0.1.1`. That's why the checks run first.

---

## Part D: Switch future releases to GitHub (10 min)

### D1. Create a protected "npm" environment on GitHub

Repository → **Settings** → **Environments** → **New environment** → name it **`npm`** → **Configure environment**.

Under **Deployment protection rules**, tick **Required reviewers** and add yourself. Every release will then wait for you to click **Approve**, so nobody else can publish even with access to the repo.

### D2. Tell npm to trust that workflow

On npmjs.com, open your package (profile picture → **Packages** → **@vetrixtech/middleware**) → **Settings**. Find the **Trusted Publisher** section. Under **Select your publisher**, click **GitHub Actions**, and fill in:

| Field | Value |
|---|---|
| Organization or user | `SwarmTechConsulting` |
| Repository | `vetrixtech-middleware` |
| Workflow filename | `publish.yml` (just the filename, not the folder) |
| Environment name | `npm` |
| Allowed actions | leave `npm publish` allowed |

Save it. npm doesn't check these values when you save, so a typo only shows up as an error on your next release. Double-check the spelling. npm also notes that a new trusted-publisher setting must complete a successful publish within 2 days, so do your second release (Part E) soon after. If the setting shows as expired, add it again.

### D3. Lock down passwords and tokens

Same **Settings** page → **Publishing access** → select **Require two-factor authentication and disallow tokens** → click **Update Package Settings**. From now on, a release needs either the approved GitHub workflow or you with your security key.

---

## Part E: Every release after that

1. Make your changes and run `npm test`. Add a line under `## Unreleased` in `CHANGELOG.md` describing them.
2. Commit them: `git add .` then `git commit -m "describe the change"`.
3. Bump the version with **one** command. Use `patch` for fixes (0.1.1 → 0.1.2) and `minor` for changes in behaviour (0.1.x → 0.2.0):
   ```bash
   npm version patch
   ```
   This updates `package.json`, `SDK_VERSION` in `src/client.ts`, the changelog heading and the README example, then commits and creates the tag (e.g. `v0.1.2`).
4. Push the commit and the tag: `git push --follow-tags`.
5. On GitHub: **Releases** → **Draft a new release** → **Choose a tag** → pick the tag you just pushed → **Publish release**.
6. Open the **Actions** tab, click the **Publish** run, and click **Review deployments** → tick **npm** → **Approve and deploy**. It runs the checks and tests and publishes. No terminal login, no phone approval.

**If you change detection rules:** the server (`base44/shared/ruleEngine.ts`) and this package have separate engines. Both must give the same verdicts. When you change one, add a case to `test/vectors.json` and make sure both pass it. The Base44 app's tests already read the same cases.

---

## Part F: After the first publish

Put the install instructions back on the Integration page by pasting this into the Base44 builder:

> On the Integration page, add framework tabs (Express, Next.js, Cloudflare Workers, Base44 functions) using the snippets from the @vetrixtech/middleware README on npm. Every snippet must read the connection key and URLs from environment variables (process.env for Node/Next, env for Cloudflare, Deno.env.get for Base44 functions), show `npm install @vetrixtech/middleware` (or `import { VetrixTech } from "npm:@vetrixtech/middleware@0.1.0"` for Base44), and fill the sync and log URLs from the configured public API base URL. Keep the Direct API tab as an alternative.

---

## If something goes wrong

| Message | What it means | Fix |
|---|---|---|
| `Not publishing: … placeholder` | The GitHub name was never filled in | `npm run set-repo -- SwarmTechConsulting` |
| `Version mismatch` | `package.json` and `SDK_VERSION` differ | Make them the same |
| `Node … is too old` | Node older than 22 | Install Node 22 LTS |
| `E404` / `E403` on publish | The `vetrixtech` organisation doesn't exist on npm, or you're not a member | Part A1, step 3 |
| `ENEEDAUTH` | Not logged in | `npm login` |
| `E403 … cannot publish over the previously published version` | That version already exists | Bump the version (Part E, step 2) |
| Workflow: `Tag v… does not match package.json` | Release tag differs from the version | Delete the release, retag with the right version |
| Workflow: provenance or "repository" error | `repository` in package.json doesn't match the GitHub repo exactly | Check owner and repo name, run `set-repo` again, push |
| Workflow: `E403`/`ENEEDAUTH` | Trusted publisher fields don't match | Recheck Part D2 for typos: workflow filename `publish.yml`, environment name `npm` |
