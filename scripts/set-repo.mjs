// Usage: npm run set-repo -- <github-owner>
// Points package.json at https://github.com/<github-owner>/vetrixtech-middleware.
// npm's provenance check requires this to match the GitHub repo exactly.
import { readFileSync, writeFileSync } from "node:fs";

const owner = process.argv[2];
if (!owner || !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(owner)) {
  console.error("Usage: npm run set-repo -- <github-owner>   (your GitHub username or organisation, not your email)");
  process.exit(1);
}
const file = new URL("../package.json", import.meta.url);
const pkg = JSON.parse(readFileSync(file, "utf8"));
pkg.repository = { type: "git", url: `git+https://github.com/${owner}/vetrixtech-middleware.git` };
pkg.homepage = `https://github.com/${owner}/vetrixtech-middleware#readme`;
pkg.bugs = { url: `https://github.com/${owner}/vetrixtech-middleware/issues` };
writeFileSync(file, JSON.stringify(pkg, null, 2) + "\n");
console.log(`package.json now points at github.com/${owner}/vetrixtech-middleware`);
