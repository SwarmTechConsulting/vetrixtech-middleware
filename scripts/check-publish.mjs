// Runs before every publish. Stops mistakes that are hard to undo once a version is on npm.
import { readFileSync } from "node:fs";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const client = readFileSync(new URL("../src/client.ts", import.meta.url), "utf8");
const problems = [];

if (!pkg.repository?.url || pkg.repository.url.includes("GITHUB-OWNER")) {
  problems.push('package.json "repository" still has the placeholder. Run: npm run set-repo -- <your-github-name>');
}
const sdk = /SDK_VERSION = "([^"]+)"/.exec(client)?.[1];
if (sdk !== pkg.version) {
  problems.push(`Version mismatch: package.json is ${pkg.version} but SDK_VERSION in src/client.ts is ${sdk}. Make them equal.`);
}
const [major, minor] = process.versions.node.split(".").map(Number);
if (major < 22 || (major === 22 && minor < 6)) {
  problems.push(`Node ${process.versions.node} is too old to run the tests. Install Node 22 (LTS) or newer.`);
}

if (problems.length) {
  console.error("Not publishing:\n - " + problems.join("\n - "));
  process.exit(1);
}
console.log(`Ready to publish ${pkg.name}@${pkg.version}`);
