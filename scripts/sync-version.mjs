// Runs automatically during `npm version <patch|minor|major>` (after package.json is bumped,
// before the commit and tag). Keeps the other places that mention the version in step:
//   - SDK_VERSION in src/client.ts
//   - CHANGELOG.md: the "## Unreleased" section becomes "## <version> (<date>)", with a fresh
//     empty "## Unreleased" section above it.
//   - README.md: the pinned Base44 import example.
import { readFileSync, writeFileSync } from "node:fs";

const root = new URL("../", import.meta.url);
const read = (p) => readFileSync(new URL(p, root), "utf8");
const write = (p, s) => writeFileSync(new URL(p, root), s);

const version = JSON.parse(read("package.json")).version;
const date = new Date().toISOString().slice(0, 10);

write("src/client.ts", read("src/client.ts").replace(/SDK_VERSION = "[^"]+"/, `SDK_VERSION = "${version}"`));

let changelog = read("CHANGELOG.md");
if (/^## Unreleased[ \t]*$/m.test(changelog)) {
  changelog = changelog.replace(/^## Unreleased[ \t]*$/m, `## Unreleased\n\n## ${version} (${date})`);
} else {
  console.warn('CHANGELOG.md has no "## Unreleased" section; add notes for this release by hand.');
}
write("CHANGELOG.md", changelog);

write("README.md", read("README.md").replace(/npm:@swarmtechshield\/middleware@[0-9][^"]*/g, `npm:@swarmtechshield/middleware@${version}`));

console.log(`Version ${version}: updated SDK_VERSION, CHANGELOG.md and README.md`);
