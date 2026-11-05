// Node-only helpers. Import from "@swarmtechshield/middleware/node"; the main entry stays
// free of Node APIs so it runs on edge runtimes.

/**
 * Read the app's direct dependencies and the versions actually installed in node_modules.
 * Returns { name: installedVersion }. Pass it as `dependencies` in the options, or call
 * client.setDependencies(). Never throws; returns what it could read.
 */
export async function detectDependencies(dir?: string): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  try {
    const fs: any = await import("node:" + "fs");
    const path: any = await import("node:" + "path");
    const proc = (globalThis as { process?: { cwd(): string } }).process;
    const root = dir || (proc ? proc.cwd() : ".");
    const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    const names = Object.keys({ ...(pkg.dependencies || {}), ...(pkg.optionalDependencies || {}) }).slice(0, 2000);
    for (const name of names) {
      try {
        const installed = JSON.parse(fs.readFileSync(path.join(root, "node_modules", name, "package.json"), "utf8"));
        if (typeof installed.version === "string") out[name] = installed.version;
      } catch {
        const declared = (pkg.dependencies || {})[name];
        if (typeof declared === "string" && /^\d/.test(declared)) out[name] = declared;
      }
    }
  } catch {
    // No package.json or no file system: nothing to report.
  }
  return out;
}
