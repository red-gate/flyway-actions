import * as core from "@actions/core";
import { existsSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";

const EXCLUDED_DIRS = new Set(["node_modules", ".git", ".github", "dist"]);

export const findActions = (rootDir: string): string[] => {
  const actions: string[] = [];

  const walk = (dir: string) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (!entry.isDirectory() || EXCLUDED_DIRS.has(entry.name)) {
        continue;
      }
      const fullPath = join(dir, entry.name);
      if (existsSync(join(fullPath, "action.yml"))) {
        const relativePath = relative(rootDir, fullPath).split("\\").join("/");
        actions.push(relativePath);
      }
      walk(fullPath);
    }
  };

  walk(rootDir);
  return actions.sort();
};

const run = async (): Promise<void> => {
  try {
    const actions = findActions(join(import.meta.dirname, "..", ".."));
    for (const action of actions) {
      core.info(action);
    }
    core.setOutput("actions", JSON.stringify(actions));
  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(error.message);
    } else {
      core.setFailed("An unexpected error occurred");
    }
  }
};

await run();
