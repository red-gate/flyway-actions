import { join } from "node:path";

const REPO_ROOT = join(import.meta.dirname, "..", "..");

describe("findActions", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.doMock("@actions/core", () => ({
      info: vi.fn(),
      setOutput: vi.fn(),
      setFailed: vi.fn(),
    }));
  });

  it("discovers action.yml files and returns relative paths", async () => {
    const { findActions } = await import("../src/main.js");
    const actions = findActions(REPO_ROOT);

    expect(actions).toEqual(["migrations/checks", "migrations/deploy"]);
  });

  it("excludes directories", async () => {
    const { findActions } = await import("../src/main.js");
    const actions = findActions(REPO_ROOT);

    for (const action of actions) {
      expect(action).not.toMatch(/^(node_modules|\.git|\.github|dist)\//);
    }
  });

  it("returns an empty array when no actions exist", async () => {
    const { findActions } = await import("../src/main.js");
    const actions = findActions(import.meta.dirname);

    expect(actions).toEqual([]);
  });
});
