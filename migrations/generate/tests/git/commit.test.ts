import type { FlywayMigrationsGenerateInputs } from "../../src/types.js";

const setOutput = vi.fn();
const info = vi.fn();
const startGroup = vi.fn();
const endGroup = vi.fn();
const exec = vi.fn();

vi.doMock("@actions/core", () => ({
  info,
  startGroup,
  endGroup,
  setOutput,
}));

vi.doMock("@actions/exec", () => ({
  exec,
}));

const { commitAndPush } = await import("../../src/git/commit.js");

const baseInputs: FlywayMigrationsGenerateInputs = {
  commitMigrations: true,
  commitMessage: "chore: generate Flyway migrations",
  commitUserName: "github-actions[bot]",
  commitUserEmail: "bot@example.com",
};

beforeEach(() => {
  process.env.GITHUB_REF_NAME = "main";
});

afterEach(() => {
  delete process.env.GITHUB_REF_NAME;
});

describe("commitAndPush", () => {
  it("should be a no-op when commit-migrations is disabled", async () => {
    const result = await commitAndPush({ ...baseInputs, commitMigrations: false }, ["a.sql"]);

    expect(result.committed).toBe(false);
    expect(exec).not.toHaveBeenCalled();
    expect(setOutput).toHaveBeenCalledWith("committed", "false");
  });

  it("should be a no-op when no scripts were generated", async () => {
    const result = await commitAndPush(baseInputs, []);

    expect(result.committed).toBe(false);
    expect(exec).not.toHaveBeenCalled();
    expect(info).toHaveBeenCalledWith("No generated migrations to commit.");
    expect(setOutput).toHaveBeenCalledWith("committed", "false");
  });

  it("should throw when the branch cannot be determined", async () => {
    delete process.env.GITHUB_REF_NAME;

    await expect(commitAndPush(baseInputs, ["a.sql"])).rejects.toThrow("Could not determine the branch");
  });

  it("should commit and push when changes are staged", async () => {
    exec.mockImplementation((_cmd: string, args: string[]) => {
      if (args[0] === "diff" && args.includes("--quiet")) {
        return Promise.resolve(1);
      }
      return Promise.resolve(0);
    });

    const result = await commitAndPush(baseInputs, ["migrations/V001__add.sql"]);

    expect(result.committed).toBe(true);
    expect(exec).toHaveBeenCalledWith("git", ["config", "user.name", "github-actions[bot]"], expect.any(Object));
    expect(exec).toHaveBeenCalledWith("git", ["config", "user.email", "bot@example.com"], expect.any(Object));
    expect(exec).toHaveBeenCalledWith("git", ["add", "--", "migrations/V001__add.sql"], expect.any(Object));
    expect(exec).toHaveBeenCalledWith("git", ["commit", "-m", "chore: generate Flyway migrations"], expect.any(Object));
    expect(exec).toHaveBeenCalledWith("git", ["push", "origin", "HEAD:main"], expect.any(Object));
    expect(setOutput).toHaveBeenCalledWith("committed", "true");
  });

  it("should skip commit and push when nothing is staged after add", async () => {
    exec.mockImplementation((_cmd: string, args: string[]) => {
      if (args[0] === "diff" && args.includes("--quiet")) {
        return Promise.resolve(0);
      }
      return Promise.resolve(0);
    });

    const result = await commitAndPush(baseInputs, ["a.sql"]);

    expect(result.committed).toBe(false);
    expect(info).toHaveBeenCalledWith("No staged changes after add. Skipping commit.");
    expect(exec).not.toHaveBeenCalledWith("git", expect.arrayContaining(["commit"]), expect.any(Object));
    expect(exec).not.toHaveBeenCalledWith("git", expect.arrayContaining(["push"]), expect.any(Object));
    expect(setOutput).toHaveBeenCalledWith("committed", "false");
  });

  it("should push to the configured branch when commit-branch is set", async () => {
    exec.mockImplementation((_cmd: string, args: string[]) =>
      args.includes("--quiet") ? Promise.resolve(1) : Promise.resolve(0),
    );

    await commitAndPush({ ...baseInputs, commitBranch: "feature/migrations" }, ["a.sql"]);

    expect(exec).toHaveBeenCalledWith("git", ["push", "origin", "HEAD:feature/migrations"], expect.any(Object));
  });

  it("should run git commands inside the working directory", async () => {
    exec.mockImplementation((_cmd: string, args: string[]) =>
      args.includes("--quiet") ? Promise.resolve(1) : Promise.resolve(0),
    );

    await commitAndPush({ ...baseInputs, workingDirectory: "/repo/sub" }, ["a.sql"]);

    expect(exec).toHaveBeenCalledWith(
      "git",
      expect.arrayContaining(["add"]),
      expect.objectContaining({ cwd: "/repo/sub" }),
    );
    expect(exec).toHaveBeenCalledWith(
      "git",
      expect.arrayContaining(["push", "origin", "HEAD:main"]),
      expect.objectContaining({ cwd: "/repo/sub" }),
    );
  });
});
