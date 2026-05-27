import type { MockExecOptions } from "@flyway-actions/shared/test-utils";
import { mockExecSequence } from "@flyway-actions/shared/test-utils";

const getInput = vi.fn();
const getBooleanInput = vi.fn();
const setOutput = vi.fn();
const setFailed = vi.fn();
const setSecret = vi.fn();
const info = vi.fn();
const warning = vi.fn();
const error = vi.fn();
const startGroup = vi.fn();
const endGroup = vi.fn();
const exec = vi.fn();
const unlink = vi.fn();

const summary = {
  addHeading: vi.fn(),
  addTable: vi.fn(),
  addRaw: vi.fn(),
  addEOL: vi.fn(),
  addList: vi.fn(),
  write: vi.fn().mockResolvedValue(undefined),
};
summary.addHeading.mockReturnValue(summary);
summary.addTable.mockReturnValue(summary);
summary.addRaw.mockReturnValue(summary);
summary.addEOL.mockReturnValue(summary);
summary.addList.mockReturnValue(summary);

const setupMocks = () => {
  summary.addHeading.mockReturnValue(summary);
  summary.addTable.mockReturnValue(summary);
  summary.addRaw.mockReturnValue(summary);
  summary.addEOL.mockReturnValue(summary);
  summary.addList.mockReturnValue(summary);
  summary.write.mockResolvedValue(undefined);

  vi.doMock("@actions/core", () => ({
    getInput,
    getBooleanInput,
    setOutput,
    setFailed,
    setSecret,
    info,
    warning,
    error,
    startGroup,
    endGroup,
    summary,
  }));

  vi.doMock("@actions/exec", () => ({
    exec,
  }));

  vi.doMock("node:fs/promises", () => ({
    unlink,
  }));
};

type SetupFlywayMockOptions = {
  edition: string;
  diffExitCode?: number;
  diffOutput?: Record<string, unknown>;
  generateExitCode?: number;
  generateOutput?: Record<string, unknown>;
};

const getDiffCalls = () =>
  (exec.mock.calls as [string, string[]][]).filter((call) => call[0] === "flyway" && call[1]?.includes("diff"));

const getGenerateCalls = () =>
  (exec.mock.calls as [string, string[]][]).filter((call) => call[0] === "flyway" && call[1]?.includes("generate"));

const getGitCalls = () => (exec.mock.calls as [string, string[]][]).filter((call) => call[0] === "git");

describe("run", () => {
  beforeEach(() => {
    vi.resetModules();
    setupMocks();
    getBooleanInput.mockReturnValue(false);
    unlink.mockResolvedValue(undefined);
  });

  const setupFlywayMock = ({
    edition,
    diffExitCode = 0,
    diffOutput,
    generateExitCode = 0,
    generateOutput,
  }: SetupFlywayMockOptions) => {
    const calls: MockExecOptions[] = [{ stdout: { edition, version: "12.0.0" } }];
    if (edition.toLowerCase() === "enterprise") {
      calls.push({ stdout: diffOutput ?? {}, exitCode: diffExitCode });
      calls.push({ stdout: generateOutput ?? { scripts: [] }, exitCode: generateExitCode });
    }
    exec.mockImplementation(mockExecSequence(calls));
  };

  it("should fail when flyway is not installed", async () => {
    exec.mockRejectedValue(new Error("Command not found"));

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setFailed).toHaveBeenCalledWith(expect.stringContaining("Flyway is not installed"));
  });

  it("should fail when flyway version is below the minimum", async () => {
    exec.mockImplementation(mockExecSequence([{ stdout: { edition: "Enterprise", version: "11.20.0" } }]));

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setFailed).toHaveBeenCalledWith(expect.stringContaining("11.20.0"));
    expect(setFailed).toHaveBeenCalledWith(expect.stringContaining("12.0.0"));
  });

  it("should fail for non-enterprise edition", async () => {
    setupFlywayMock({ edition: "Community" });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setFailed).toHaveBeenCalledWith(expect.stringContaining("requires Flyway Enterprise edition"));
  });

  it("should run diff and generate for enterprise edition", async () => {
    setupFlywayMock({
      edition: "Enterprise",
      generateOutput: {
        scripts: [{ type: "versioned", location: "migrations/V001__add.sql", differences: [], warnings: [] }],
      },
    });
    getInput.mockReturnValue("");

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(getDiffCalls()).toHaveLength(1);
    expect(getGenerateCalls()).toHaveLength(1);
    expect(setOutput).toHaveBeenCalledWith("exit-code", "0");
    expect(setOutput).toHaveBeenCalledWith("script-paths", JSON.stringify(["migrations/V001__add.sql"]));
  });

  it("should fail when diff returns non-zero exit code", async () => {
    setupFlywayMock({
      edition: "Enterprise",
      diffExitCode: 1,
      diffOutput: { error: { errorCode: "FAULT", message: "Diff failed" } },
    });
    getInput.mockReturnValue("");

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(getDiffCalls()).toHaveLength(1);
    expect(getGenerateCalls()).toHaveLength(0);
    expect(setFailed).toHaveBeenCalledWith(expect.stringContaining("Flyway diff failed with exit code 1"));
  });

  it("should fail when generate returns non-zero exit code", async () => {
    setupFlywayMock({
      edition: "Enterprise",
      generateExitCode: 1,
      generateOutput: { error: { errorCode: "FAULT", message: "Generate failed" } },
    });
    getInput.mockReturnValue("");

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(getDiffCalls()).toHaveLength(1);
    expect(getGenerateCalls()).toHaveLength(1);
    expect(setFailed).toHaveBeenCalledWith(expect.stringContaining("Flyway generate failed with exit code 1"));
  });

  it("should mask build password", async () => {
    setupFlywayMock({
      edition: "Enterprise",
      generateOutput: { scripts: [] },
    });
    getInput.mockImplementation((name: string) => (name === "build-password" ? "shh" : ""));

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setSecret).toHaveBeenCalledWith("shh");
  });

  it("should not invoke git when commit-migrations is disabled", async () => {
    setupFlywayMock({
      edition: "Enterprise",
      generateOutput: {
        scripts: [{ type: "versioned", location: "migrations/V001__add.sql", differences: [], warnings: [] }],
      },
    });
    getInput.mockReturnValue("");

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(getGitCalls()).toHaveLength(0);
    expect(setOutput).toHaveBeenCalledWith("committed", "false");
  });

  it("should commit and push when commit-migrations is enabled and scripts were generated", async () => {
    process.env.GITHUB_REF_NAME = "main";
    let flywayCallIndex = 0;
    const flywayResponses: { stdout: Record<string, unknown> }[] = [
      { stdout: { edition: "Enterprise", version: "12.0.0" } },
      { stdout: {} },
      {
        stdout: {
          scripts: [{ type: "versioned", location: "migrations/V001__add.sql", differences: [], warnings: [] }],
        },
      },
    ];
    exec.mockImplementation(
      (cmd: string, args: string[], options?: { listeners?: { stdout?: (b: Buffer) => void } }) => {
        if (cmd === "flyway") {
          const next = flywayResponses[flywayCallIndex] ?? flywayResponses[flywayResponses.length - 1];
          flywayCallIndex++;
          options?.listeners?.stdout?.(Buffer.from(JSON.stringify(next.stdout)));
          return Promise.resolve(0);
        }
        if (cmd === "git" && args[0] === "diff" && args.includes("--quiet")) {
          return Promise.resolve(1);
        }
        return Promise.resolve(0);
      },
    );
    getInput.mockReturnValue("");
    getBooleanInput.mockImplementation((name: string) => name === "commit-migrations");

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    const gitCalls = getGitCalls();

    expect(gitCalls.some((c) => c[1][0] === "commit")).toBe(true);
    expect(gitCalls.some((c) => c[1].join(" ") === "push origin HEAD:main")).toBe(true);
    expect(setOutput).toHaveBeenCalledWith("committed", "true");

    delete process.env.GITHUB_REF_NAME;
  });

  it("should delete the diff artifact after a successful generate", async () => {
    setupFlywayMock({
      edition: "Enterprise",
      diffOutput: { artifactFilename: "/tmp/diff-artifact" },
      generateOutput: { scripts: [] },
    });
    getInput.mockReturnValue("");

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(unlink).toHaveBeenCalledWith("/tmp/diff-artifact");
  });

  it("should delete the diff artifact even when generate fails", async () => {
    setupFlywayMock({
      edition: "Enterprise",
      diffOutput: { artifactFilename: "/tmp/diff-artifact" },
      generateExitCode: 1,
      generateOutput: { error: { errorCode: "FAULT", message: "Generate failed" } },
    });
    getInput.mockReturnValue("");

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setFailed).toHaveBeenCalledWith(expect.stringContaining("Flyway generate failed"));
    expect(unlink).toHaveBeenCalledWith("/tmp/diff-artifact");
  });

  it("should skip artifact deletion when diff did not report an artifact path", async () => {
    setupFlywayMock({
      edition: "Enterprise",
      diffOutput: {},
      generateOutput: { scripts: [] },
    });
    getInput.mockReturnValue("");

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(unlink).not.toHaveBeenCalled();
  });
});
