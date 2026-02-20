import type { ExecOptions } from "@actions/exec";

const getInput = vi.fn();
const getBooleanInput = vi.fn();
const setFailed = vi.fn();
const setOutput = vi.fn();
const setSecret = vi.fn();
const info = vi.fn();
const error = vi.fn();
const startGroup = vi.fn();
const endGroup = vi.fn();
const exec = vi.fn();

const setupMocks = () => {
  vi.doMock("@actions/core", () => ({
    getInput,
    getBooleanInput,
    setFailed,
    setOutput,
    setSecret,
    info,
    error,
    startGroup,
    endGroup,
  }));

  vi.doMock("@actions/exec", () => ({
    exec,
  }));
};

const setupChecksMock = (edition: string, checkExitCode = 0, outputByFlag?: Record<string, string>) => {
  let callCount = 0;
  exec.mockImplementation((_cmd: string, args?: string[], options?: ExecOptions) => {
    callCount++;
    if (callCount === 1) {
      options?.listeners?.stdout?.(Buffer.from(JSON.stringify({ edition, version: "10.0.0" })));
      return Promise.resolve(0);
    }
    if (outputByFlag && args) {
      for (const [flag, output] of Object.entries(outputByFlag)) {
        if (args.includes(flag)) {
          options?.listeners?.stdout?.(Buffer.from(output));
          return Promise.resolve(checkExitCode);
        }
      }
    }
    options?.listeners?.stdout?.(Buffer.from("{}"));
    return Promise.resolve(checkExitCode);
  });
};

const setupInputMock = (overrides: Record<string, string> = {}, booleanOverrides: Record<string, boolean> = {}) => {
  getInput.mockImplementation((name: string) => overrides[name] || "");
  getBooleanInput.mockImplementation((name: string) => booleanOverrides[name] ?? false);
};

const getCheckCalls = () => (exec.mock.calls as [string, string[]][]).filter((call) => call[1]?.[0] === "check");

describe("run", () => {
  beforeEach(() => {
    vi.resetModules();
    setupMocks();
  });

  it("should fail when flyway is not installed", async () => {
    exec.mockRejectedValue(new Error("Command not found"));

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setFailed).toHaveBeenCalledWith(expect.stringContaining("Flyway is not installed"));
  });

  it("should fail when neither url nor environment is provided", async () => {
    setupChecksMock("Community");
    setupInputMock();

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setFailed).toHaveBeenCalledWith(
      expect.stringContaining('Either "target-environment" or "target-url" must be provided'),
    );
  });

  it("should run each check as a separate invocation for enterprise", async () => {
    setupChecksMock("Enterprise");
    setupInputMock({ "target-url": "jdbc:sqlite:test.db" });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(getCheckCalls()).toHaveLength(3);
    expect(setFailed).not.toHaveBeenCalled();
  });

  it("should only run -code invocation for Community edition", async () => {
    setupChecksMock("Community");
    setupInputMock({ "target-url": "jdbc:sqlite:test.db" });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(getCheckCalls()).toHaveLength(1);
    expect(setFailed).not.toHaveBeenCalled();
  });

  it("should run -dryrun and -code but not -drift or -changes for Teams edition", async () => {
    setupChecksMock("Teams");
    setupInputMock({ "target-url": "jdbc:sqlite:test.db", "build-url": "jdbc:sqlite:build.db" });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(getCheckCalls()).toHaveLength(2);
    expect(setFailed).not.toHaveBeenCalled();
  });

  it("should fail when check exits with non-zero code", async () => {
    setupChecksMock("Enterprise", 1);
    setupInputMock({ "target-url": "jdbc:sqlite:test.db" });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setFailed).toHaveBeenCalledWith("Flyway checks failed");
  });

  it("should not fail when check exits with zero code", async () => {
    setupChecksMock("Enterprise", 0);
    setupInputMock({ "target-url": "jdbc:sqlite:test.db" });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setFailed).not.toHaveBeenCalled();
  });

  it("should set outputs from each check's JSON response", async () => {
    const driftOutput = JSON.stringify({
      individualResults: [{ operation: "drift", differences: [{ name: "Table_1" }] }],
    });
    const codeOutput = JSON.stringify({
      individualResults: [{ operation: "code", results: [{ violations: [{ code: "RG06" }] }] }],
    });
    setupChecksMock("Enterprise", 0, { "-drift": driftOutput, "-code": codeOutput });
    setupInputMock({ "target-url": "jdbc:sqlite:test.db" });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setOutput).toHaveBeenCalledWith("exit-code", "0");
    expect(setOutput).toHaveBeenCalledWith("drift-detected", "true");
    expect(setOutput).toHaveBeenCalledWith("code-violation-count", "1");
    expect(setOutput).toHaveBeenCalledWith("code-violation-codes", "RG06");
  });
});
