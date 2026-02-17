import type { ExecOptions } from "@actions/exec";

const getInput = vi.fn();
const setFailed = vi.fn();
const setSecret = vi.fn();
const info = vi.fn();
const error = vi.fn();
const startGroup = vi.fn();
const endGroup = vi.fn();
const exec = vi.fn();

const setupMocks = () => {
  vi.doMock("@actions/core", () => ({
    getInput,
    setFailed,
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

const setupFlywayVersionMock = (edition: string) => {
  exec.mockImplementation((_cmd: string, _args?: string[], options?: ExecOptions) => {
    options?.listeners?.stdout?.(Buffer.from(`Flyway ${edition} Edition 10.0.0 by Redgate\n`));
    return Promise.resolve(0);
  });
};

const setupChecksMock = (edition: string, checkExitCode = 0) => {
  let callCount = 0;
  exec.mockImplementation((_cmd: string, _args?: string[], options?: ExecOptions) => {
    callCount++;
    if (callCount === 1) {
      options?.listeners?.stdout?.(Buffer.from(`Flyway ${edition} Edition 10.0.0 by Redgate\n`));
      return Promise.resolve(0);
    }
    return Promise.resolve(checkExitCode);
  });
};

const setupInputMock = (overrides: Record<string, string> = {}) => {
  getInput.mockImplementation((name: string) => overrides[name] || "");
};

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
    setupFlywayVersionMock("Community");
    setupInputMock();

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setFailed).toHaveBeenCalledWith(
      expect.stringContaining('Either "target-url" or "target-environment" must be provided'),
    );
  });

  it("should run dryrun check with target url", async () => {
    setupChecksMock("Enterprise");
    setupInputMock({ "target-url": "jdbc:sqlite:test.db" });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    const checkCall = exec.mock.calls[1];
    const args = checkCall[1] as string[];

    expect(args[0]).toBe("check");
    expect(args).toContain("-dryrun");
    expect(args).toContain("-url=jdbc:sqlite:test.db");
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
});
