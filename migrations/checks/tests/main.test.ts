import type { ExecOptions } from "@actions/exec";

const getInput = vi.fn();
const getBooleanInput = vi.fn();
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
    getBooleanInput,
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
    options?.listeners?.stdout?.(Buffer.from(JSON.stringify({ edition, version: "10.0.0" })));
    return Promise.resolve(0);
  });
};

const setupChecksMock = (edition: string, checkExitCode = 0) => {
  let callCount = 0;
  exec.mockImplementation((_cmd: string, _args?: string[], options?: ExecOptions) => {
    callCount++;
    if (callCount === 1) {
      options?.listeners?.stdout?.(Buffer.from(JSON.stringify({ edition, version: "10.0.0" })));
      return Promise.resolve(0);
    }
    return Promise.resolve(checkExitCode);
  });
};

const setupInputMock = (overrides: Record<string, string> = {}, booleanOverrides: Record<string, boolean> = {}) => {
  getInput.mockImplementation((name: string) => overrides[name] || "");
  getBooleanInput.mockImplementation((name: string) => booleanOverrides[name] ?? false);
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
      expect.stringContaining('Either "target-environment" or "target-url" must be provided'),
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

  it("should include -failOnError flag when fail-on-code-review is true", async () => {
    setupChecksMock("Enterprise");
    setupInputMock({ "target-url": "jdbc:sqlite:test.db" }, { "fail-on-code-review": true });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    const checkCall = exec.mock.calls[1];
    const args = checkCall[1] as string[];

    expect(args).toContain("-code");
    expect(args).toContain("-check.failOnError=true");
    expect(args).not.toContain("-check.failOnDrift=true");
  });

  it("should not include -failOnError when fail-on-code-review is false", async () => {
    setupChecksMock("Enterprise");
    setupInputMock({ "target-url": "jdbc:sqlite:test.db" }, { "fail-on-code-review": false });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    const checkCall = exec.mock.calls[1];
    const args = checkCall[1] as string[];

    expect(args).toContain("-code");
    expect(args).not.toContain("-check.failOnError=true");
  });

  it("should include -failOnDrift when fail-on-drift is true", async () => {
    setupChecksMock("Enterprise");
    setupInputMock({ "target-url": "jdbc:sqlite:test.db" }, { "fail-on-drift": true });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    const checkCall = exec.mock.calls[1];
    const args = checkCall[1] as string[];

    expect(args).toContain("-drift");
    expect(args).toContain("-check.failOnDrift=true");
    expect(args).not.toContain("-check.failOnError=true");
  });

  it("should not include -failOnDrift when fail-on-drift is false", async () => {
    setupChecksMock("Enterprise");
    setupInputMock({ "target-url": "jdbc:sqlite:test.db" }, { "fail-on-drift": false });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    const checkCall = exec.mock.calls[1];
    const args = checkCall[1] as string[];

    expect(args).toContain("-drift");
    expect(args).not.toContain("-check.failOnDrift=true");
  });

  it("should include -changes and build args when build-url is provided", async () => {
    setupChecksMock("Enterprise");
    setupInputMock({ "target-url": "jdbc:sqlite:test.db", "build-url": "jdbc:sqlite:build.db" });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    const checkCall = exec.mock.calls[1];
    const args = checkCall[1] as string[];

    expect(args).toContain("-changes");
    expect(args).toContain("-environments.default_build.url=jdbc:sqlite:build.db");
  });

  it("should not include -changes when no build inputs provided", async () => {
    setupChecksMock("Enterprise");
    setupInputMock({ "target-url": "jdbc:sqlite:test.db" });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    const checkCall = exec.mock.calls[1];
    const args = checkCall[1] as string[];

    expect(args).not.toContain("-changes");
  });

  it("should omit -code when skip-code-review is true", async () => {
    setupChecksMock("Enterprise");
    setupInputMock({ "target-url": "jdbc:sqlite:test.db" }, { "skip-code-review": true });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    const checkCall = exec.mock.calls[1];
    const args = checkCall[1] as string[];

    expect(args).not.toContain("-code");
    expect(args).toContain("-dryrun");
    expect(args).toContain("-drift");
  });

  it("should omit -drift when skip-drift-check is true", async () => {
    setupChecksMock("Enterprise");
    setupInputMock({ "target-url": "jdbc:sqlite:test.db" }, { "skip-drift-check": true });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    const checkCall = exec.mock.calls[1];
    const args = checkCall[1] as string[];

    expect(args).not.toContain("-drift");
    expect(args).toContain("-dryrun");
    expect(args).toContain("-code");
  });

  it("should omit -dryrun when skip-deployment-script-review is true", async () => {
    setupChecksMock("Enterprise");
    setupInputMock({ "target-url": "jdbc:sqlite:test.db" }, { "skip-deployment-script-review": true });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    const checkCall = exec.mock.calls[1];
    const args = checkCall[1] as string[];

    expect(args).not.toContain("-dryrun");
    expect(args).toContain("-code");
    expect(args).toContain("-drift");
  });

  it("should omit -changes and build args when skip-deployment-changes-report is true", async () => {
    setupChecksMock("Enterprise");
    setupInputMock(
      { "target-url": "jdbc:sqlite:test.db", "build-url": "jdbc:sqlite:build.db" },
      { "skip-deployment-changes-report": true },
    );

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    const checkCall = exec.mock.calls[1];
    const args = checkCall[1] as string[];

    expect(args).not.toContain("-changes");
    expect(args).not.toContain("-environments.default_build.url=jdbc:sqlite:build.db");
  });

  it("should suppress -failOnError when skip-code-review is true", async () => {
    setupChecksMock("Enterprise");
    setupInputMock({ "target-url": "jdbc:sqlite:test.db" }, { "skip-code-review": true, "fail-on-code-review": true });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    const checkCall = exec.mock.calls[1];
    const args = checkCall[1] as string[];

    expect(args).not.toContain("-code");
    expect(args).not.toContain("-check.failOnError=true");
  });

  it("should suppress -failOnDrift when skip-drift-check is true", async () => {
    setupChecksMock("Enterprise");
    setupInputMock({ "target-url": "jdbc:sqlite:test.db" }, { "skip-drift-check": true, "fail-on-drift": true });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    const checkCall = exec.mock.calls[1];
    const args = checkCall[1] as string[];

    expect(args).not.toContain("-drift");
    expect(args).not.toContain("-check.failOnDrift=true");
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

  it("should only include -code for Community edition", async () => {
    setupChecksMock("Community");
    setupInputMock({ "target-url": "jdbc:sqlite:test.db" });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    const checkCall = exec.mock.calls[1];
    const args = checkCall[1] as string[];

    expect(args).toContain("-code");
    expect(args).not.toContain("-dryrun");
    expect(args).not.toContain("-drift");
    expect(args).not.toContain("-changes");
    expect(setFailed).not.toHaveBeenCalled();
  });

  it("should include -dryrun and -code but not -drift or -changes for Teams edition", async () => {
    setupChecksMock("Teams");
    setupInputMock({ "target-url": "jdbc:sqlite:test.db", "build-url": "jdbc:sqlite:build.db" });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    const checkCall = exec.mock.calls[1];
    const args = checkCall[1] as string[];

    expect(args).toContain("-dryrun");
    expect(args).toContain("-code");
    expect(args).not.toContain("-drift");
    expect(args).not.toContain("-changes");
    expect(setFailed).not.toHaveBeenCalled();
  });
});
