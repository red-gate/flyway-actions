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

const setupBooleanInputMock = (overrides: Record<string, boolean> = {}) => {
  getBooleanInput.mockImplementation((name: string) => {
    if (name in overrides) {
      return overrides[name];
    }
    if (name === "generate-report") {
      return true;
    }
    if (name === "fail-on-drift") {
      return true;
    }
    if (name === "fail-on-code-review") {
      return true;
    }
    return false;
  });
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
    setupBooleanInputMock();

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setFailed).toHaveBeenCalledWith(
      expect.stringContaining('Either "target-url" or "target-environment" must be provided'),
    );
  });

  it("should run a single check invocation with all flags when generate-report=true and build env provided", async () => {
    setupChecksMock("Enterprise");
    setupInputMock({
      "target-url": "jdbc:sqlite:test.db",
      "build-environment": "shadow",
    });
    setupBooleanInputMock({ "generate-report": true });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    const checkCall = exec.mock.calls[1];
    const args = checkCall[1] as string[];

    expect(args[0]).toBe("check");
    expect(args).toContain("-code");
    expect(args).toContain("-drift");
    expect(args).toContain("-changes");
    expect(args).toContain("-dryrun");
    expect(setFailed).not.toHaveBeenCalled();
  });

  it("should override generateReport to false when no build env provided", async () => {
    setupChecksMock("Enterprise");
    setupInputMock({ "target-url": "jdbc:sqlite:test.db" });
    setupBooleanInputMock({ "generate-report": true, "fail-on-drift": true, "fail-on-code-review": true });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(info).toHaveBeenCalledWith(expect.stringContaining("No build environment provided"));

    const checkCall = exec.mock.calls[1];
    const args = checkCall[1] as string[];

    expect(args).toContain("-code");
    expect(args).toContain("-drift");
    expect(args).not.toContain("-changes");
    expect(args).not.toContain("-dryrun");
  });

  it("should only include code and drift flags when generate-report=false and fail flags true", async () => {
    setupChecksMock("Enterprise");
    setupInputMock({ "target-url": "jdbc:sqlite:test.db" });
    setupBooleanInputMock({ "generate-report": false, "fail-on-drift": true, "fail-on-code-review": true });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    const checkCall = exec.mock.calls[1];
    const args = checkCall[1] as string[];

    expect(args).toContain("-code");
    expect(args).toContain("-drift");
    expect(args).not.toContain("-changes");
    expect(args).not.toContain("-dryrun");
  });

  it("should run no checks when generate-report=false and both fail flags false", async () => {
    setupChecksMock("Enterprise");
    setupInputMock({ "target-url": "jdbc:sqlite:test.db" });
    setupBooleanInputMock({ "generate-report": false, "fail-on-drift": false, "fail-on-code-review": false });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(exec).toHaveBeenCalledTimes(1);
    expect(setFailed).not.toHaveBeenCalled();
  });

  it("should fail when check exits with non-zero code", async () => {
    setupChecksMock("Enterprise", 1);
    setupInputMock({
      "target-url": "jdbc:sqlite:test.db",
      "build-environment": "shadow",
    });
    setupBooleanInputMock();

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setFailed).toHaveBeenCalledWith("Flyway checks failed");
  });

  it("should not fail when check exits with zero code", async () => {
    setupChecksMock("Enterprise", 0);
    setupInputMock({
      "target-url": "jdbc:sqlite:test.db",
      "build-environment": "shadow",
    });
    setupBooleanInputMock();

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setFailed).not.toHaveBeenCalled();
  });

  it("should include failOnError and failOnDrift flags based on inputs", async () => {
    setupChecksMock("Enterprise");
    setupInputMock({ "target-url": "jdbc:sqlite:test.db" });
    setupBooleanInputMock({ "generate-report": false, "fail-on-drift": true, "fail-on-code-review": false });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    const checkCall = exec.mock.calls[1];
    const args = checkCall[1] as string[];

    expect(args).toContain("-failOnDrift=true");
    expect(args).not.toContain("-failOnError=true");
  });
});
