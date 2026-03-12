import type { MockExecOptions } from "@flyway-actions/shared/test-utils";
import { mockExecSequence } from "@flyway-actions/shared/test-utils";

const getInput = vi.fn();
const getBooleanInput = vi.fn();
const setOutput = vi.fn();
const setFailed = vi.fn();
const setSecret = vi.fn();
const warning = vi.fn();
const info = vi.fn();
const error = vi.fn();
const startGroup = vi.fn();
const endGroup = vi.fn();
const exec = vi.fn();
const runCheckChanges = vi.fn();

const setupMocks = () => {
  vi.doMock("@actions/core", () => ({
    getInput,
    getBooleanInput,
    setOutput,
    setFailed,
    setSecret,
    warning,
    info,
    error,
    startGroup,
    endGroup,
  }));

  vi.doMock("@actions/exec", () => ({
    exec,
  }));

  vi.doMock("../src/flyway/check-changes.js", () => ({
    runCheckChanges,
  }));
};

type SetupFlywayMockOptions = {
  edition: string;
  driftExitCode?: number;
  driftOutput?: Record<string, unknown>;
  codeReviewExitCode?: number;
  codeReviewOutput?: Record<string, unknown>;
  prepareExitCode: number;
  prepareOutput?: Record<string, unknown>;
};

const getDriftCheckCalls = () =>
  (exec.mock.calls as [string, string[]][]).filter((call) => call[1]?.includes("check") && call[1]?.includes("-drift"));

const getCodeReviewCalls = () =>
  (exec.mock.calls as [string, string[]][]).filter((call) => call[1]?.includes("check") && call[1]?.includes("-code"));

const getPrepareCalls = () => (exec.mock.calls as [string, string[]][]).filter((call) => call[1]?.includes("prepare"));

describe("run", () => {
  beforeEach(() => {
    vi.resetModules();
    setupMocks();
    runCheckChanges.mockResolvedValue(undefined);
  });

  const setupFlywayMock = ({
    edition,
    driftExitCode,
    driftOutput,
    codeReviewExitCode,
    codeReviewOutput,
    prepareExitCode,
    prepareOutput,
  }: SetupFlywayMockOptions) => {
    const defaultDriftOutput = {
      error: { errorCode: "CHECK_DRIFT_DETECTED", message: "Drift detected" },
    };
    const defaultCodeReviewOutput = {
      individualResults: [{ operation: "code", results: [] }],
    };
    const calls: MockExecOptions[] = [{ stdout: { edition, version: "10.0.0" } }];
    if (driftExitCode !== undefined && edition.toLowerCase() === "enterprise") {
      calls.push({ stdout: driftOutput ?? defaultDriftOutput, exitCode: driftExitCode });
    }
    calls.push({ stdout: prepareOutput, exitCode: prepareExitCode });
    if (codeReviewExitCode !== undefined) {
      calls.push({ stdout: codeReviewOutput ?? defaultCodeReviewOutput, exitCode: codeReviewExitCode });
    }
    exec.mockImplementation(mockExecSequence(calls));
  };

  it("should fail when flyway is not installed", async () => {
    exec.mockRejectedValue(new Error("Command not found"));

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setFailed).toHaveBeenCalledWith(expect.stringContaining("Flyway is not installed"));
  });

  it("should fail when neither url nor environment is provided", async () => {
    setupFlywayMock({ edition: "Community", prepareExitCode: 0 });
    getInput.mockReturnValue("");

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setFailed).toHaveBeenCalledWith(
      expect.stringContaining('Either "target-environment" or "target-url" must be provided'),
    );
  });

  it("should run drift check, changes report, code review, and prepare for enterprise edition", async () => {
    setupFlywayMock({
      edition: "Enterprise",
      driftExitCode: 0,
      codeReviewExitCode: 0,
      prepareExitCode: 0,
      prepareOutput: { scriptFilename: "deployments/D__deployment.sql" },
    });
    getInput.mockImplementation((name: string) => (name === "target-url" ? "jdbc:sqlite:test.db" : ""));

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(getDriftCheckCalls()).toHaveLength(1);
    expect(runCheckChanges).toHaveBeenCalledWith(expect.any(Object), "enterprise");
    expect(getCodeReviewCalls()).toHaveLength(1);
    expect(getPrepareCalls()).toHaveLength(1);
    expect(setOutput).toHaveBeenCalledWith("exit-code", "0");
    expect(setOutput).toHaveBeenCalledWith("script-path", "deployments/D__deployment.sql");
  });

  it("should fail when flyway returns non-zero exit code", async () => {
    setupFlywayMock({
      edition: "Enterprise",
      driftExitCode: 0,
      codeReviewExitCode: 0,
      prepareExitCode: 1,
      prepareOutput: { error: { errorCode: "FAULT", message: "Something went wrong" } },
    });
    getInput.mockImplementation((name: string) => (name === "target-url" ? "jdbc:sqlite:test.db" : ""));

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setFailed).toHaveBeenCalledWith(expect.stringContaining("Flyway prepare failed with exit code 1"));
  });

  it("should mask password", async () => {
    setupFlywayMock({
      edition: "Enterprise",
      driftExitCode: 0,
      codeReviewExitCode: 0,
      prepareExitCode: 0,
    });
    getInput.mockImplementation((name: string) => {
      const values: Record<string, string> = {
        "target-url": "jdbc:sqlite:test.db",
        "target-password": "secret123",
      };
      return values[name] || "";
    });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setSecret).toHaveBeenCalledWith("secret123");
  });

  it("should fail and not prepare when drift is detected with fail-on-drift enabled", async () => {
    setupFlywayMock({ edition: "Enterprise", driftExitCode: 1, prepareExitCode: 0 });
    getInput.mockImplementation((name: string) => (name === "target-url" ? "jdbc:sqlite:test.db" : ""));
    getBooleanInput.mockImplementation((name: string) => name === "fail-on-drift");

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(getDriftCheckCalls()).toHaveLength(1);
    expect(getPrepareCalls()).toHaveLength(0);
    expect(setOutput).toHaveBeenCalledWith("drift-detected", "true");
    expect(setFailed).toHaveBeenCalledWith(expect.stringContaining("Drift detected"));
  });

  it("should continue prepare when drift is detected with fail-on-drift disabled", async () => {
    setupFlywayMock({
      edition: "Enterprise",
      driftExitCode: 1,
      codeReviewExitCode: 0,
      prepareExitCode: 0,
      prepareOutput: { scriptFilename: "deployments/D__deployment.sql" },
    });
    getInput.mockImplementation((name: string) => (name === "target-url" ? "jdbc:sqlite:test.db" : ""));
    getBooleanInput.mockReturnValue(false);

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(getDriftCheckCalls()).toHaveLength(1);
    expect(getPrepareCalls()).toHaveLength(1);
    expect(setOutput).toHaveBeenCalledWith("drift-detected", "true");
    expect(warning).toHaveBeenCalledWith(expect.stringContaining("fail-on-drift is disabled"));
    expect(setFailed).not.toHaveBeenCalled();
    expect(setOutput).toHaveBeenCalledWith("script-path", "deployments/D__deployment.sql");
  });

  it("should skip drift check when skip-drift-check is enabled", async () => {
    setupFlywayMock({
      edition: "Enterprise",
      codeReviewExitCode: 0,
      prepareExitCode: 0,
    });
    getInput.mockImplementation((name: string) => (name === "target-url" ? "jdbc:sqlite:test.db" : ""));
    getBooleanInput.mockImplementation((name: string) => name === "skip-drift-check");

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(getDriftCheckCalls()).toHaveLength(0);
    expect(getPrepareCalls()).toHaveLength(1);
    expect(info).toHaveBeenCalledWith(expect.stringContaining("Skipping drift check"));
    expect(setFailed).not.toHaveBeenCalled();
  });

  it("should skip drift check for community edition", async () => {
    setupFlywayMock({
      edition: "Community",
      codeReviewExitCode: 0,
      prepareExitCode: 0,
      prepareOutput: { scriptFilename: "deployments/D__deployment.sql" },
    });
    getInput.mockImplementation((name: string) => (name === "target-url" ? "jdbc:sqlite:test.db" : ""));

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(getDriftCheckCalls()).toHaveLength(0);
    expect(getPrepareCalls()).toHaveLength(1);
    expect(info).toHaveBeenCalledWith(expect.stringContaining("edition is not Enterprise"));
    expect(setFailed).not.toHaveBeenCalled();
  });

  it("should proceed with prepare when no drift detected for enterprise edition", async () => {
    setupFlywayMock({
      edition: "Enterprise",
      driftExitCode: 0,
      codeReviewExitCode: 0,
      prepareExitCode: 0,
      prepareOutput: { scriptFilename: "deployments/D__deployment.sql" },
    });
    getInput.mockImplementation((name: string) => (name === "target-url" ? "jdbc:sqlite:test.db" : ""));

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(getDriftCheckCalls()).toHaveLength(1);
    expect(getPrepareCalls()).toHaveLength(1);
    expect(setOutput).toHaveBeenCalledWith("drift-detected", "false");
    expect(setFailed).not.toHaveBeenCalled();
  });

  it("should proceed with prepare when comparison is not supported", async () => {
    setupFlywayMock({
      edition: "Enterprise",
      driftExitCode: 1,
      driftOutput: {
        error: {
          errorCode: "COMPARISON_DATABASE_NOT_SUPPORTED",
          message: "No comparison capability found",
        },
      },
      codeReviewExitCode: 0,
      prepareExitCode: 0,
      prepareOutput: { scriptFilename: "deployments/D__deployment.sql" },
    });
    getInput.mockImplementation((name: string) => (name === "target-url" ? "jdbc:h2:mem:test" : ""));

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(getDriftCheckCalls()).toHaveLength(1);
    expect(getPrepareCalls()).toHaveLength(1);
    expect(setFailed).not.toHaveBeenCalled();
    expect(setOutput).toHaveBeenCalledWith("script-path", "deployments/D__deployment.sql");
  });

  it("should fail after prepare when code review violations detected with fail-on-code-review enabled", async () => {
    setupFlywayMock({
      edition: "Enterprise",
      driftExitCode: 0,
      codeReviewExitCode: 1,
      codeReviewOutput: {
        error: {
          errorCode: "CHECK_CODE_REVIEW_VIOLATION",
          message: "Code Analysis Violation(s) detected",
          results: [{ violations: [{ code: "RG06" }] }],
          htmlReport: "/tmp/report.html",
        },
      },
      prepareExitCode: 0,
      prepareOutput: { scriptFilename: "deployments/D__deployment.sql" },
    });
    getInput.mockImplementation((name: string) => (name === "target-url" ? "jdbc:sqlite:test.db" : ""));
    getBooleanInput.mockImplementation((name: string) => name === "fail-on-code-review");

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(getPrepareCalls()).toHaveLength(1);
    expect(getCodeReviewCalls()).toHaveLength(1);
    expect(setOutput).toHaveBeenCalledWith("exit-code", "1");
    expect(setFailed).toHaveBeenCalledWith(expect.stringContaining("Code review failed"));
  });

  it("should succeed when code review violations detected with fail-on-code-review disabled", async () => {
    setupFlywayMock({
      edition: "Enterprise",
      driftExitCode: 0,
      codeReviewExitCode: 0,
      codeReviewOutput: {
        individualResults: [{ operation: "code", results: [{ violations: [{ code: "AM04" }] }] }],
      },
      prepareExitCode: 0,
      prepareOutput: { scriptFilename: "deployments/D__deployment.sql" },
    });
    getInput.mockImplementation((name: string) => (name === "target-url" ? "jdbc:sqlite:test.db" : ""));
    getBooleanInput.mockReturnValue(false);

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(getCodeReviewCalls()).toHaveLength(1);
    expect(getPrepareCalls()).toHaveLength(1);
    expect(setFailed).not.toHaveBeenCalled();
    expect(setOutput).toHaveBeenCalledWith("script-path", "deployments/D__deployment.sql");
  });

  it("should call runCheckChanges", async () => {
    setupFlywayMock({
      edition: "Community",
      codeReviewExitCode: 0,
      prepareExitCode: 0,
      prepareOutput: { scriptFilename: "deployments/D__deployment.sql" },
    });
    getInput.mockImplementation((name: string) => (name === "target-url" ? "jdbc:sqlite:test.db" : ""));

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(runCheckChanges).toHaveBeenCalledWith(expect.any(Object), "community");
  });

  it("should skip code review when skip-code-review is enabled", async () => {
    setupFlywayMock({
      edition: "Enterprise",
      driftExitCode: 0,
      prepareExitCode: 0,
      prepareOutput: { scriptFilename: "deployments/D__deployment.sql" },
    });
    getInput.mockImplementation((name: string) => (name === "target-url" ? "jdbc:sqlite:test.db" : ""));
    getBooleanInput.mockImplementation((name: string) => name === "skip-code-review");

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(getCodeReviewCalls()).toHaveLength(0);
    expect(getPrepareCalls()).toHaveLength(1);
    expect(info).toHaveBeenCalledWith(expect.stringContaining("Skipping code review"));
    expect(setFailed).not.toHaveBeenCalled();
  });
});
