import type { MockExecOptions } from "@flyway-actions/shared/test-utils";
import { mockExecSequence } from "@flyway-actions/shared/test-utils";

const getInput = vi.fn();
const getBooleanInput = vi.fn();
const setOutput = vi.fn();
const setFailed = vi.fn();
const setSecret = vi.fn();
const info = vi.fn();
const error = vi.fn();
const startGroup = vi.fn();
const endGroup = vi.fn();
const exec = vi.fn();

const summary = {
  addHeading: vi.fn(),
  addTable: vi.fn(),
  write: vi.fn().mockResolvedValue(undefined),
};
summary.addHeading.mockReturnValue(summary);
summary.addTable.mockReturnValue(summary);

const setupMocks = () => {
  summary.addHeading.mockReturnValue(summary);
  summary.addTable.mockReturnValue(summary);
  summary.write.mockResolvedValue(undefined);

  vi.doMock("@actions/core", () => ({
    getInput,
    getBooleanInput,
    setOutput,
    setFailed,
    setSecret,
    info,
    error,
    startGroup,
    endGroup,
    summary,
  }));

  vi.doMock("@actions/exec", () => ({
    exec,
  }));
};

type SetupFlywayMockOptions = {
  edition: string;
  driftExitCode?: number;
  driftOutput?: Record<string, unknown>;
  migrateExitCode: number;
  migrateOutput?: Record<string, unknown>;
};

describe("run", () => {
  beforeEach(() => {
    vi.resetModules();
    setupMocks();
  });

  const setupFlywayMock = ({
    edition,
    driftExitCode,
    driftOutput,
    migrateExitCode,
    migrateOutput,
  }: SetupFlywayMockOptions) => {
    const defaultDriftOutput = {
      error: { errorCode: "CHECK_DRIFT_DETECTED", message: "Drift detected" },
    };
    const calls: MockExecOptions[] = [{ stdout: { edition, version: "10.0.0" } }];
    if (driftExitCode !== undefined && edition.toLowerCase() === "enterprise") {
      calls.push({ stdout: driftOutput ?? defaultDriftOutput, exitCode: driftExitCode });
    }
    calls.push({ stdout: migrateOutput, exitCode: migrateExitCode });
    exec.mockImplementation(mockExecSequence(calls));
  };

  it("should fail when flyway is not installed", async () => {
    exec.mockRejectedValue(new Error("Command not found"));

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setFailed).toHaveBeenCalledWith(expect.stringContaining("Flyway is not installed"));
  });

  it("should fail when neither url nor environment is provided", async () => {
    setupFlywayMock({ edition: "Community", migrateExitCode: 0 });
    getInput.mockReturnValue("");

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setFailed).toHaveBeenCalledWith(
      expect.stringContaining('Either "target-environment" or "target-url" must be provided'),
    );
  });

  it("should include saveSnapshot for enterprise edition", async () => {
    setupFlywayMock({
      edition: "Enterprise",
      driftExitCode: 0,
      migrateExitCode: 0,
      migrateOutput: { migrationsExecuted: 1, targetSchemaVersion: "1" },
    });
    getInput.mockImplementation((name: string) => {
      if (name === "target-url") {
        return "jdbc:sqlite:test.db";
      }
      return "";
    });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(exec).toHaveBeenCalledWith(
      "flyway",
      expect.arrayContaining(["-migrate.saveSnapshot=true"]),
      expect.any(Object),
    );
  });

  it("should not include saveSnapshot for community edition", async () => {
    setupFlywayMock({
      edition: "Community",
      migrateExitCode: 0,
      migrateOutput: { migrationsExecuted: 1, targetSchemaVersion: "1" },
    });
    getInput.mockImplementation((name: string) => {
      if (name === "target-url") {
        return "jdbc:sqlite:test.db";
      }
      return "";
    });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(exec).not.toHaveBeenCalledWith(
      "flyway",
      expect.arrayContaining(["-migrate.saveSnapshot=true"]),
      expect.any(Object),
    );
  });

  it("should fail when flyway returns non-zero exit code", async () => {
    setupFlywayMock({ edition: "Community", migrateExitCode: 1 });
    getInput.mockImplementation((name: string) => {
      if (name === "target-url") {
        return "jdbc:sqlite:test.db";
      }
      return "";
    });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setFailed).toHaveBeenCalledWith(expect.stringContaining("Flyway migrate failed with exit code 1"));
  });

  it("should set outputs on successful execution", async () => {
    setupFlywayMock({
      edition: "Community",
      migrateExitCode: 0,
      migrateOutput: { migrationsExecuted: 3, targetSchemaVersion: "3" },
    });
    getInput.mockImplementation((name: string) => {
      if (name === "target-url") {
        return "jdbc:sqlite:test.db";
      }
      return "";
    });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setOutput).toHaveBeenCalledWith("exit-code", "0");
    expect(setOutput).toHaveBeenCalledWith("migrations-applied", "3");
    expect(setOutput).toHaveBeenCalledWith("schema-version", "3");
  });

  it("should fail and not migrate when drift is detected for enterprise edition", async () => {
    setupFlywayMock({ edition: "Enterprise", driftExitCode: 1, migrateExitCode: 0 });
    getInput.mockImplementation((name: string) => {
      if (name === "target-url") {
        return "jdbc:sqlite:test.db";
      }
      return "";
    });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setOutput).toHaveBeenCalledWith("drift-detected", "true");
    expect(setFailed).toHaveBeenCalledWith(expect.stringContaining("Drift detected"));
    expect(exec).toHaveBeenCalledTimes(2);
  });

  it("should skip drift check when skip-drift-check is enabled", async () => {
    setupFlywayMock({
      edition: "Enterprise",
      migrateExitCode: 0,
      migrateOutput: { migrationsExecuted: 1, targetSchemaVersion: "1" },
    });
    getInput.mockImplementation((name: string) => {
      if (name === "target-url") {
        return "jdbc:sqlite:test.db";
      }
      return "";
    });
    getBooleanInput.mockReturnValue(true);

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(info).toHaveBeenCalledWith(expect.stringContaining("Skipping drift check"));
    expect(setFailed).not.toHaveBeenCalled();
    expect(exec).toHaveBeenCalledTimes(2);
  });

  it("should not include saveSnapshot when drift check indicates no comparison support", async () => {
    setupFlywayMock({
      edition: "Enterprise",
      driftExitCode: 1,
      driftOutput: {
        error: {
          errorCode: "COMPARISON_DATABASE_NOT_SUPPORTED",
          message: "No comparison capability found that supports both types",
        },
      },
      migrateExitCode: 0,
      migrateOutput: { migrationsExecuted: 1, targetSchemaVersion: "1" },
    });
    getInput.mockImplementation((name: string) => {
      if (name === "target-url") {
        return "jdbc:h2:mem:test";
      }
      return "";
    });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(exec).not.toHaveBeenCalledWith(
      "flyway",
      expect.arrayContaining(["-migrate.saveSnapshot=true"]),
      expect.any(Object),
    );
  });

  it("should proceed with migration when no drift detected for enterprise edition", async () => {
    setupFlywayMock({
      edition: "Enterprise",
      driftExitCode: 0,
      migrateExitCode: 0,
      migrateOutput: { migrationsExecuted: 1, targetSchemaVersion: "1" },
    });
    getInput.mockImplementation((name: string) => {
      if (name === "target-url") {
        return "jdbc:sqlite:test.db";
      }
      return "";
    });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setOutput).toHaveBeenCalledWith("drift-detected", "false");
    expect(setFailed).not.toHaveBeenCalled();
    expect(exec).toHaveBeenCalledTimes(3);
  });
});
