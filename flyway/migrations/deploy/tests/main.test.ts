import type { ExecOptions } from "@actions/exec";

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

const setupMocks = () => {
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
  }));

  vi.doMock("@actions/exec", () => ({
    exec,
  }));
};

type SetupFlywayMockOptions = {
  edition: string;
  migrateExitCode: number;
  migrateOutput?: string;
  driftExitCode?: number;
};

describe("run", () => {
  beforeEach(() => {
    vi.resetModules();
    setupMocks();
  });

  const setupFlywayMock = ({ edition, migrateExitCode, migrateOutput = "", driftExitCode }: SetupFlywayMockOptions) => {
    let callCount = 0;
    const hasDriftCheck = driftExitCode !== undefined && edition.toLowerCase() === "enterprise";
    exec.mockImplementation(async (_cmd: string, _args?: string[], options?: ExecOptions) => {
      callCount++;
      if (callCount === 1) {
        options?.listeners?.stdout?.(Buffer.from(`Flyway ${edition} Edition 10.0.0 by Redgate\n`));
        return 0;
      }
      if (hasDriftCheck && callCount === 2) {
        return driftExitCode;
      }
      if (migrateOutput) {
        options?.listeners?.stdout?.(Buffer.from(migrateOutput));
      }
      return migrateExitCode;
    });
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

    expect(setFailed).toHaveBeenCalledWith(expect.stringContaining('Either "url" or "environment" must be provided'));
  });

  it("should include saveSnapshot for enterprise edition", async () => {
    setupFlywayMock({
      edition: "Enterprise",
      migrateExitCode: 0,
      migrateOutput: "Successfully applied 1 migrations\n",
      driftExitCode: 0,
    });
    getInput.mockImplementation((name: string) => {
      if (name === "url") return "jdbc:sqlite:test.db";
      return "";
    });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(exec).toHaveBeenCalledWith("flyway", expect.arrayContaining(["-saveSnapshot=true"]), expect.any(Object));
  });

  it("should not include saveSnapshot for community edition", async () => {
    setupFlywayMock({
      edition: "Community",
      migrateExitCode: 0,
      migrateOutput: "Successfully applied 1 migrations\n",
    });
    getInput.mockImplementation((name: string) => {
      if (name === "url") return "jdbc:sqlite:test.db";
      return "";
    });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(exec).toHaveBeenCalledWith(
      "flyway",
      expect.not.arrayContaining([expect.stringContaining("saveSnapshot")]),
      expect.any(Object),
    );
  });

  it("should fail when flyway returns non-zero exit code", async () => {
    setupFlywayMock({ edition: "Community", migrateExitCode: 1 });
    getInput.mockImplementation((name: string) => {
      if (name === "url") return "jdbc:sqlite:test.db";
      return "";
    });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setFailed).toHaveBeenCalledWith(expect.stringContaining("Flyway migrate failed with exit code 1"));
  });

  it("should log stderr as error", async () => {
    let callCount = 0;
    exec.mockImplementation(async (_cmd: string, _args?: string[], options?: ExecOptions) => {
      callCount++;
      if (callCount === 1) {
        options?.listeners?.stdout?.(Buffer.from("Flyway Community Edition 10.0.0 by Redgate\n"));
        return 0;
      }
      options?.listeners?.stdout?.(Buffer.from("Successfully applied 1 migrations\n"));
      options?.listeners?.stderr?.(Buffer.from("some warning"));
      return 0;
    });
    getInput.mockImplementation((name: string) => {
      if (name === "url") return "jdbc:sqlite:test.db";
      return "";
    });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(error).toHaveBeenCalledWith("some warning");
  });

  it("should set outputs on successful execution", async () => {
    setupFlywayMock({
      edition: "Community",
      migrateExitCode: 0,
      migrateOutput: "Successfully applied 3 migrations\nSchema now at version 3\n",
    });
    getInput.mockImplementation((name: string) => {
      if (name === "url") return "jdbc:sqlite:test.db";
      return "";
    });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setOutput).toHaveBeenCalledWith("exit-code", "0");
    expect(setOutput).toHaveBeenCalledWith("migrations-applied", "3");
    expect(setOutput).toHaveBeenCalledWith("schema-version", "3");
  });

  it("should fail and not migrate when drift is detected for enterprise edition", async () => {
    setupFlywayMock({ edition: "Enterprise", migrateExitCode: 0, driftExitCode: 1 });
    getInput.mockImplementation((name: string) => {
      if (name === "url") return "jdbc:sqlite:test.db";
      return "";
    });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setOutput).toHaveBeenCalledWith("drift-detected", "true");
    expect(setFailed).toHaveBeenCalledWith(expect.stringContaining("Drift detected"));
    expect(exec).toHaveBeenCalledTimes(2);
  });

  it("should proceed with migration when no drift detected for enterprise edition", async () => {
    setupFlywayMock({
      edition: "Enterprise",
      migrateExitCode: 0,
      migrateOutput: "Successfully applied 1 migrations\n",
      driftExitCode: 0,
    });
    getInput.mockImplementation((name: string) => {
      if (name === "url") return "jdbc:sqlite:test.db";
      return "";
    });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setOutput).toHaveBeenCalledWith("drift-detected", "false");
    expect(setFailed).not.toHaveBeenCalled();
    expect(exec).toHaveBeenCalledTimes(3);
  });
});
