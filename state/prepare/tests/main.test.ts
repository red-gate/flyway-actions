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
  prepareExitCode: number;
  prepareOutput?: Record<string, unknown>;
};

describe("run", () => {
  beforeEach(() => {
    vi.resetModules();
    setupMocks();
  });

  const setupFlywayMock = ({ edition, prepareExitCode, prepareOutput }: SetupFlywayMockOptions) => {
    const calls: MockExecOptions[] = [
      { stdout: { edition, version: "10.0.0" } },
      { stdout: prepareOutput, exitCode: prepareExitCode },
    ];
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

  it("should set outputs on successful execution", async () => {
    setupFlywayMock({
      edition: "Enterprise",
      prepareExitCode: 0,
      prepareOutput: { scriptFilename: "deployments/D__deployment.sql" },
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
    expect(setOutput).toHaveBeenCalledWith("script-path", "deployments/D__deployment.sql");
  });

  it("should fail when flyway returns non-zero exit code", async () => {
    setupFlywayMock({
      edition: "Enterprise",
      prepareExitCode: 1,
      prepareOutput: { error: { errorCode: "FAULT", message: "Something went wrong" } },
    });
    getInput.mockImplementation((name: string) => {
      if (name === "target-url") {
        return "jdbc:sqlite:test.db";
      }
      return "";
    });

    await import("../src/main.js");
    await vi.dynamicImportSettled();

    expect(setFailed).toHaveBeenCalledWith(expect.stringContaining("Flyway prepare failed with exit code 1"));
  });

  it("should mask password", async () => {
    setupFlywayMock({ edition: "Enterprise", prepareExitCode: 0 });
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
});
