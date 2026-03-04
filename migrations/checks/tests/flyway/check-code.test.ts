import type { FlywayMigrationsChecksInputs } from "../../src/types.js";
import { mockExec } from "@flyway-actions/shared/test-utils";

const info = vi.fn();
const error = vi.fn();
const setOutput = vi.fn();
const exec = vi.fn();

vi.doMock("@actions/core", () => ({
  info,
  error,
  setOutput,
  startGroup: vi.fn(),
  endGroup: vi.fn(),
}));

vi.doMock("@actions/exec", () => ({
  exec,
}));

const { getCodeArgs, runCheckCode, setCodeOutputs } = await import("../../src/flyway/check-code.js");

const baseInputs: FlywayMigrationsChecksInputs = {};

describe("getCodeArgs", () => {
  it("should return args with -code", () => {
    const args = getCodeArgs(baseInputs);

    expect(args).toBeDefined();
    expect(args![0]).toBe("check");
    expect(args).toContain("-code");
  });

  it("should include -check.code.failOnError=true when failOnCodeReview is true", () => {
    const args = getCodeArgs({ failOnCodeReview: true });

    expect(args).toContain("-check.code.failOnError=true");
  });

  it("should not include -check.code.failOnError=true when failOnCodeReview is false", () => {
    const args = getCodeArgs({ failOnCodeReview: false });

    expect(args).not.toContain("-check.code.failOnError=true");
  });

  it("should include target and base args", () => {
    const args = getCodeArgs({ targetUrl: "jdbc:postgresql://localhost/db", workingDirectory: "/app/db" });

    expect(args).toContain("-url=jdbc:postgresql://localhost/db");
    expect(args).toContain("-workingDirectory=/app/db");
  });

  it("should include target args but not target migration version or cherry pick", () => {
    const args = getCodeArgs({
      targetUrl: "jdbc:postgresql://localhost/db",
      targetMigrationVersion: "5.0",
      cherryPick: "3.0,4.0",
    });

    expect(args).toContain("-url=jdbc:postgresql://localhost/db");
    expect(args).not.toContain("-target=5.0");
    expect(args).not.toContain("-cherryPick=3.0,4.0");
  });

  it("should not include build environment args", () => {
    const args = getCodeArgs({ buildUrl: "jdbc:sqlite:build.db" });

    expect(args).not.toContain(expect.stringContaining("default_build"));
  });

  it("should return undefined when skipCodeReview is true", () => {
    expect(getCodeArgs({ skipCodeReview: true })).toBeUndefined();
    expect(info).toHaveBeenCalledWith(expect.stringContaining("Skipping code review"));
  });

  it("should return undefined when skipCodeReview is true even if failOnCodeReview is true", () => {
    expect(getCodeArgs({ skipCodeReview: true, failOnCodeReview: true })).toBeUndefined();
  });
});

describe("setCodeOutputs", () => {
  it("should set code-violation-count and code-violation-codes", () => {
    setCodeOutputs([{ violations: [{ code: "RG06" }, { code: "RG09" }] }, { violations: [{ code: "RG06" }] }]);

    expect(setOutput).toHaveBeenCalledWith("code-violation-count", "3");
    expect(setOutput).toHaveBeenCalledWith("code-violation-codes", "RG06,RG09");
  });

  it("should set code-violation-count to zero when no violations", () => {
    setCodeOutputs([{ violations: [] }]);

    expect(setOutput).toHaveBeenCalledWith("code-violation-count", "0");
    expect(setOutput).toHaveBeenCalledWith("code-violation-codes", "");
  });

  it("should handle empty results", () => {
    setCodeOutputs([]);

    expect(setOutput).toHaveBeenCalledWith("code-violation-count", "0");
    expect(setOutput).toHaveBeenCalledWith("code-violation-codes", "");
  });
});

describe("runCheckCode", () => {
  it("should return undefined when skipCodeReview is true", async () => {
    const result = await runCheckCode({ skipCodeReview: true });

    expect(result).toBeUndefined();
  });

  it("should set outputs and return reportPath on success", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: {
          htmlReport: "report.html",
          individualResults: [{ operation: "code", results: [{ violations: [{ code: "RG06" }] }] }],
        },
      }),
    );

    const result = await runCheckCode(baseInputs);

    expect(result?.exitCode).toBe(0);
    expect(result?.reportPath).toBe("report.html");
    expect(setOutput).toHaveBeenCalledWith("code-violation-count", "1");
  });

  it("should parse violations from error output on failure", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: {
          error: {
            errorCode: "CHECK_CODE_REVIEW_VIOLATION",
            message: "Code Analysis Violation(s) detected",
            results: [{ filepath: "V1__init.sql", violations: [{ code: "RG06" }] }],
            htmlReport: "/tmp/report.html",
          },
        },
        exitCode: 1,
      }),
    );

    const result = await runCheckCode({ failOnCodeReview: true });

    expect(result?.exitCode).toBe(1);
    expect(result?.reportPath).toBe("/tmp/report.html");
    expect(error).toHaveBeenCalledWith("Code Analysis Violation(s) detected");
    expect(setOutput).toHaveBeenCalledWith("code-violation-count", "1");
    expect(setOutput).toHaveBeenCalledWith("code-violation-codes", "RG06");
  });

  it("should handle error output without results", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: { error: { errorCode: "FAULT", message: "Something failed" } },
        exitCode: 1,
      }),
    );

    const result = await runCheckCode(baseInputs);

    expect(result?.exitCode).toBe(1);
    expect(result?.reportPath).toBeUndefined();
    expect(error).toHaveBeenCalledWith("Something failed");
  });
});
