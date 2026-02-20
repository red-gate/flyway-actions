import type { FlywayMigrationsChecksInputs } from "../../src/types.js";

const info = vi.fn();
const setOutput = vi.fn();

vi.doMock("@actions/core", () => ({
  info,
  setOutput,
}));

const { getCodeArgs, setCodeOutputs } = await import("../../src/flyway/check-code.js");

const baseInputs: FlywayMigrationsChecksInputs = {};

describe("getCodeArgs", () => {
  it("should return args with -code", () => {
    const args = getCodeArgs(baseInputs);

    expect(args).toBeDefined();
    expect(args![0]).toBe("check");
    expect(args).toContain("-outputType=json");
    expect(args).toContain("-outputLogsInJson=true");
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
    setCodeOutputs({
      individualResults: [
        {
          operation: "code",
          results: [{ violations: [{ code: "RG06" }, { code: "RG09" }] }, { violations: [{ code: "RG06" }] }],
        },
      ],
    });

    expect(setOutput).toHaveBeenCalledWith("code-violation-count", "3");
    expect(setOutput).toHaveBeenCalledWith("code-violation-codes", "RG06,RG09");
  });

  it("should set code-violation-count to zero when no violations", () => {
    setCodeOutputs({ individualResults: [{ operation: "code", results: [{ violations: [] }] }] });

    expect(setOutput).toHaveBeenCalledWith("code-violation-count", "0");
    expect(setOutput).toHaveBeenCalledWith("code-violation-codes", "");
  });

  it("should not set code outputs when code result is absent", () => {
    setCodeOutputs({ individualResults: [{ operation: "drift" }] });

    expect(setOutput).not.toHaveBeenCalledWith("code-violation-count", expect.anything());
    expect(setOutput).not.toHaveBeenCalledWith("code-violation-codes", expect.anything());
  });
});
