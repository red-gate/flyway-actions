const info = vi.fn();
const checkForCodeReview = vi.fn();

vi.doMock("@actions/core", () => ({
  info,
  error: vi.fn(),
  setOutput: vi.fn(),
  startGroup: vi.fn(),
  endGroup: vi.fn(),
}));

vi.doMock("@actions/exec", () => ({
  exec: vi.fn(),
}));

vi.doMock("@flyway-actions/shared/check-for-code-review", () => ({
  checkForCodeReview,
}));

const { runCheckCode } = await import("../../src/flyway/check-code.js");

describe("runCheckCode", () => {
  beforeEach(() => {
    checkForCodeReview.mockResolvedValue({ exitCode: 0, violationCount: 0, violationCodes: [] });
  });

  it("should return undefined when skipCodeReview is true", async () => {
    expect(await runCheckCode({ skipCodeReview: true })).toBeUndefined();
    expect(info).toHaveBeenCalledWith(expect.stringContaining("Skipping code review"));
    expect(checkForCodeReview).not.toHaveBeenCalled();
  });

  it("should return undefined when skipCodeReview is true even if failOnCodeReview is true", async () => {
    expect(await runCheckCode({ skipCodeReview: true, failOnCodeReview: true })).toBeUndefined();
    expect(checkForCodeReview).not.toHaveBeenCalled();
  });

  it("should pass args with check and -code", async () => {
    await runCheckCode({});

    const args = checkForCodeReview.mock.calls[0][0] as string[];

    expect(args[0]).toBe("check");
    expect(args).toContain("-code");
  });

  it("should include -check.code.failOnError=true when failOnCodeReview is true", async () => {
    await runCheckCode({ failOnCodeReview: true });

    const args = checkForCodeReview.mock.calls[0][0] as string[];

    expect(args).toContain("-check.code.failOnError=true");
  });

  it("should not include -check.code.failOnError=true when failOnCodeReview is false", async () => {
    await runCheckCode({ failOnCodeReview: false });

    const args = checkForCodeReview.mock.calls[0][0] as string[];

    expect(args).not.toContain("-check.code.failOnError=true");
  });

  it("should include target and base args", async () => {
    await runCheckCode({ targetUrl: "jdbc:postgresql://localhost/db", workingDirectory: "/app/db" });

    const args = checkForCodeReview.mock.calls[0][0] as string[];

    expect(args).toContain("-url=jdbc:postgresql://localhost/db");
    expect(args).toContain("-workingDirectory=/app/db");
  });

  it("should pass workingDirectory to checkForCodeReview", async () => {
    await runCheckCode({ workingDirectory: "/app/db" });

    expect(checkForCodeReview).toHaveBeenCalledWith(expect.any(Array), "/app/db");
  });

  it("should include target args but not target migration version or cherry pick", async () => {
    await runCheckCode({
      targetUrl: "jdbc:postgresql://localhost/db",
      targetMigrationVersion: "5.0",
      cherryPick: "3.0,4.0",
    });

    const args = checkForCodeReview.mock.calls[0][0] as string[];

    expect(args).toContain("-url=jdbc:postgresql://localhost/db");
    expect(args).not.toContain("-target=5.0");
    expect(args).not.toContain("-cherryPick=3.0,4.0");
  });

  it("should not include build environment args", async () => {
    await runCheckCode({ buildUrl: "jdbc:sqlite:build.db" });

    const args = checkForCodeReview.mock.calls[0][0] as string[];

    expect(args).not.toContain(expect.stringContaining("default_build"));
  });

  it("should return exitCode and reportPath from result", async () => {
    checkForCodeReview.mockResolvedValue({
      exitCode: 1,
      reportPath: "/tmp/report.html",
      violationCount: 1,
      violationCodes: ["RG06"],
    });

    const result = await runCheckCode({});

    expect(result).toEqual({ exitCode: 1, reportPath: "/tmp/report.html" });
  });
});
