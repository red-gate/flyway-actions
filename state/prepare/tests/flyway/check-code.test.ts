const info = vi.fn();
const checkForCodeReviewViolations = vi.fn();

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

vi.doMock("@flyway-actions/shared/check-for-code-review-violations", () => ({
  checkForCodeReviewViolations,
}));

const { runCheckCode } = await import("../../src/flyway/check-code.js");

describe("runCheckCode", () => {
  beforeEach(() => {
    checkForCodeReviewViolations.mockResolvedValue({ exitCode: 0, violationCount: 0, violationCodes: [] });
  });

  it("should return undefined when skipCodeReview is true", async () => {
    expect(await runCheckCode({ skipCodeReview: true }, "V001__create.sql")).toBeUndefined();
    expect(info).toHaveBeenCalledWith(expect.stringContaining("Skipping code review"));
    expect(checkForCodeReviewViolations).not.toHaveBeenCalled();
  });

  it("should return undefined when skipCodeReview is true even if failOnCodeReview is true", async () => {
    expect(await runCheckCode({ skipCodeReview: true, failOnCodeReview: true }, "V001__create.sql")).toBeUndefined();
    expect(checkForCodeReviewViolations).not.toHaveBeenCalled();
  });

  it("should pass args with check and -code", async () => {
    await runCheckCode({}, "V001__create.sql");

    const args = checkForCodeReviewViolations.mock.calls[0][0] as string[];

    expect(args[0]).toBe("check");
    expect(args).toContain("-code");
  });

  it("should include -check.scope=script and -check.scriptFilename", async () => {
    await runCheckCode({}, "V001__create.sql");

    const args = checkForCodeReviewViolations.mock.calls[0][0] as string[];

    expect(args).toContain("-check.scope=script");
    expect(args).toContain("-check.scriptFilename=V001__create.sql");
  });

  it("should include -check.code.failOnError=true when failOnCodeReview is true", async () => {
    await runCheckCode({ failOnCodeReview: true }, "V001__create.sql");

    const args = checkForCodeReviewViolations.mock.calls[0][0] as string[];

    expect(args).toContain("-check.code.failOnError=true");
  });

  it("should not include -check.code.failOnError=true when failOnCodeReview is false", async () => {
    await runCheckCode({ failOnCodeReview: false }, "V001__create.sql");

    const args = checkForCodeReviewViolations.mock.calls[0][0] as string[];

    expect(args).not.toContain("-check.code.failOnError=true");
  });

  it("should include target environment and working directory args", async () => {
    await runCheckCode(
      { targetUrl: "jdbc:postgresql://localhost/db", workingDirectory: "/app/db" },
      "V001__create.sql",
    );

    const args = checkForCodeReviewViolations.mock.calls[0][0] as string[];

    expect(args).toContain("-url=jdbc:postgresql://localhost/db");
    expect(args).toContain("-workingDirectory=/app/db");
  });

  it("should pass workingDirectory to checkForCodeReviewViolations", async () => {
    await runCheckCode({ workingDirectory: "/app/db" }, "V001__create.sql");

    expect(checkForCodeReviewViolations).toHaveBeenCalledWith(expect.any(Array), "/app/db");
  });

  it("should include reportFilename when preDeploymentReportName is set", async () => {
    await runCheckCode({ preDeploymentReportName: "my-report" }, "V001__create.sql");

    const args = checkForCodeReviewViolations.mock.calls[0][0] as string[];

    expect(args).toContain("-reportFilename=my-report");
  });

  it("should not include reportFilename when preDeploymentReportName is not set", async () => {
    await runCheckCode({}, "V001__create.sql");

    const args = checkForCodeReviewViolations.mock.calls[0][0] as string[];

    expect(args.some((a: string) => a.startsWith("-reportFilename="))).toBe(false);
  });
});
