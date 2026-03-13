const checkForDrift = vi.fn();

vi.doMock("@actions/core", () => ({
  info: vi.fn(),
  error: vi.fn(),
  setOutput: vi.fn(),
  startGroup: vi.fn(),
  endGroup: vi.fn(),
}));

vi.doMock("@actions/exec", () => ({
  exec: vi.fn(),
}));

vi.doMock("@flyway-actions/shared/check-for-drift", () => ({
  checkForDrift,
}));

const { runCheckDrift } = await import("../../src/flyway/check-drift.js");

describe("runCheckDrift", () => {
  beforeEach(() => {
    checkForDrift.mockResolvedValue({ driftDetected: false, comparisonSupported: true });
  });

  it("should pass args with check and -drift", async () => {
    await runCheckDrift({});

    const args = checkForDrift.mock.calls[0][0] as string[];

    expect(args[0]).toBe("check");
    expect(args).toContain("-drift");
    expect(args).toContain("-check.failOnDrift=true");
  });

  it("should include target environment args", async () => {
    await runCheckDrift({ targetUrl: "jdbc:postgresql://localhost/db" });

    const args = checkForDrift.mock.calls[0][0] as string[];

    expect(args).toContain("-url=jdbc:postgresql://localhost/db");
  });

  it("should include working directory in args", async () => {
    await runCheckDrift({ workingDirectory: "/app/db" });

    const args = checkForDrift.mock.calls[0][0] as string[];

    expect(args).toContain("-workingDirectory=/app/db");
  });

  it("should include extra args", async () => {
    await runCheckDrift({ extraArgs: "-X -loggers=auto" });

    const args = checkForDrift.mock.calls[0][0] as string[];

    expect(args).toContain("-X");
    expect(args).toContain("-loggers=auto");
  });

  it("should include report filename when deploymentReportName is set", async () => {
    await runCheckDrift({ deploymentReportName: "my-report" });

    const args = checkForDrift.mock.calls[0][0] as string[];

    expect(args).toContain("-reportFilename=my-report");
  });

  it("should not include report filename when deploymentReportName is not set", async () => {
    await runCheckDrift({});

    const args = checkForDrift.mock.calls[0][0] as string[];

    expect(args.some((a: string) => a.startsWith("-reportFilename="))).toBe(false);
  });

  it("should pass workingDirectory to checkForDrift", async () => {
    await runCheckDrift({ workingDirectory: "/app/db" });

    expect(checkForDrift).toHaveBeenCalledWith(expect.any(Array), "/app/db");
  });

  it("should return result from checkForDrift", async () => {
    checkForDrift.mockResolvedValue({ driftDetected: true, comparisonSupported: true });

    const result = await runCheckDrift({});

    expect(result).toEqual({ driftDetected: true, comparisonSupported: true });
  });
});
