const info = vi.fn();
const checkForChanges = vi.fn();

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

vi.doMock("@flyway-actions/shared/check-for-changes", () => ({
  checkForChanges,
}));

const { runCheckChanges } = await import("../../src/flyway/check-changes.js");

describe("runCheckChanges", () => {
  beforeEach(() => {
    checkForChanges.mockResolvedValue({ exitCode: 0 });
  });

  it("should skip for community edition", async () => {
    const result = await runCheckChanges({}, "community");

    expect(result).toBeUndefined();
    expect(info).toHaveBeenCalledWith(expect.stringContaining("Community"));
    expect(checkForChanges).not.toHaveBeenCalled();
  });

  it("should skip for teams edition", async () => {
    const result = await runCheckChanges({}, "teams");

    expect(result).toBeUndefined();
    expect(info).toHaveBeenCalledWith(expect.stringContaining("Teams"));
    expect(checkForChanges).not.toHaveBeenCalled();
  });

  it("should skip when skipDeploymentChangesReport is true", async () => {
    const result = await runCheckChanges({ skipDeploymentChangesReport: true }, "enterprise");

    expect(result).toBeUndefined();
    expect(info).toHaveBeenCalledWith(expect.stringContaining("skip-deployment-changes-report"));
    expect(checkForChanges).not.toHaveBeenCalled();
  });

  it("should pass args with check and -changes", async () => {
    await runCheckChanges({}, "enterprise");

    const args = checkForChanges.mock.calls[0][0] as string[];

    expect(args[0]).toBe("check");
    expect(args).toContain("-changes");
  });

  it("should include -changesSource=schemaModel", async () => {
    await runCheckChanges({}, "enterprise");

    const args = checkForChanges.mock.calls[0][0] as string[];

    expect(args).toContain("-changesSource=schemaModel");
  });

  it("should include target environment args", async () => {
    await runCheckChanges({ targetUrl: "jdbc:postgresql://localhost/db" }, "enterprise");

    const args = checkForChanges.mock.calls[0][0] as string[];

    expect(args).toContain("-url=jdbc:postgresql://localhost/db");
  });

  it("should include working directory args", async () => {
    await runCheckChanges({ workingDirectory: "/app/db" }, "enterprise");

    const args = checkForChanges.mock.calls[0][0] as string[];

    expect(args).toContain("-workingDirectory=/app/db");
  });

  it("should include extra args", async () => {
    await runCheckChanges({ extraArgs: "-X -loggers=auto" }, "enterprise");

    const args = checkForChanges.mock.calls[0][0] as string[];

    expect(args).toContain("-X");
    expect(args).toContain("-loggers=auto");
  });

  it("should include report filename when set", async () => {
    await runCheckChanges({ preDeploymentReportName: "my-report" }, "enterprise");

    const args = checkForChanges.mock.calls[0][0] as string[];

    expect(args).toContain("-reportFilename=my-report");
  });

  it("should not include report filename when not set", async () => {
    await runCheckChanges({}, "enterprise");

    const args = checkForChanges.mock.calls[0][0] as string[];

    expect(args.some((a: string) => a.startsWith("-reportFilename="))).toBe(false);
  });

  it("should pass workingDirectory to checkForChanges", async () => {
    await runCheckChanges({ workingDirectory: "/app/db" }, "enterprise");

    expect(checkForChanges).toHaveBeenCalledWith(expect.any(Array), "/app/db");
  });

  it("should return result from checkForChanges", async () => {
    checkForChanges.mockResolvedValue({ exitCode: 0, reportPath: "/tmp/report.html" });

    const result = await runCheckChanges({}, "enterprise");

    expect(result).toEqual({ exitCode: 0, reportPath: "/tmp/report.html" });
  });
});
