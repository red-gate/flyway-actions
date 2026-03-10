const setOutput = vi.fn();
const exec = vi.fn();

vi.doMock("@actions/core", () => ({
  info: vi.fn(),
  error: vi.fn(),
  startGroup: vi.fn(),
  endGroup: vi.fn(),
  setOutput,
}));

vi.doMock("@actions/exec", () => ({
  exec,
}));

const { checkForDrift } = await import("../../src/flyway/check-for-drift.js");

describe("checkForDrift", () => {
  it("should pass common args and drift report name to shared check", async () => {
    exec.mockResolvedValue(0);

    await checkForDrift({ targetUrl: "jdbc:sqlite:test.db", driftReportName: "custom-report" });

    const flywayCmdArgs = exec.mock.calls[0][1] as string[];

    expect(flywayCmdArgs).toContain("-url=jdbc:sqlite:test.db");
    expect(flywayCmdArgs).toContain("-reportFilename=custom-report");
    expect(flywayCmdArgs).toContain("check");
    expect(flywayCmdArgs).toContain("-drift");
  });

  it("should not include target migration version, cherry pick, or save snapshot in drift args", async () => {
    exec.mockResolvedValue(0);

    await checkForDrift({
      targetUrl: "jdbc:postgresql://localhost/db",
      targetMigrationVersion: "5.0",
      cherryPick: "2.0,2.1",
      saveSnapshot: true,
    });

    const flywayCmdArgs = exec.mock.calls[0][1] as string[];

    expect(flywayCmdArgs.some((a: string) => a.includes("target="))).toBe(false);
    expect(flywayCmdArgs.some((a: string) => a.includes("cherryPick"))).toBe(false);
    expect(flywayCmdArgs.some((a: string) => a.includes("saveSnapshot"))).toBe(false);
  });
});
