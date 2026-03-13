import type { FlywayMigrationsChecksInputs } from "../../src/types.js";

const info = vi.fn();
const setOutput = vi.fn();
const checkForDrift = vi.fn();

vi.doMock("@actions/core", () => ({
  info,
  error: vi.fn(),
  setOutput,
  startGroup: vi.fn(),
  endGroup: vi.fn(),
}));

vi.doMock("@actions/exec", () => ({
  exec: vi.fn(),
}));

vi.doMock("@flyway-actions/shared/check-for-drift", () => ({
  checkForDrift,
}));

const { getDriftArgs, runCheckDrift } = await import("../../src/flyway/check-drift.js");

const baseInputs: FlywayMigrationsChecksInputs = {};

describe("getDriftArgs", () => {
  it("should return args with -drift for enterprise edition", () => {
    const args = getDriftArgs(baseInputs, "enterprise");

    expect(args).toBeDefined();
    expect(args![0]).toBe("check");
    expect(args).toContain("-drift");
  });

  it("should include -check.failOnDrift=true when failOnDrift is true", () => {
    const args = getDriftArgs({ failOnDrift: true }, "enterprise");

    expect(args).toContain("-check.failOnDrift=true");
  });

  it("should not include -check.failOnDrift=true when failOnDrift is false", () => {
    const args = getDriftArgs({ failOnDrift: false }, "enterprise");

    expect(args).not.toContain("-check.failOnDrift=true");
  });

  it("should include target args but not target migration version or cherry pick", () => {
    const args = getDriftArgs(
      { targetUrl: "jdbc:postgresql://localhost/db", targetMigrationVersion: "5.0", cherryPick: "3.0" },
      "enterprise",
    );

    expect(args).toContain("-url=jdbc:postgresql://localhost/db");
    expect(args).not.toContain("-target=5.0");
    expect(args).not.toContain("-cherryPick=3.0");
  });

  it("should not include build environment args", () => {
    const args = getDriftArgs({ buildUrl: "jdbc:sqlite:build.db" }, "enterprise");

    expect(args).not.toContain(expect.stringContaining("default_build"));
  });

  it("should return undefined for community edition", () => {
    expect(getDriftArgs(baseInputs, "community")).toBeUndefined();
    expect(info).toHaveBeenCalledWith("Skipping drift check: not available in Community edition");
  });

  it("should return undefined for teams edition", () => {
    expect(getDriftArgs(baseInputs, "teams")).toBeUndefined();
    expect(info).toHaveBeenCalledWith("Skipping drift check: not available in Teams edition");
  });

  it("should return undefined when skipDriftCheck is true", () => {
    expect(getDriftArgs({ skipDriftCheck: true }, "enterprise")).toBeUndefined();
    expect(info).toHaveBeenCalledWith(expect.stringContaining("Skipping drift check"));
  });

  it("should return undefined when skipDriftCheck is true even if failOnDrift is true", () => {
    expect(getDriftArgs({ skipDriftCheck: true, failOnDrift: true }, "enterprise")).toBeUndefined();
  });
});

describe("runCheckDrift", () => {
  beforeEach(() => {
    checkForDrift.mockResolvedValue({ exitCode: 0, driftDetected: false, comparisonSupported: true });
  });

  it("should return undefined when edition is not enterprise", async () => {
    const result = await runCheckDrift(baseInputs, "community");

    expect(result).toBeUndefined();
  });

  it("should pass workingDirectory to checkForDrift", async () => {
    await runCheckDrift({ workingDirectory: "my-project" }, "enterprise");

    expect(checkForDrift).toHaveBeenCalledWith(expect.any(Array), "my-project");
  });

  it("should return exitCode and reportPath from result", async () => {
    checkForDrift.mockResolvedValue({
      exitCode: 0,
      driftDetected: false,
      comparisonSupported: true,
      reportPath: "custom-report.html",
    });

    const result = await runCheckDrift(baseInputs, "enterprise");

    expect(result).toEqual({ exitCode: 0, reportPath: "custom-report.html" });
  });

  it("should set GitHub outputs when drift detected", async () => {
    checkForDrift.mockResolvedValue({
      exitCode: 1,
      driftDetected: true,
      comparisonSupported: true,
      driftResolutionFolder: "/resolution",
    });

    await runCheckDrift(baseInputs, "enterprise");

    expect(setOutput).toHaveBeenCalledWith("drift-detected", "true");
    expect(setOutput).toHaveBeenCalledWith("drift-resolution-folder", "/resolution");
  });

  it("should set GitHub outputs when no drift and comparison supported", async () => {
    await runCheckDrift(baseInputs, "enterprise");

    expect(setOutput).toHaveBeenCalledWith("drift-detected", "false");
  });

  it("should not set outputs when comparison not supported", async () => {
    checkForDrift.mockResolvedValue({ exitCode: 0, driftDetected: false, comparisonSupported: false });

    await runCheckDrift(baseInputs, "enterprise");

    expect(setOutput).not.toHaveBeenCalledWith("drift-detected", expect.anything());
  });

  it("should not set outputs when non-drift error occurs", async () => {
    checkForDrift.mockResolvedValue({ exitCode: 1, driftDetected: false, comparisonSupported: true });

    await runCheckDrift(baseInputs, "enterprise");

    expect(setOutput).not.toHaveBeenCalledWith("drift-detected", expect.anything());
  });
});
