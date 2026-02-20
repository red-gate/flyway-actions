import type { FlywayMigrationsChecksInputs } from "../../src/types.js";

const info = vi.fn();
const setOutput = vi.fn();

vi.doMock("@actions/core", () => ({
  info,
  setOutput,
}));

const { getDriftArgs, setDriftOutputs } = await import("../../src/flyway/check-drift.js");

const baseInputs: FlywayMigrationsChecksInputs = {};

describe("getDriftArgs", () => {
  it("should return args with -drift for enterprise edition", () => {
    const args = getDriftArgs(baseInputs, "enterprise");

    expect(args).toBeDefined();
    expect(args![0]).toBe("check");
    expect(args).toContain("-outputType=json");
    expect(args).toContain("-outputLogsInJson=true");
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

describe("setDriftOutputs", () => {
  it("should set drift-detected to true when differences exist", () => {
    setDriftOutputs({ individualResults: [{ operation: "drift", differences: [{ name: "Table_1" }] }] });

    expect(setOutput).toHaveBeenCalledWith("drift-detected", "true");
  });

  it("should set drift-detected to false when no differences", () => {
    setDriftOutputs({ individualResults: [{ operation: "drift", onlyInSource: [], onlyInTarget: [] }] });

    expect(setOutput).toHaveBeenCalledWith("drift-detected", "false");
  });

  it("should not set drift-detected when drift result is absent", () => {
    setDriftOutputs({ individualResults: [{ operation: "code", results: [] }] });

    expect(setOutput).not.toHaveBeenCalledWith("drift-detected", expect.anything());
  });
});
