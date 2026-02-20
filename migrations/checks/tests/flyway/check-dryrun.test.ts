import type { FlywayMigrationsChecksInputs } from "../../src/types.js";

const info = vi.fn();

vi.doMock("@actions/core", () => ({
  info,
}));

const { getDryrunArgs } = await import("../../src/flyway/check-dryrun.js");

const baseInputs: FlywayMigrationsChecksInputs = {};

describe("getDryrunArgs", () => {
  it("should return args with -dryrun for enterprise edition", () => {
    const args = getDryrunArgs(baseInputs, "enterprise");

    expect(args).toBeDefined();
    expect(args![0]).toBe("check");
    expect(args).toContain("-outputType=json");
    expect(args).toContain("-outputLogsInJson=true");
    expect(args).toContain("-dryrun");
  });

  it("should include target and base args", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      targetUrl: "jdbc:postgresql://localhost/db",
      workingDirectory: "/app/db",
      extraArgs: "-X",
    };

    const args = getDryrunArgs(inputs, "enterprise");

    expect(args).toContain("-url=jdbc:postgresql://localhost/db");
    expect(args).toContain("-workingDirectory=/app/db");
    expect(args).toContain("-X");
  });

  it("should include target migration version and cherry pick", () => {
    const args = getDryrunArgs({ targetMigrationVersion: "5.0", cherryPick: "3.0,4.0" }, "enterprise");

    expect(args).toContain("-target=5.0");
    expect(args).toContain("-cherryPick=3.0,4.0");
  });

  it("should not include build environment args", () => {
    const args = getDryrunArgs({ buildUrl: "jdbc:sqlite:build.db" }, "enterprise");

    expect(args).not.toContain(expect.stringContaining("default_build"));
  });

  it("should return undefined for community edition", () => {
    expect(getDryrunArgs(baseInputs, "community")).toBeUndefined();
    expect(info).toHaveBeenCalledWith("Skipping deployment script review: not available in Community edition");
  });

  it("should return undefined when skipDeploymentScriptReview is true", () => {
    expect(getDryrunArgs({ skipDeploymentScriptReview: true }, "enterprise")).toBeUndefined();
    expect(info).toHaveBeenCalledWith(expect.stringContaining("Skipping deployment script review"));
  });

  it("should return args for teams edition", () => {
    const args = getDryrunArgs(baseInputs, "teams");

    expect(args).toBeDefined();
    expect(args).toContain("-dryrun");
  });
});
