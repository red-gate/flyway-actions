import type { FlywayMigrationsDeploymentInputs } from "../../src/types.js";

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

const { buildFlywayCheckDriftArgs, checkForDrift } = await import("../../src/flyway/check-for-drift.js");

describe("checkForDrift", () => {
  it("should set drift-detected output to false when exit code is 0", async () => {
    exec.mockResolvedValue(0);

    await checkForDrift({ targetUrl: "jdbc:sqlite:test.db" });

    expect(setOutput).toHaveBeenCalledWith("drift-detected", "false");
  });

  it("should set drift-detected output to true when exit code is non-zero", async () => {
    exec.mockResolvedValue(1);

    await checkForDrift({ targetUrl: "jdbc:sqlite:test.db" });

    expect(setOutput).toHaveBeenCalledWith("drift-detected", "true");
  });
});

describe("buildFlywayCheckDriftArgs", () => {
  it("should build args with check and -drift as first elements", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {};

    const args = buildFlywayCheckDriftArgs(inputs);

    expect(args[0]).toBe("check");
    expect(args[1]).toBe("-drift");
    expect(args[2]).toBe("-failOnDrift=true");
  });

  it("should include connection params", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      targetUrl: "jdbc:postgresql://localhost/db",
      targetUser: "admin",
      targetPassword: "secret",
      targetEnvironment: "production",
      targetSchemas: "public,audit",
    };

    const args = buildFlywayCheckDriftArgs(inputs);

    expect(args).toContain("-url=jdbc:postgresql://localhost/db");
    expect(args).toContain("-user=admin");
    expect(args).toContain("-password=secret");
    expect(args).toContain("-environment=production");
    expect(args).toContain("-schemas=public,audit");
  });

  it("should include workingDirectory and extraArgs", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      workingDirectory: "/app/db",
      extraArgs: "-X -custom=value",
    };

    const args = buildFlywayCheckDriftArgs(inputs);

    expect(args).toContain("-workingDirectory=/app/db");
    expect(args).toContain("-X");
    expect(args).toContain("-custom=value");
  });

  it("should not include target, cherryPick, or saveSnapshot", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      targetUrl: "jdbc:postgresql://localhost/db",
      targetMigrationVersion: "5.0",
      cherryPick: "2.0,2.1",
      saveSnapshot: true,
    };

    const args = buildFlywayCheckDriftArgs(inputs);

    expect(args.some((a) => a.includes("target"))).toBe(false);
    expect(args.some((a) => a.includes("cherryPick"))).toBe(false);
    expect(args.some((a) => a.includes("saveSnapshot"))).toBe(false);
  });
});
