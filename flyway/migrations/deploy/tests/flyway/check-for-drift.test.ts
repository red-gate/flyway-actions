import type { FlywayMigrationsDeploymentInputs } from "../../src/types.js";

vi.doMock("@actions/core", () => ({
  info: vi.fn(),
  setOutput: vi.fn(),
}));

vi.doMock("@actions/exec", () => ({
  exec: vi.fn(),
}));

const { buildFlywayCheckDriftArgs } = await import("../../src/flyway/check-for-drift.js");

describe("buildFlywayCheckDriftArgs", () => {
  it("should build args with check and -drift as first elements", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {};

    const args = buildFlywayCheckDriftArgs(inputs);

    expect(args[0]).toBe("check");
    expect(args[1]).toBe("-drift");
  });

  it("should include connection params", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      url: "jdbc:postgresql://localhost/db",
      user: "admin",
      password: "secret",
      environment: "production",
    };

    const args = buildFlywayCheckDriftArgs(inputs);

    expect(args).toContain("-url=jdbc:postgresql://localhost/db");
    expect(args).toContain("-user=admin");
    expect(args).toContain("-password=secret");
    expect(args).toContain("-environment=production");
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
      url: "jdbc:postgresql://localhost/db",
      target: "5.0",
      cherryPick: "2.0,2.1",
      saveSnapshot: true,
    };

    const args = buildFlywayCheckDriftArgs(inputs);

    expect(args.some((a) => a.includes("target"))).toBe(false);
    expect(args.some((a) => a.includes("cherryPick"))).toBe(false);
    expect(args.some((a) => a.includes("saveSnapshot"))).toBe(false);
  });
});
