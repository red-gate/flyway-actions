import type { FlywayMigrationsDeploymentInputs } from "../../src/types.js";

vi.doMock("@actions/core", () => ({
  info: vi.fn(),
  setOutput: vi.fn(),
}));

vi.doMock("@actions/exec", () => ({
  exec: vi.fn(),
}));

const { buildFlywayMigrateArgs } = await import("../../src/flyway/migrate.js");

describe("buildFlywayMigrateArgs", () => {
  it("should build args with defaults only", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {};

    const args = buildFlywayMigrateArgs(inputs);

    expect(args).toContain("migrate");
    expect(args.some((a) => a.includes("saveSnapshot"))).toBe(false);
  });

  it("should build args with url connection", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      url: "jdbc:postgresql://localhost/db",
      user: "admin",
      password: "secret",
    };

    const args = buildFlywayMigrateArgs(inputs);

    expect(args).toContain("-url=jdbc:postgresql://localhost/db");
    expect(args).toContain("-user=admin");
    expect(args).toContain("-password=secret");
  });

  it("should build args with environment", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      environment: "production",
    };

    const args = buildFlywayMigrateArgs(inputs);

    expect(args).toContain("-environment=production");
  });

  it("should build args with target", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      url: "jdbc:postgresql://localhost/db",
      target: "5.0",
    };

    const args = buildFlywayMigrateArgs(inputs);

    expect(args).toContain("-target=5.0");
  });

  it("should build args with cherry-pick", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      url: "jdbc:postgresql://localhost/db",
      cherryPick: "2.0,2.1",
    };

    const args = buildFlywayMigrateArgs(inputs);

    expect(args).toContain("-cherryPick=2.0,2.1");
  });

  it("should include -saveSnapshot=true when saveSnapshot is true", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      url: "jdbc:postgresql://localhost/db",
      saveSnapshot: true,
    };

    const args = buildFlywayMigrateArgs(inputs);

    expect(args).toContain("-saveSnapshot=true");
  });

  it("should omit -saveSnapshot when saveSnapshot is not set", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      url: "jdbc:postgresql://localhost/db",
    };

    const args = buildFlywayMigrateArgs(inputs);

    expect(args.some((a) => a.includes("saveSnapshot"))).toBe(false);
  });

  it("should include working directory", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      workingDirectory: "/app/db",
    };

    const args = buildFlywayMigrateArgs(inputs);

    expect(args).toContain("-workingDirectory=/app/db");
  });

  it("should include extra args", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      url: "jdbc:postgresql://localhost/db",
      extraArgs: "-X -custom=value",
    };

    const args = buildFlywayMigrateArgs(inputs);

    expect(args).toContain("-X");
    expect(args).toContain("-custom=value");
  });

  it("should not include undefined optional values", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {};

    const args = buildFlywayMigrateArgs(inputs);

    expect(args.filter((a) => a.includes("url")).length).toBe(0);
    expect(args.filter((a) => a.includes("user")).length).toBe(0);
    expect(args.filter((a) => a.includes("password")).length).toBe(0);
    expect(args.filter((a) => a.includes("environment")).length).toBe(0);
    expect(args.filter((a) => a.includes("target")).length).toBe(0);
    expect(args.filter((a) => a.includes("cherryPick")).length).toBe(0);
  });
});
