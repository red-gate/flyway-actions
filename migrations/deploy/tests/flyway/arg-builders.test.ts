import type { FlywayMigrationsDeploymentInputs } from "../../src/types.js";

const { getCommonArgs } = await import("../../src/flyway/arg-builders.js");

const baseInputs: FlywayMigrationsDeploymentInputs = {};

describe("getCommonArgs", () => {
  it("should return empty array when no inputs", () => {
    expect(getCommonArgs(baseInputs)).toEqual([]);
  });

  describe("target params", () => {
    it("should use flat params with no environment", () => {
      const inputs: FlywayMigrationsDeploymentInputs = {
        ...baseInputs,
        targetUrl: "jdbc:postgresql://localhost/db",
        targetUser: "admin",
        targetPassword: "secret",
        targetSchemas: "public,audit",
      };

      const args = getCommonArgs(inputs);

      expect(args).toContain("-url=jdbc:postgresql://localhost/db");
      expect(args).toContain("-user=admin");
      expect(args).toContain("-password=secret");
      expect(args).toContain("-schemas=public,audit");
    });

    it("should use flat params with default environment", () => {
      const inputs: FlywayMigrationsDeploymentInputs = {
        ...baseInputs,
        targetEnvironment: "default",
        targetUrl: "jdbc:postgresql://localhost/db",
        targetUser: "admin",
        targetPassword: "secret",
        targetSchemas: "public,audit",
      };

      const args = getCommonArgs(inputs);

      expect(args).toContain("-environment=default");
      expect(args).toContain("-url=jdbc:postgresql://localhost/db");
      expect(args).toContain("-user=admin");
      expect(args).toContain("-password=secret");
      expect(args).toContain("-schemas=public,audit");
    });

    it("should scope params to named environment", () => {
      const inputs: FlywayMigrationsDeploymentInputs = {
        ...baseInputs,
        targetEnvironment: "production",
        targetUrl: "jdbc:postgresql://localhost/db",
        targetUser: "admin",
        targetPassword: "secret",
        targetSchemas: "public,audit",
      };

      const args = getCommonArgs(inputs);

      expect(args).toContain("-environment=production");
      expect(args).toContain("-environments.production.url=jdbc:postgresql://localhost/db");
      expect(args).toContain("-environments.production.user=admin");
      expect(args).toContain("-environments.production.password=secret");
      expect(args).toContain("-environments.production.schemas=public,audit");
    });
  });

  it("should include working directory", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      ...baseInputs,
      workingDirectory: "/app/db",
    };

    const args = getCommonArgs(inputs);

    expect(args).toContain("-workingDirectory=/app/db");
  });

  it("should include extra args", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      ...baseInputs,
      extraArgs: "-X -custom=value",
    };

    const args = getCommonArgs(inputs);

    expect(args).toContain("-X");
    expect(args).toContain("-custom=value");
  });

  it("should not include undefined optional values", () => {
    const args = getCommonArgs(baseInputs);

    expect(args.filter((a) => a.includes("url")).length).toBe(0);
    expect(args.filter((a) => a.includes("user")).length).toBe(0);
    expect(args.filter((a) => a.includes("password")).length).toBe(0);
    expect(args.filter((a) => a.includes("environment")).length).toBe(0);
  });

  it("should not include action-specific inputs", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      targetUrl: "jdbc:postgresql://localhost/db",
      targetMigrationVersion: "5.0",
      cherryPick: "2.0,2.1",
      baselineOnMigrate: true,
      saveSnapshot: true,
      skipDriftCheck: true,
      driftReportName: "report",
    };

    const args = getCommonArgs(inputs);

    expect(args.some((a) => a.includes("target"))).toBe(false);
    expect(args.some((a) => a.includes("cherryPick"))).toBe(false);
    expect(args.some((a) => a.includes("baselineOnMigrate"))).toBe(false);
    expect(args.some((a) => a.includes("saveSnapshot"))).toBe(false);
    expect(args.some((a) => a.includes("skipDriftCheck"))).toBe(false);
    expect(args.some((a) => a.includes("driftReportName"))).toBe(false);
  });
});
