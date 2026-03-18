import type { FlywayStateDeploymentInputs } from "../../src/types.js";

const { getCommonArgs } = await import("../../src/flyway/arg-builders.js");

const baseInputs: FlywayStateDeploymentInputs = {};

describe("getCommonArgs", () => {
  it("should return empty array when no inputs", () => {
    expect(getCommonArgs(baseInputs)).toEqual([]);
  });

  describe("target params", () => {
    it("should use flat params with no environment", () => {
      const inputs: FlywayStateDeploymentInputs = {
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
      const inputs: FlywayStateDeploymentInputs = {
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
      const inputs: FlywayStateDeploymentInputs = {
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
    const inputs: FlywayStateDeploymentInputs = {
      ...baseInputs,
      workingDirectory: "/app/db",
    };

    const args = getCommonArgs(inputs);

    expect(args).toContain("-workingDirectory=/app/db");
  });

  it("should include extra args", () => {
    const inputs: FlywayStateDeploymentInputs = {
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
    const inputs: FlywayStateDeploymentInputs = {
      targetUrl: "jdbc:postgresql://localhost/db",
      scriptPath: "/scripts",
      saveSnapshot: true,
      skipDriftCheck: true,
      deploymentReportName: "report",
    };

    const args = getCommonArgs(inputs);

    expect(args.some((a) => a.includes("scriptPath"))).toBe(false);
    expect(args.some((a) => a.includes("saveSnapshot"))).toBe(false);
    expect(args.some((a) => a.includes("skipDriftCheck"))).toBe(false);
    expect(args.some((a) => a.includes("deploymentReportName"))).toBe(false);
  });
});
