import type { FlywayMigrationsChecksInputs } from "../../src/types.js";

const exec = vi.fn();

vi.doMock("@actions/core", () => ({
  info: vi.fn(),
  setOutput: vi.fn(),
}));

vi.doMock("@actions/exec", () => ({
  exec,
}));

const { getTargetEnvironmentArgs, getCheckCommandArgs, getBuildEnvironmentArgs, canAutoProvisionDocker } =
  await import("../../src/flyway/arg-builders.js");

const baseInputs: FlywayMigrationsChecksInputs = {};

describe("getTargetEnvironmentArgs", () => {
  it("should return empty array when no target inputs", () => {
    expect(getTargetEnvironmentArgs(baseInputs)).toEqual([]);
  });

  describe("target params", () => {
    it("should use flat params with no environment", () => {
      const inputs: FlywayMigrationsChecksInputs = {
        ...baseInputs,
        targetUrl: "jdbc:postgresql://localhost/db",
        targetUser: "admin",
        targetPassword: "secret",
        targetSchemas: "public,audit",
      };

      const args = getTargetEnvironmentArgs(inputs);

      expect(args).toContain("-url=jdbc:postgresql://localhost/db");
      expect(args).toContain("-user=admin");
      expect(args).toContain("-password=secret");
      expect(args).toContain("-schemas=public,audit");
    });

    it("should use flat params with default environment", () => {
      const inputs: FlywayMigrationsChecksInputs = {
        ...baseInputs,
        targetEnvironment: "default",
        targetUrl: "jdbc:postgresql://localhost/db",
        targetUser: "admin",
        targetPassword: "secret",
        targetSchemas: "public,audit",
      };

      const args = getTargetEnvironmentArgs(inputs);

      expect(args).toContain("-environment=default");
      expect(args).toContain("-url=jdbc:postgresql://localhost/db");
      expect(args).toContain("-user=admin");
      expect(args).toContain("-password=secret");
      expect(args).toContain("-schemas=public,audit");
    });

    it("should scope params to named environment", () => {
      const inputs: FlywayMigrationsChecksInputs = {
        ...baseInputs,
        targetEnvironment: "production",
        targetUrl: "jdbc:postgresql://localhost/db",
        targetUser: "admin",
        targetPassword: "secret",
        targetSchemas: "public,audit",
      };

      const args = getTargetEnvironmentArgs(inputs);

      expect(args).toContain("-environment=production");
      expect(args).toContain("-environments.production.url=jdbc:postgresql://localhost/db");
      expect(args).toContain("-environments.production.user=admin");
      expect(args).toContain("-environments.production.password=secret");
      expect(args).toContain("-environments.production.schemas=public,audit");
    });
  });
});

describe("getBuildEnvironmentArgs", () => {
  it("should default to a docker-provisioned build environment when no build inputs and target engine is supported", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      targetUrl: "jdbc:postgresql://localhost/db",
    };

    const args = getBuildEnvironmentArgs(inputs);

    expect(args).toContain("-check.buildEnvironment=default_build");
    expect(args).toContain("-environments.default_build.provisioner=docker");
  });

  it("should return empty array when no build inputs and target engine is not docker-provisionable", () => {
    const inputs: FlywayMigrationsChecksInputs = { ...baseInputs, targetUrl: "jdbc:sqlite:test.db" };

    expect(getBuildEnvironmentArgs(inputs)).toEqual([]);
  });

  it("should return empty array when no build inputs and no target url", () => {
    expect(getBuildEnvironmentArgs(baseInputs)).toEqual([]);
  });

  it("should not include the EULA flag by default when auto-provisioning", () => {
    const inputs: FlywayMigrationsChecksInputs = { ...baseInputs, targetUrl: "jdbc:sqlserver://localhost/db" };

    const args = getBuildEnvironmentArgs(inputs);

    expect(args.some((a) => a.startsWith("-environments.default_build.iAgreeToTheDBVendorsEula"))).toBe(false);
  });

  it("should include the EULA flag when auto-provisioning and buildDockerIAgreeToTheDbVendorsEula is true", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      targetUrl: "jdbc:sqlserver://localhost/db",
      buildDockerIAgreeToTheDbVendorsEula: true,
    };

    const args = getBuildEnvironmentArgs(inputs);

    expect(args).toContain("-environments.default_build.iAgreeToTheDBVendorsEula=true");
  });

  it("should include all build connection params", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      buildEnvironment: "build",
      buildUrl: "jdbc:postgresql://localhost/build-db",
      buildUser: "deploy",
      buildPassword: "secret",
      buildSchemas: "public,staging",
    };

    const args = getBuildEnvironmentArgs(inputs);

    expect(args).toContain("-check.buildEnvironment=build");
    expect(args).toContain("-environments.build.url=jdbc:postgresql://localhost/build-db");
    expect(args).toContain("-environments.build.user=deploy");
    expect(args).toContain("-environments.build.password=secret");
    expect(args).toContain("-environments.build.schemas=public,staging");
  });

  it("should only include provided build params", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      buildUrl: "jdbc:sqlite:build.db",
    };

    const args = getBuildEnvironmentArgs(inputs);

    expect(args).toContain("-check.buildEnvironment=default_build");
    expect(args).toContain("-environments.default_build.url=jdbc:sqlite:build.db");
  });

  it("should set clean provisioner for build environment when buildOkToErase is true", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      buildEnvironment: "build",
      buildOkToErase: true,
    };

    const args = getBuildEnvironmentArgs(inputs);

    expect(args).toContain("-environments.build.flyway.cleanDisabled=false");
  });

  it("should not set clean provisioner when buildOkToErase is false", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      buildEnvironment: "build",
      buildOkToErase: false,
    };

    const args = getBuildEnvironmentArgs(inputs);

    expect(args).not.toContain("-environments.build.provisioner=clean");
  });

  it("should use default_build environment when buildEnvironment is not set", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      buildUrl: "jdbc:sqlite:build.db",
      buildOkToErase: true,
    };

    const args = getBuildEnvironmentArgs(inputs);

    expect(args).toContain("-environments.default_build.flyway.cleanDisabled=false");
  });
});

describe("getCheckCommandArgs", () => {
  it("should return default args when no base inputs", () => {
    expect(getCheckCommandArgs(baseInputs)).toEqual(["check"]);
  });

  it("should include working directory", () => {
    const inputs: FlywayMigrationsChecksInputs = { ...baseInputs, workingDirectory: "/app/db" };

    const args = getCheckCommandArgs(inputs);

    expect(args).toContain("-workingDirectory=/app/db");
  });

  it("should include report filename when preDeploymentReportName is set", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      preDeploymentReportName: "deployment-report",
    };

    const args = getCheckCommandArgs(inputs);

    expect(args).toContain("-reportFilename=deployment-report");
  });

  it("should not include report filename when preDeploymentReportName is not set", () => {
    const args = getCheckCommandArgs(baseInputs);

    expect(args.some((a) => a.startsWith("-reportFilename="))).toBe(false);
  });

  it("should include extra args", () => {
    const inputs: FlywayMigrationsChecksInputs = { ...baseInputs, extraArgs: "-X -custom=value" };

    const args = getCheckCommandArgs(inputs);

    expect(args).toContain("-X");
    expect(args).toContain("-custom=value");
  });

  it("should place extra args after report filename", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      extraArgs: "-reportFilename=override-name",
      preDeploymentReportName: "deployment-report",
    };

    const args = getCheckCommandArgs(inputs);

    const reportNameIndex = args.indexOf("-reportFilename=deployment-report");
    const extraArgIndex = args.indexOf("-reportFilename=override-name");

    expect(extraArgIndex).toBeGreaterThan(reportNameIndex);
  });
});

describe("canAutoProvisionDocker", () => {
  it.each([
    "jdbc:postgresql://localhost/db",
    "jdbc:mysql://localhost/db",
    "jdbc:sqlserver://localhost/db",
    "jdbc:oracle:thin:@localhost/db",
  ])("should return true for docker-provisionable url %s", (targetUrl) => {
    expect(canAutoProvisionDocker({ ...baseInputs, targetUrl })).toBe(true);
  });

  it("should return false for a non-docker-provisionable engine such as sqlite", () => {
    expect(canAutoProvisionDocker({ ...baseInputs, targetUrl: "jdbc:sqlite:test.db" })).toBe(false);
  });

  it("should return false when no target url is provided", () => {
    expect(canAutoProvisionDocker(baseInputs)).toBe(false);
  });
});
