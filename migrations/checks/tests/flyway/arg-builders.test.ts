import type { FlywayMigrationsChecksInputs } from "../../src/types.js";

const exec = vi.fn();

vi.doMock("@actions/core", () => ({
  info: vi.fn(),
  setOutput: vi.fn(),
}));

vi.doMock("@actions/exec", () => ({
  exec,
}));

const { getTargetEnvironmentArgs, getCheckCommandArgs, getBuildEnvironmentArgs } =
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
  it("should return empty array when no build inputs", () => {
    expect(getBuildEnvironmentArgs(baseInputs)).toEqual([]);
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

    expect(args).toContain("-environments.build.provisioner=clean");
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

    expect(args).toContain("-environments.default_build.provisioner=clean");
  });
});

describe("getCheckCommandArgs", () => {
  it("should return default args when no base inputs", () => {
    expect(getCheckCommandArgs(baseInputs)).toEqual(["check", "-outputType=json", "-outputLogsInJson=true"]);
  });

  it("should include working directory", () => {
    const inputs: FlywayMigrationsChecksInputs = { ...baseInputs, workingDirectory: "/app/db" };

    const args = getCheckCommandArgs(inputs);

    expect(args).toContain("-workingDirectory=/app/db");
  });

  it("should include extra args", () => {
    const inputs: FlywayMigrationsChecksInputs = { ...baseInputs, extraArgs: "-X -custom=value" };

    const args = getCheckCommandArgs(inputs);

    expect(args).toContain("-X");
    expect(args).toContain("-custom=value");
  });
});
