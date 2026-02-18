import type { FlywayMigrationsChecksInputs } from "../../src/types.js";

const exec = vi.fn();

vi.doMock("@actions/core", () => ({
  info: vi.fn(),
  setOutput: vi.fn(),
}));

vi.doMock("@actions/exec", () => ({
  exec,
}));

const { buildTargetArgs, buildBaseArgs, getBuildEnvironmentArgs } = await import("../../src/flyway/arg-builders.js");

const baseInputs: FlywayMigrationsChecksInputs = {};

describe("buildTargetArgs", () => {
  it("should return empty array when no target inputs", () => {
    expect(buildTargetArgs(baseInputs)).toEqual([]);
  });

  it("should include all target connection params", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      targetEnvironment: "production",
      targetUrl: "jdbc:postgresql://localhost/db",
      targetUser: "admin",
      targetPassword: "secret",
      targetSchemas: "public,audit",
    };

    const args = buildTargetArgs(inputs);

    expect(args).toContain("-environment=production");
    expect(args).toContain("-url=jdbc:postgresql://localhost/db");
    expect(args).toContain("-user=admin");
    expect(args).toContain("-password=secret");
    expect(args).toContain("-schemas=public,audit");
  });

  it("should only include provided target params", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      targetUrl: "jdbc:sqlite:test.db",
    };

    const args = buildTargetArgs(inputs);

    expect(args).toEqual(["-url=jdbc:sqlite:test.db"]);
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

    expect(args).toContain("-buildEnvironment=build");
    expect(args).toContain("-buildUrl=jdbc:postgresql://localhost/build-db");
    expect(args).toContain("-buildUser=deploy");
    expect(args).toContain("-buildPassword=secret");
    expect(args).toContain("-buildSchemas=public,staging");
  });

  it("should only include provided build params", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      buildUrl: "jdbc:sqlite:build.db",
    };

    const args = getBuildEnvironmentArgs(inputs);

    expect(args).toEqual(["-buildUrl=jdbc:sqlite:build.db"]);
  });
});

describe("buildBaseArgs", () => {
  it("should return empty array when no base inputs", () => {
    expect(buildBaseArgs(baseInputs)).toEqual([]);
  });

  it("should include working directory", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      workingDirectory: "/app/db",
    };

    const args = buildBaseArgs(inputs);

    expect(args).toContain("-workingDirectory=/app/db");
  });

  it("should include extra args", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      extraArgs: "-X -custom=value",
    };

    const args = buildBaseArgs(inputs);

    expect(args).toContain("-X");
    expect(args).toContain("-custom=value");
  });
});
