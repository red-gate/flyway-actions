import type { FlywayMigrationsChecksInputs } from "../../src/types.js";

const exec = vi.fn();

vi.doMock("@actions/core", () => ({
  info: vi.fn(),
  setOutput: vi.fn(),
}));

vi.doMock("@actions/exec", () => ({
  exec,
}));

const { buildTargetArgs, buildBuildEnvArgs, buildBaseArgs } = await import("../../src/flyway/arg-builders.js");

const baseInputs: FlywayMigrationsChecksInputs = {
  generateReport: true,
  failOnDrift: true,
  failOnCodeReview: true,
};

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

describe("buildBuildEnvArgs", () => {
  it("should return empty array when no build inputs", () => {
    expect(buildBuildEnvArgs(baseInputs)).toEqual([]);
  });

  it("should use named build environment when provided", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      buildEnvironment: "shadow",
    };

    const args = buildBuildEnvArgs(inputs);

    expect(args).toEqual(["-buildEnvironment=shadow"]);
  });

  it("should use inline build env with default name when buildUrl provided", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      buildUrl: "jdbc:postgresql://localhost/build",
      buildUser: "builduser",
      buildPassword: "buildsecret",
      buildSchemas: "public",
    };

    const args = buildBuildEnvArgs(inputs);

    expect(args).toContain("-buildEnvironment=build");
    expect(args).toContain("-environments.build.url=jdbc:postgresql://localhost/build");
    expect(args).toContain("-environments.build.user=builduser");
    expect(args).toContain("-environments.build.password=buildsecret");
    expect(args).toContain("-environments.build.schemas=public");
  });

  it("should use named env when both buildEnvironment and buildUrl are set", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      buildEnvironment: "shadow",
      buildUrl: "jdbc:postgresql://localhost/build",
      buildUser: "builduser",
    };

    const args = buildBuildEnvArgs(inputs);

    expect(args).toContain("-buildEnvironment=shadow");
    expect(args).not.toContain("-buildEnvironment=build");
    expect(args).toContain("-environments.shadow.url=jdbc:postgresql://localhost/build");
    expect(args).toContain("-environments.shadow.user=builduser");
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
