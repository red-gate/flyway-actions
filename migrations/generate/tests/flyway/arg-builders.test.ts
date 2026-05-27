import type { FlywayCommandInputs } from "../../src/types.js";

const { getDiffArgs, getGenerateArgs } = await import("../../src/flyway/arg-builders.js");

describe("getDiffArgs", () => {
  it("should start with diff command", () => {
    const args = getDiffArgs({});

    expect(args[0]).toBe("diff");
  });

  it("should target migrations", () => {
    const args = getDiffArgs({});

    expect(args).toContain("-target=migrations");
  });

  it("should set diff.buildEnvironment when build inputs provided", () => {
    const args = getDiffArgs({ buildEnvironment: "build" });

    expect(args).toContain("-diff.buildEnvironment=build");
  });

  it("should set diff.buildEnvironment to the default when only build-url provided", () => {
    const args = getDiffArgs({ buildUrl: "jdbc:postgresql://localhost/build" });

    expect(args).toContain("-diff.buildEnvironment=default_build");
  });

  it("should omit diff.buildEnvironment when no build inputs provided", () => {
    const args = getDiffArgs({});

    expect(args.some((a) => a.startsWith("-diff.buildEnvironment="))).toBe(false);
  });

  it("should include source when provided", () => {
    const args = getDiffArgs({ source: "schemaModel" });

    expect(args).toContain("-source=schemaModel");
  });

  it("should include build environment args", () => {
    const inputs: FlywayCommandInputs = {
      buildEnvironment: "build",
      buildUrl: "jdbc:postgresql://localhost/build",
      buildUser: "admin",
      buildPassword: "shh",
      buildSchemas: "public,audit",
    };

    const args = getDiffArgs(inputs);

    expect(args).toContain("-environment=build");
    expect(args).toContain("-environments.build.url=jdbc:postgresql://localhost/build");
    expect(args).toContain("-environments.build.user=admin");
    expect(args).toContain("-environments.build.password=shh");
    expect(args).toContain("-environments.build.schemas=public,audit");
  });

  it("should default the build environment name when only url provided", () => {
    const args = getDiffArgs({ buildUrl: "jdbc:postgresql://localhost/build" });

    expect(args).toContain("-environment=default_build");
    expect(args).toContain("-environments.default_build.url=jdbc:postgresql://localhost/build");
  });

  it("should omit build args when no build inputs provided", () => {
    const args = getDiffArgs({ source: "schemaModel" });

    expect(args.some((a) => a.startsWith("-environment="))).toBe(false);
    expect(args.some((a) => a.startsWith("-environments."))).toBe(false);
  });

  it("should include working directory", () => {
    const args = getDiffArgs({ workingDirectory: "/app/db" });

    expect(args).toContain("-workingDirectory=/app/db");
  });

  it("should include extra args", () => {
    const args = getDiffArgs({ extraArgs: "-X -custom=value" });

    expect(args).toContain("-X");
    expect(args).toContain("-custom=value");
  });
});

describe("getGenerateArgs", () => {
  it("should start with generate command", () => {
    const args = getGenerateArgs({});

    expect(args[0]).toBe("generate");
  });

  it("should include types when provided", () => {
    const args = getGenerateArgs({ migrationTypes: "versioned,undo" });

    expect(args).toContain("-types=versioned,undo");
  });

  it("should omit types when not provided", () => {
    const args = getGenerateArgs({});

    expect(args.some((a) => a.startsWith("-types="))).toBe(false);
  });

  it("should include description when provided", () => {
    const args = getGenerateArgs({ migrationDescription: "add_orders_table" });

    expect(args).toContain("-description=add_orders_table");
  });

  it("should omit description when not provided", () => {
    const args = getGenerateArgs({});

    expect(args.some((a) => a.startsWith("-description="))).toBe(false);
  });

  it("should include working directory", () => {
    const args = getGenerateArgs({ workingDirectory: "/app/db" });

    expect(args).toContain("-workingDirectory=/app/db");
  });

  it("should include extra args", () => {
    const args = getGenerateArgs({ extraArgs: "-X -custom=value" });

    expect(args).toContain("-X");
    expect(args).toContain("-custom=value");
  });

  it("should not include source even when provided", () => {
    const args = getGenerateArgs({ source: "schemaModel" });

    expect(args.some((a) => a.startsWith("-source="))).toBe(false);
  });

  it("should not include build environment args even when provided", () => {
    const args = getGenerateArgs({
      buildEnvironment: "build",
      buildUrl: "jdbc:postgresql://localhost/build",
    });

    expect(args.some((a) => a.startsWith("-environment="))).toBe(false);
    expect(args.some((a) => a.startsWith("-environments."))).toBe(false);
  });
});
