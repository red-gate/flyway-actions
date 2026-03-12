import type { FlywayStatePrepareInputs } from "../../src/types.js";

const { getCommonArgs, getPrepareArgs } = await import("../../src/flyway/arg-builders.js");

describe("getPrepareArgs", () => {
  it("should build args with prepare command and schema model source", () => {
    const inputs: FlywayStatePrepareInputs = {
      targetUrl: "jdbc:sqlite:test.db",
    };

    const args = getPrepareArgs(inputs);

    expect(args[0]).toBe("prepare");
    expect(args).toContain("-source=schemaModel");
  });

  it("should use -target instead of -environment", () => {
    const inputs: FlywayStatePrepareInputs = {
      targetEnvironment: "production",
      targetUrl: "jdbc:postgresql://localhost/db",
    };

    const args = getPrepareArgs(inputs);

    expect(args).toContain("-target=production");
    expect(args).not.toContain("-environment=production");
  });

  it("should scope params to named environment", () => {
    const inputs: FlywayStatePrepareInputs = {
      targetEnvironment: "production",
      targetUrl: "jdbc:postgresql://localhost/db",
    };

    const args = getPrepareArgs(inputs);

    expect(args).toContain("-environments.production.url=jdbc:postgresql://localhost/db");
  });

  it("should include deploy and undo prepare types when generate-undo is true", () => {
    const inputs: FlywayStatePrepareInputs = {
      targetUrl: "jdbc:sqlite:test.db",
      generateUndo: true,
    };

    const args = getPrepareArgs(inputs);

    expect(args).toContain("-types=deploy,undo");
  });

  it("should include only deploy prepare type when generate-undo is false", () => {
    const inputs: FlywayStatePrepareInputs = {
      targetUrl: "jdbc:sqlite:test.db",
      generateUndo: false,
    };

    const args = getPrepareArgs(inputs);

    expect(args).toContain("-types=deploy");
  });

  it("should include working directory", () => {
    const inputs: FlywayStatePrepareInputs = {
      targetUrl: "jdbc:sqlite:test.db",
      workingDirectory: "/app/db",
    };

    const args = getPrepareArgs(inputs);

    expect(args).toContain("-workingDirectory=/app/db");
  });

  it("should include extra args", () => {
    const inputs: FlywayStatePrepareInputs = {
      targetUrl: "jdbc:sqlite:test.db",
      extraArgs: "-X -custom=value",
    };

    const args = getPrepareArgs(inputs);

    expect(args).toContain("-X");
    expect(args).toContain("-custom=value");
  });
});

describe("getCommonArgs", () => {
  it("should use -environment instead of -target", () => {
    const inputs: FlywayStatePrepareInputs = {
      targetEnvironment: "production",
      targetUrl: "jdbc:postgresql://localhost/db",
    };

    const args = getCommonArgs(inputs);

    expect(args).toContain("-environment=production");
    expect(args).not.toContain("-target=production");
  });

  it("should scope params to named environment", () => {
    const inputs: FlywayStatePrepareInputs = {
      targetEnvironment: "production",
      targetUrl: "jdbc:postgresql://localhost/db",
      targetUser: "admin",
      targetPassword: "secret",
      targetSchemas: "public,app",
    };

    const args = getCommonArgs(inputs);

    expect(args).toContain("-environments.production.url=jdbc:postgresql://localhost/db");
    expect(args).toContain("-environments.production.user=admin");
    expect(args).toContain("-environments.production.password=secret");
    expect(args).toContain("-environments.production.schemas=public,app");
  });

  it("should use flat params for default environment", () => {
    const inputs: FlywayStatePrepareInputs = {
      targetEnvironment: "default",
      targetUrl: "jdbc:sqlite:test.db",
    };

    const args = getCommonArgs(inputs);

    expect(args).toContain("-url=jdbc:sqlite:test.db");
  });

  it("should include working directory", () => {
    const inputs: FlywayStatePrepareInputs = {
      targetUrl: "jdbc:sqlite:test.db",
      workingDirectory: "/app/db",
    };

    const args = getCommonArgs(inputs);

    expect(args).toContain("-workingDirectory=/app/db");
  });

  it("should include extra args", () => {
    const inputs: FlywayStatePrepareInputs = {
      targetUrl: "jdbc:sqlite:test.db",
      extraArgs: "-X -custom=value",
    };

    const args = getCommonArgs(inputs);

    expect(args).toContain("-X");
    expect(args).toContain("-custom=value");
  });
});
