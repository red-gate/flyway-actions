import type { FlywayStatePrepareInputs } from "../../src/types.js";

const { getPrepareArgs } = await import("../../src/flyway/arg-builders.js");

const baseInputs: FlywayStatePrepareInputs = {};

describe("getPrepareArgs", () => {
  it("should build args with prepare command and schema model source", () => {
    const inputs: FlywayStatePrepareInputs = {
      ...baseInputs,
      targetUrl: "jdbc:sqlite:test.db",
    };

    const args = getPrepareArgs(inputs);

    expect(args[0]).toBe("prepare");
    expect(args).toContain("-source=schemaModel");
  });

  it("should use -target instead of -environment", () => {
    const inputs: FlywayStatePrepareInputs = {
      ...baseInputs,
      targetEnvironment: "production",
      targetUrl: "jdbc:postgresql://localhost/db",
    };

    const args = getPrepareArgs(inputs);

    expect(args).toContain("-target=production");
    expect(args).not.toContain("-environment=production");
  });

  it("should scope params to named environment", () => {
    const inputs: FlywayStatePrepareInputs = {
      ...baseInputs,
      targetEnvironment: "production",
      targetUrl: "jdbc:postgresql://localhost/db",
    };

    const args = getPrepareArgs(inputs);

    expect(args).toContain("-environments.production.url=jdbc:postgresql://localhost/db");
  });

  it("should include deploy and undo prepare types when generate-undo is true", () => {
    const inputs: FlywayStatePrepareInputs = {
      ...baseInputs,
      targetUrl: "jdbc:sqlite:test.db",
      generateUndo: true,
    };

    const args = getPrepareArgs(inputs);

    expect(args).toContain("-types=deploy,undo");
  });

  it("should include only deploy prepare type when generate-undo is false", () => {
    const inputs: FlywayStatePrepareInputs = {
      ...baseInputs,
      targetUrl: "jdbc:sqlite:test.db",
      generateUndo: false,
    };

    const args = getPrepareArgs(inputs);

    expect(args).toContain("-types=deploy");
  });

  it("should include working directory", () => {
    const inputs: FlywayStatePrepareInputs = {
      ...baseInputs,
      targetUrl: "jdbc:sqlite:test.db",
      workingDirectory: "/app/db",
    };

    const args = getPrepareArgs(inputs);

    expect(args).toContain("-workingDirectory=/app/db");
  });

  it("should include extra args", () => {
    const inputs: FlywayStatePrepareInputs = {
      ...baseInputs,
      targetUrl: "jdbc:sqlite:test.db",
      extraArgs: "-X -custom=value",
    };

    const args = getPrepareArgs(inputs);

    expect(args).toContain("-X");
    expect(args).toContain("-custom=value");
  });
});
