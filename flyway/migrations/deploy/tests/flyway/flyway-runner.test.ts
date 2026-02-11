import type { ExecOptions } from "@actions/exec";

const info = vi.fn();
const setOutput = vi.fn();
const exec = vi.fn();

vi.doMock("@actions/core", () => ({
  info,
  setOutput,
}));

vi.doMock("@actions/exec", () => ({
  exec,
}));

const { parseExtraArgs, maskArgsForLog, parseFlywayOutput, runFlyway, setDriftOutput, setOutputs, getFlywayDetails } =
  await import("../../src/flyway/flyway-runner.js");

describe("setDriftOutput", () => {
  it("should set drift-detected output to true", () => {
    setDriftOutput(true);
    expect(setOutput).toHaveBeenCalledWith("drift-detected", "true");
  });

  it("should set drift-detected output to false", () => {
    setDriftOutput(false);
    expect(setOutput).toHaveBeenCalledWith("drift-detected", "false");
  });
});

describe("parseExtraArgs", () => {
  it("should parse simple space-separated args", () => {
    const result = parseExtraArgs("-X -Y -Z");
    expect(result).toEqual(["-X", "-Y", "-Z"]);
  });

  it("should handle quoted strings with spaces", () => {
    const result = parseExtraArgs('-message="Hello World" -flag');
    expect(result).toEqual(["-message=Hello World", "-flag"]);
  });

  it("should handle single-quoted strings", () => {
    const result = parseExtraArgs("-message='Hello World' -flag");
    expect(result).toEqual(["-message=Hello World", "-flag"]);
  });

  it("should handle empty string", () => {
    const result = parseExtraArgs("");
    expect(result).toEqual([]);
  });

  it("should handle multiple spaces", () => {
    const result = parseExtraArgs("-X    -Y     -Z");
    expect(result).toEqual(["-X", "-Y", "-Z"]);
  });

  it("should handle args with equals signs", () => {
    const result = parseExtraArgs("-key=value -another=test");
    expect(result).toEqual(["-key=value", "-another=test"]);
  });

  it("should handle unclosed quotes", () => {
    const result = parseExtraArgs('-message="hello world');
    expect(result).toEqual(["-message=hello world"]);
  });

  it("should handle mixed quote types", () => {
    const result = parseExtraArgs(`-a="double" -b='single'`);
    expect(result).toEqual(["-a=double", "-b=single"]);
  });
});

describe("maskArgsForLog", () => {
  it("should mask password argument", () => {
    const args = ["-password=secret123"];
    const masked = maskArgsForLog(args);

    expect(masked).toContain("-password=***");
    expect(masked).not.toContain("-password=secret123");
  });

  it("should mask user argument", () => {
    const args = ["-user=admin"];
    const masked = maskArgsForLog(args);

    expect(masked).toContain("-user=***");
  });

  it("should mask url argument", () => {
    const args = ["-url=jdbc:postgresql://user:pass@localhost/db"];
    const masked = maskArgsForLog(args);

    expect(masked).toContain("-url=***");
    expect(masked).not.toContain("pass");
  });

  it("should handle empty array", () => {
    expect(maskArgsForLog([])).toEqual([]);
  });

  it("should mask case-insensitively", () => {
    const masked = maskArgsForLog(["-Password=secret", "-USER=admin", "-URL=jdbc:test"]);
    expect(masked).toEqual(["-Password=***", "-USER=***", "-URL=***"]);
  });

  it("should not mask non-sensitive args", () => {
    const args = ["-saveSnapshot=true", "-target=5.0"];
    const masked = maskArgsForLog(args);

    expect(masked).toEqual(args);
  });

  it("should handle mixed sensitive and non-sensitive args", () => {
    const args = ["-url=jdbc:postgresql://localhost/db", "-user=admin", "-password=secret", "-saveSnapshot=true"];
    const masked = maskArgsForLog(args);

    expect(masked[0]).toBe("-url=***");
    expect(masked[1]).toBe("-user=***");
    expect(masked[2]).toBe("-password=***");
    expect(masked[3]).toBe("-saveSnapshot=true");
  });

  it("should mask args containing password", () => {
    const masked = maskArgsForLog(["-jdbcPassword=secret"]);
    expect(masked).toEqual(["-jdbcPassword=***"]);
  });

  it("should mask args containing token", () => {
    const masked = maskArgsForLog(["-licenseKeyToken=abc123"]);
    expect(masked).toEqual(["-licenseKeyToken=***"]);
  });
});

describe("parseFlywayOutput", () => {
  it("should parse migration count from success message", () => {
    const stdout = `
Flyway Community Edition 10.0.0 by Redgate
Database: jdbc:postgresql://localhost/test
Successfully applied 3 migrations to schema "public" (execution time 00:00.150s)
    `;

    const result = parseFlywayOutput(stdout);

    expect(result.migrationsApplied).toBe(3);
  });

  it("should parse schema version", () => {
    const stdout = `
Flyway Community Edition 10.0.0 by Redgate
Database: jdbc:postgresql://localhost/test
Schema version: 2.0.1
    `;

    const result = parseFlywayOutput(stdout);

    expect(result.schemaVersion).toBe("2.0.1");
  });

  it("should parse current version of schema format", () => {
    const stdout = `
Current version of schema "public": 1.5
    `;

    const result = parseFlywayOutput(stdout);

    expect(result.schemaVersion).toBe("1.5");
  });

  it("should return defaults when no patterns match", () => {
    const stdout = "Some unrelated output";

    const result = parseFlywayOutput(stdout);

    expect(result.migrationsApplied).toBe(0);
    expect(result.schemaVersion).toBe("unknown");
  });

  it("should parse JSON output if present", () => {
    const stdout = `
{"schemaVersion": "3.0", "migrationsExecuted": 5}
    `;

    const result = parseFlywayOutput(stdout);

    expect(result.migrationsApplied).toBe(5);
    expect(result.schemaVersion).toBe("3.0");
  });

  it("should handle validated migrations message", () => {
    const stdout = `
Successfully validated 10 migrations
    `;

    const result = parseFlywayOutput(stdout);

    expect(result.migrationsApplied).toBe(10);
  });

  it("should handle zero migrations", () => {
    const stdout = `
Schema "public" is up to date. No migration necessary.
    `;

    const result = parseFlywayOutput(stdout);

    expect(result.migrationsApplied).toBe(0);
  });

  it("should handle empty string", () => {
    const result = parseFlywayOutput("");
    expect(result.migrationsApplied).toBe(0);
    expect(result.schemaVersion).toBe("unknown");
  });

  it("should fall back to regex when JSON is malformed", () => {
    const stdout = `
Successfully applied 2 migrations
Schema version: 4.0
{"schemaVersion": broken json}
    `;

    const result = parseFlywayOutput(stdout);

    expect(result.migrationsApplied).toBe(2);
    expect(result.schemaVersion).toBe("4.0");
  });
});

describe("runFlyway", () => {
  it("should execute flyway with provided arguments", async () => {
    exec.mockResolvedValue(0);

    await runFlyway(["migrate", "-url=jdbc:sqlite:test.db"]);

    expect(exec).toHaveBeenCalledWith("flyway", ["migrate", "-url=jdbc:sqlite:test.db"], expect.any(Object));
  });

  it("should return exit code, stdout, and stderr", async () => {
    exec.mockImplementation(async (_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stdout?.(Buffer.from("success output"));
      options?.listeners?.stderr?.(Buffer.from("warning output"));
      return 0;
    });

    const result = await runFlyway(["migrate"]);

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe("success output");
    expect(result.stderr).toBe("warning output");
  });

  it("should return non-zero exit code on failure", async () => {
    exec.mockResolvedValue(1);

    const result = await runFlyway(["migrate"]);

    expect(result.exitCode).toBe(1);
  });

  it("should set cwd when provided", async () => {
    exec.mockResolvedValue(0);

    await runFlyway(["migrate", "-url=jdbc:sqlite:test.db"], "/app/db");

    expect(exec).toHaveBeenCalledWith("flyway", expect.any(Array), expect.objectContaining({ cwd: "/app/db" }));
  });

  it("should not set cwd when not provided", async () => {
    exec.mockResolvedValue(0);

    await runFlyway(["migrate"]);

    expect(exec).toHaveBeenCalledWith(
      "flyway",
      expect.any(Array),
      expect.not.objectContaining({ cwd: expect.anything() }),
    );
  });

  it("should log masked command", async () => {
    exec.mockResolvedValue(0);

    await runFlyway(["migrate", "-url=jdbc:sqlite:test.db", "-password=secret"]);

    expect(info).toHaveBeenCalledWith(expect.stringContaining("-password=***"));
    expect(info).toHaveBeenCalledWith(expect.not.stringContaining("secret"));
  });
});

describe("setOutputs", () => {
  it("should set all outputs correctly", () => {
    setOutputs({
      exitCode: 0,
      migrationsApplied: 3,
      schemaVersion: "2.0",
    });

    expect(setOutput).toHaveBeenCalledWith("exit-code", "0");
    expect(setOutput).toHaveBeenCalledWith("migrations-applied", "3");
    expect(setOutput).toHaveBeenCalledWith("schema-version", "2.0");
  });
});

describe("getFlywayDetails", () => {
  it("should return installed false when flyway is not found", async () => {
    exec.mockRejectedValue(new Error("Command not found"));

    const result = await getFlywayDetails();

    expect(result).toEqual({ installed: false });
  });

  it("should detect Community edition", async () => {
    exec.mockImplementation(async (_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stdout?.(Buffer.from("Flyway Community Edition 10.0.0 by Redgate\n"));
      return 0;
    });

    const result = await getFlywayDetails();

    expect(result).toEqual({ installed: true, edition: "community" });
  });

  it("should detect Teams edition", async () => {
    exec.mockImplementation(async (_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stdout?.(Buffer.from("Flyway Teams Edition 10.5.0 by Redgate\n"));
      return 0;
    });

    const result = await getFlywayDetails();

    expect(result).toEqual({ installed: true, edition: "teams" });
  });

  it("should detect Enterprise edition", async () => {
    exec.mockImplementation(async (_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stdout?.(Buffer.from("Flyway Enterprise Edition 11.0.0 by Redgate\n"));
      return 0;
    });

    const result = await getFlywayDetails();

    expect(result).toEqual({ installed: true, edition: "enterprise" });
  });

  it("should default to community for unparseable output", async () => {
    exec.mockImplementation(async (_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stdout?.(Buffer.from("Something unexpected\n"));
      return 0;
    });

    const result = await getFlywayDetails();

    expect(result).toEqual({ installed: true, edition: "community" });
  });
});
