import { mockExec } from "../src/test-utils.js";

const info = vi.fn();
const error = vi.fn();
const exec = vi.fn();

vi.doMock("@actions/core", () => ({
  info,
  error,
  setOutput: vi.fn(),
}));

vi.doMock("@actions/exec", () => ({
  exec,
}));

const { parseErrorOutput, parseExtraArgs, maskArgsForLog, runFlyway, getFlywayDetails } =
  await import("../src/flyway-runner.js");

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

  it("should mask build env password args", () => {
    const masked = maskArgsForLog(["-environments.build.password=secret"]);

    expect(masked).toEqual(["-environments.build.password=***"]);
  });
});

describe("parseErrorOutput", () => {
  it("should return the error message from valid error output", () => {
    const stdout = JSON.stringify({ error: { errorCode: "FAULT", message: "Migration validation failed" } });

    const errorOutput = parseErrorOutput(stdout);

    expect(errorOutput?.error?.errorCode).toBe("FAULT");
    expect(errorOutput?.error?.message).toBe("Migration validation failed");
  });

  it("should return undefined for invalid JSON", () => {
    expect(parseErrorOutput("not json")).toBeUndefined();
  });

  it("should return undefined when error has no message", () => {
    const stdout = JSON.stringify({ error: { errorCode: "FAULT" } });

    const errorOutput = parseErrorOutput(stdout);

    expect(errorOutput?.error?.errorCode).toBe("FAULT");
    expect(errorOutput?.error?.message).toBeUndefined();
  });

  it("should return undefined when error field is missing", () => {
    const stdout = JSON.stringify({ something: "else" });

    const errorOutput = parseErrorOutput(stdout);

    expect(errorOutput?.error).toBeUndefined();
  });
});

describe("runFlyway", () => {
  it("should execute flyway with provided arguments and JSON flags", async () => {
    exec.mockResolvedValue(0);

    await runFlyway(["migrate", "-url=jdbc:sqlite:test.db"]);

    expect(exec).toHaveBeenCalledWith(
      "flyway",
      ["migrate", "-url=jdbc:sqlite:test.db", "-outputType=json", "-outputLogsInJson=true"],
      expect.any(Object),
    );
  });

  it("should return exit code and stdout", async () => {
    exec.mockImplementation(mockExec({ stdout: "success output" }));

    const result = await runFlyway(["migrate"]);

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe("success output");
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

  it("should log JSON log messages", async () => {
    const stderr = `${[
      JSON.stringify({ level: "INFO", message: "Migrate running" }),
      JSON.stringify({ level: "ERROR", message: "Migrate failed" }),
    ].join("\n")}\n`;
    exec.mockImplementation(mockExec({ stderr, exitCode: 1 }));

    await runFlyway(["migrate"]);

    expect(info).toHaveBeenCalledWith("Migrate running");
    expect(error).toHaveBeenCalledWith("Migrate failed");
  });

  it("should log stdout on failure without parsing error", async () => {
    const stdout = JSON.stringify({ error: { errorCode: "FAULT", message: "Checks failed" } });
    exec.mockImplementation(mockExec({ stdout, exitCode: 1 }));

    await runFlyway(["check"]);

    expect(info).toHaveBeenCalledWith(stdout);
    expect(error).not.toHaveBeenCalled();
  });

  it("should not log raw stderr as error", async () => {
    exec.mockImplementation(mockExec({ stderr: "Something went wrong", exitCode: 1 }));

    await runFlyway(["migrate"]);

    expect(error).not.toHaveBeenCalledWith("Something went wrong");
  });
});

describe("getFlywayDetails", () => {
  it("should return installed false when flyway is not found", async () => {
    exec.mockRejectedValue(new Error("Command not found"));

    const result = await getFlywayDetails();

    expect(error).toHaveBeenCalledWith("Command not found");
    expect(result).toEqual({ installed: false });
  });

  it("should detect Community edition", async () => {
    exec.mockImplementation(mockExec({ stdout: { edition: "COMMUNITY", version: "10.0.0" } }));

    const result = await getFlywayDetails();

    expect(result).toEqual({ installed: true, edition: "community" });
  });

  it("should detect Teams edition", async () => {
    exec.mockImplementation(mockExec({ stdout: { edition: "TEAMS", version: "10.5.0" } }));

    const result = await getFlywayDetails();

    expect(result).toEqual({ installed: true, edition: "teams" });
  });

  it("should detect Enterprise edition", async () => {
    exec.mockImplementation(mockExec({ stdout: { edition: "ENTERPRISE", version: "11.0.0" } }));

    const result = await getFlywayDetails();

    expect(result).toEqual({ installed: true, edition: "enterprise" });
  });

  it("should return installed false for unparseable output", async () => {
    exec.mockImplementation(mockExec({ stdout: "Something unexpected\n" }));

    const result = await getFlywayDetails();

    expect(error).toHaveBeenCalledWith(expect.stringContaining("not valid JSON"));
    expect(result).toEqual({ installed: false });
  });

  it("should pass version command with json output type", async () => {
    exec.mockImplementation(mockExec({ stdout: { edition: "COMMUNITY", version: "10.0.0" } }));

    await getFlywayDetails();

    expect(exec).toHaveBeenCalledWith("flyway", ["version", "-outputType=json"], expect.any(Object));
  });
});
