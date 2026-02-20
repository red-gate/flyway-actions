import type { FlywayMigrationsChecksInputs } from "../../src/types.js";
import type { ExecOptions } from "@actions/exec";

const info = vi.fn();
const error = vi.fn();
const setOutput = vi.fn();
const exec = vi.fn();

vi.doMock("@actions/core", () => ({
  info,
  error,
  setOutput,
  startGroup: vi.fn(),
  endGroup: vi.fn(),
}));

vi.doMock("@actions/exec", () => ({
  exec,
}));

const { runChecks } = await import("../../src/flyway/run-checks.js");

const baseInputs: FlywayMigrationsChecksInputs = {};

describe("runChecks", () => {
  it("should not throw on success", async () => {
    exec.mockImplementation((_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stdout?.(Buffer.from("{}"));
      return Promise.resolve(0);
    });

    await expect(runChecks(baseInputs, "enterprise")).resolves.not.toThrow();
  });

  it("should set exit-code to 0 on success", async () => {
    exec.mockImplementation((_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stdout?.(Buffer.from("{}"));
      return Promise.resolve(0);
    });

    await runChecks(baseInputs, "enterprise");

    expect(setOutput).toHaveBeenCalledWith("exit-code", "0");
  });

  it("should make separate exec calls for each check type", async () => {
    exec.mockImplementation((_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stdout?.(Buffer.from("{}"));
      return Promise.resolve(0);
    });

    await runChecks(baseInputs, "enterprise");

    const checkCalls = (exec.mock.calls as [string, string[]][]).filter((call) => call[1]?.[0] === "check");

    expect(checkCalls).toHaveLength(3);

    expect(checkCalls[0][1]).toContain("-dryrun");
    expect(checkCalls[0][1]).not.toContain("-code");
    expect(checkCalls[0][1]).not.toContain("-drift");

    expect(checkCalls[1][1]).toContain("-code");
    expect(checkCalls[1][1]).not.toContain("-dryrun");
    expect(checkCalls[1][1]).not.toContain("-drift");

    expect(checkCalls[2][1]).toContain("-drift");
    expect(checkCalls[2][1]).not.toContain("-dryrun");
    expect(checkCalls[2][1]).not.toContain("-code");
  });

  it("should make four exec calls when build url is provided", async () => {
    exec.mockImplementation((_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stdout?.(Buffer.from("{}"));
      return Promise.resolve(0);
    });

    await runChecks({ buildUrl: "jdbc:sqlite:build.db" }, "enterprise");

    const checkCalls = (exec.mock.calls as [string, string[]][]).filter((call) => call[1]?.[0] === "check");

    expect(checkCalls).toHaveLength(4);
    expect(checkCalls[3][1]).toContain("-changes");
  });

  it("should only include build args in the changes invocation", async () => {
    exec.mockImplementation((_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stdout?.(Buffer.from("{}"));
      return Promise.resolve(0);
    });

    await runChecks({ buildUrl: "jdbc:sqlite:build.db" }, "enterprise");

    const checkCalls = (exec.mock.calls as [string, string[]][]).filter((call) => call[1]?.[0] === "check");

    for (let i = 0; i < 3; i++) {
      expect(checkCalls[i][1]).not.toContain(expect.stringContaining("default_build"));
    }

    expect(checkCalls[3][1]).toContain("-environments.default_build.url=jdbc:sqlite:build.db");
  });

  it("should set exit-code from first failed check before throwing", async () => {
    exec.mockImplementation((_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stdout?.(
        Buffer.from(JSON.stringify({ error: { errorCode: "FAULT", message: "Check failed" } })),
      );
      return Promise.resolve(1);
    });

    await expect(runChecks(baseInputs, "enterprise")).rejects.toThrow();
    expect(setOutput).toHaveBeenCalledWith("exit-code", "1");
  });

  it("should throw Flyway checks failed on failure", async () => {
    exec.mockImplementation((_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stdout?.(
        Buffer.from(JSON.stringify({ error: { errorCode: "FAULT", message: "Check failed" } })),
      );
      return Promise.resolve(1);
    });

    await expect(runChecks(baseInputs, "enterprise")).rejects.toThrowError("Flyway checks failed");
  });

  it("should run all checks even if an earlier one fails", async () => {
    let callCount = 0;
    exec.mockImplementation((_cmd: string, _args?: string[], options?: ExecOptions) => {
      callCount++;
      options?.listeners?.stdout?.(Buffer.from("{}"));
      return Promise.resolve(callCount === 1 ? 1 : 0);
    });

    await expect(runChecks(baseInputs, "enterprise")).rejects.toThrow();

    const checkCalls = (exec.mock.calls as [string, string[]][]).filter((call) => call[1]?.[0] === "check");

    expect(checkCalls).toHaveLength(3);
  });

  it("should log friendly message on provisioner error when changes check fails and build-ok-to-erase is not set", async () => {
    exec.mockImplementation((_cmd: string, args?: string[], options?: ExecOptions) => {
      if (args?.includes("-changes")) {
        options?.listeners?.stdout?.(
          Buffer.from(JSON.stringify({ error: { errorCode: "CHECK_BUILD_NO_PROVISIONER" } })),
        );
        return Promise.resolve(1);
      }
      options?.listeners?.stdout?.(Buffer.from("{}"));
      return Promise.resolve(0);
    });

    await expect(runChecks({ buildUrl: "jdbc:sqlite:build.db" }, "enterprise")).rejects.toThrow();
    expect(error).toHaveBeenCalledWith(expect.stringContaining("build-ok-to-erase"));
  });

  it("should not log friendly message on provisioner error when build-ok-to-erase is set", async () => {
    exec.mockImplementation((_cmd: string, args?: string[], options?: ExecOptions) => {
      if (args?.includes("-changes")) {
        options?.listeners?.stdout?.(
          Buffer.from(
            JSON.stringify({
              error: { errorCode: "FAULT", message: "You need to configure a provisioner for the build environment" },
            }),
          ),
        );
        return Promise.resolve(1);
      }
      options?.listeners?.stdout?.(Buffer.from("{}"));
      return Promise.resolve(0);
    });

    await expect(runChecks({ buildUrl: "jdbc:sqlite:build.db", buildOkToErase: true }, "enterprise")).rejects.toThrow();
    expect(error).not.toHaveBeenCalledWith(expect.stringContaining("build-ok-to-erase"));
  });
});
