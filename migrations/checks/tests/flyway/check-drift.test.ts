import type { FlywayMigrationsChecksInputs } from "../../src/types.js";
import type { ExecOptions } from "@actions/exec";

const info = vi.fn();
const setOutput = vi.fn();
const exec = vi.fn();

vi.doMock("@actions/core", () => ({
  info,
  error: vi.fn(),
  setOutput,
  startGroup: vi.fn(),
  endGroup: vi.fn(),
}));

vi.doMock("@actions/exec", () => ({
  exec,
}));

const { getDriftArgs, runCheckDrift } = await import("../../src/flyway/check-drift.js");

const baseInputs: FlywayMigrationsChecksInputs = {};

describe("getDriftArgs", () => {
  it("should return args with -drift for enterprise edition", () => {
    const args = getDriftArgs(baseInputs, "enterprise");

    expect(args).toBeDefined();
    expect(args![0]).toBe("check");
    expect(args).toContain("-outputType=json");
    expect(args).toContain("-outputLogsInJson=true");
    expect(args).toContain("-drift");
  });

  it("should include -check.failOnDrift=true when failOnDrift is true", () => {
    const args = getDriftArgs({ failOnDrift: true }, "enterprise");

    expect(args).toContain("-check.failOnDrift=true");
  });

  it("should not include -check.failOnDrift=true when failOnDrift is false", () => {
    const args = getDriftArgs({ failOnDrift: false }, "enterprise");

    expect(args).not.toContain("-check.failOnDrift=true");
  });

  it("should include target args but not target migration version or cherry pick", () => {
    const args = getDriftArgs(
      { targetUrl: "jdbc:postgresql://localhost/db", targetMigrationVersion: "5.0", cherryPick: "3.0" },
      "enterprise",
    );

    expect(args).toContain("-url=jdbc:postgresql://localhost/db");
    expect(args).not.toContain("-target=5.0");
    expect(args).not.toContain("-cherryPick=3.0");
  });

  it("should not include build environment args", () => {
    const args = getDriftArgs({ buildUrl: "jdbc:sqlite:build.db" }, "enterprise");

    expect(args).not.toContain(expect.stringContaining("default_build"));
  });

  it("should return undefined for community edition", () => {
    expect(getDriftArgs(baseInputs, "community")).toBeUndefined();
    expect(info).toHaveBeenCalledWith("Skipping drift check: not available in Community edition");
  });

  it("should return undefined for teams edition", () => {
    expect(getDriftArgs(baseInputs, "teams")).toBeUndefined();
    expect(info).toHaveBeenCalledWith("Skipping drift check: not available in Teams edition");
  });

  it("should return undefined when skipDriftCheck is true", () => {
    expect(getDriftArgs({ skipDriftCheck: true }, "enterprise")).toBeUndefined();
    expect(info).toHaveBeenCalledWith(expect.stringContaining("Skipping drift check"));
  });

  it("should return undefined when skipDriftCheck is true even if failOnDrift is true", () => {
    expect(getDriftArgs({ skipDriftCheck: true, failOnDrift: true }, "enterprise")).toBeUndefined();
  });
});

describe("runDriftCheck", () => {
  it("should return undefined when edition is not enterprise", async () => {
    const result = await runCheckDrift(baseInputs, "community");

    expect(result).toBeUndefined();
  });

  it("should set drift-detected to false when exit code is 0 and no drift in output", async () => {
    exec.mockImplementation((_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stdout?.(
        Buffer.from(JSON.stringify({ individualResults: [{ operation: "drift" }] })),
      );
      return Promise.resolve(0);
    });

    await runCheckDrift(baseInputs, "enterprise");

    expect(setOutput).toHaveBeenCalledWith("drift-detected", "false");
  });

  it("should set drift-detected to true when exit code is 0 and drift detected in output", async () => {
    exec.mockImplementation((_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stdout?.(
        Buffer.from(
          JSON.stringify({
            individualResults: [{ operation: "drift", differences: [{ name: "Table_1" }] }],
          }),
        ),
      );
      return Promise.resolve(0);
    });

    await runCheckDrift(baseInputs, "enterprise");

    expect(setOutput).toHaveBeenCalledWith("drift-detected", "true");
  });

  it("should set drift-detected to true when exit code is non-zero and error contains Drift detected", async () => {
    exec.mockImplementation((_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stdout?.(
        Buffer.from(JSON.stringify({ error: { errorCode: "FAULT", message: "Drift detected" } })),
      );
      return Promise.resolve(1);
    });

    await runCheckDrift(baseInputs, "enterprise");

    expect(setOutput).toHaveBeenCalledWith("drift-detected", "true");
  });

  it("should set drift-detected to false when exit code is non-zero and error does not contain Drift detected", async () => {
    exec.mockImplementation((_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stdout?.(
        Buffer.from(JSON.stringify({ error: { errorCode: "FAULT", message: "Something else failed" } })),
      );
      return Promise.resolve(1);
    });

    await runCheckDrift(baseInputs, "enterprise");

    expect(setOutput).toHaveBeenCalledWith("drift-detected", "false");
  });
});
