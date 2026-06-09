import type { FlywayAggregateReportsInputs } from "../../src/types.js";
import { mockExec } from "@flyway-actions/shared/test-utils";

const setOutput = vi.fn();
const error = vi.fn();
const exec = vi.fn();

vi.doMock("@actions/core", () => ({
  info: vi.fn(),
  error,
  startGroup: vi.fn(),
  endGroup: vi.fn(),
  setOutput,
}));

vi.doMock("@actions/exec", () => ({
  exec,
}));

const { aggregate, getAggregateArgs } = await import("../../src/flyway/aggregate.js");

const baseInputs: FlywayAggregateReportsInputs = {
  reportsFolder: "./reports",
  reportPath: "/workspace/aggregate-report.html",
};

describe("aggregate", () => {
  it("should set exit-code and report-path outputs on success", async () => {
    exec.mockImplementation(mockExec({ stdout: {} }));

    await aggregate(baseInputs);

    expect(setOutput).toHaveBeenCalledWith("exit-code", "0");
    expect(setOutput).toHaveBeenCalledWith("report-path", "/workspace/aggregate-report.html");
  });

  it("should throw when aggregate fails", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: {
          error: {
            errorCode: "FAULT",
            message: "Something went wrong",
          },
        },
        exitCode: 1,
      }),
    );

    await expect(aggregate(baseInputs)).rejects.toThrow("Flyway aggregate failed with exit code 1");
    expect(error).toHaveBeenCalledWith("Something went wrong");
  });

  it("should still set outputs when aggregate fails", async () => {
    exec.mockImplementation(mockExec({ stdout: {}, exitCode: 1 }));

    await expect(aggregate(baseInputs)).rejects.toThrow();

    expect(setOutput).toHaveBeenCalledWith("exit-code", "1");
    expect(setOutput).toHaveBeenCalledWith("report-path", "/workspace/aggregate-report.html");
  });
});

describe("getAggregateArgs", () => {
  it("should build args starting with aggregate command", () => {
    const args = getAggregateArgs(baseInputs);

    expect(args[0]).toBe("aggregate");
  });

  it("should include reports-folder as -aggregate.reportsFolder", () => {
    const args = getAggregateArgs(baseInputs);

    expect(args).toContain("-aggregate.reportsFolder=./reports");
  });

  it("should include report-path as -reportFilename", () => {
    const args = getAggregateArgs(baseInputs);

    expect(args).toContain("-reportFilename=/workspace/aggregate-report.html");
  });

  it("should include -workingDirectory when provided", () => {
    const args = getAggregateArgs({ ...baseInputs, workingDirectory: "/app/db" });

    expect(args).toContain("-workingDirectory=/app/db");
  });

  it("should not include -workingDirectory when omitted", () => {
    const args = getAggregateArgs(baseInputs);

    expect(args.some((a) => a.includes("workingDirectory"))).toBe(false);
  });

  it("should parse and append extra-args", () => {
    const args = getAggregateArgs({ ...baseInputs, extraArgs: "-X -someFlag=value" });

    expect(args).toContain("-X");
    expect(args).toContain("-someFlag=value");
  });
});
