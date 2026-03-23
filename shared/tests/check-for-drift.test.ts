import { mockExec } from "../src/test-utils.js";

const setOutput = vi.fn();
const info = vi.fn();
const exec = vi.fn();

vi.doMock("@actions/core", () => ({
  info,
  error: vi.fn(),
  startGroup: vi.fn(),
  endGroup: vi.fn(),
  setOutput,
}));

vi.doMock("@actions/exec", () => ({
  exec,
}));

const { checkForDrift } = await import("../src/check-for-drift.js");

const driftArgs = (url: string) => ["check", "-drift", "-check.failOnDrift=true", `-url=${url}`];

describe("checkForDrift", () => {
  it("should return drift-detected false when exit code is 0", async () => {
    exec.mockResolvedValue(0);

    const { exitCode, result } = await checkForDrift(driftArgs("jdbc:sqlite:test.db"));

    expect(exitCode).toBe(0);
    expect(result).toEqual({ driftDetected: false, comparisonSupported: true });
    expect(setOutput).toHaveBeenCalledWith("exit-code", "0");
    expect(setOutput).toHaveBeenCalledWith("drift-detected", "false");
  });

  it("should detect drift from success-path output when individualResults contain drift items", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: {
          htmlReport: "report.html",
          individualResults: [
            {
              operation: "drift",
              onlyInSource: ["table_a"],
              onlyInTarget: [],
              differences: [],
              driftResolutionFolder: "/resolution/folder",
            },
          ],
        },
      }),
    );

    const { exitCode, result } = await checkForDrift(driftArgs("jdbc:sqlite:test.db"));

    expect(exitCode).toBe(0);
    expect(result).toEqual({
      driftDetected: true,
      comparisonSupported: true,
      reportPath: "report.html",
      driftResolutionFolder: "/resolution/folder",
    });
    expect(setOutput).toHaveBeenCalledWith("drift-detected", "true");
  });

  it("should set drift-detected to false when individualResults have empty drift arrays", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: {
          htmlReport: "report.html",
          individualResults: [{ operation: "drift", onlyInSource: [], onlyInTarget: [], differences: [] }],
        },
      }),
    );

    const { exitCode, result } = await checkForDrift(driftArgs("jdbc:sqlite:test.db"));

    expect(exitCode).toBe(0);
    expect(result).toEqual({ driftDetected: false, comparisonSupported: true, reportPath: "report.html" });
    expect(setOutput).toHaveBeenCalledWith("drift-detected", "false");
  });

  it("should return exitCode and drift-detected true when error code is CHECK_DRIFT_DETECTED", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: {
          error: {
            errorCode: "CHECK_DRIFT_DETECTED",
            message: "Drift detected",
            htmlReport: "drift-report.html",
            driftResolutionFolderPath: "/absolute/path/to/resolution",
          },
        },
        exitCode: 1,
      }),
    );

    const { exitCode, result } = await checkForDrift(driftArgs("jdbc:sqlite:test.db"));

    expect(exitCode).toBe(1);
    expect(result).toEqual({
      driftDetected: true,
      comparisonSupported: true,
      reportPath: "drift-report.html",
      driftResolutionFolder: "/absolute/path/to/resolution",
    });
    expect(setOutput).toHaveBeenCalledWith("exit-code", "1");
    expect(setOutput).toHaveBeenCalledWith("drift-detected", "true");
    expect(setOutput).toHaveBeenCalledWith("report-path", "drift-report.html");
    expect(setOutput).toHaveBeenCalledWith("drift-resolution-folder", "/absolute/path/to/resolution");
  });

  it("should return exitCode when non-drift error occurs", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: { error: { errorCode: "FAULT", message: "Something else failed" } },
        exitCode: 1,
      }),
    );

    const { exitCode, result } = await checkForDrift(driftArgs("jdbc:sqlite:test.db"));

    expect(exitCode).toBe(1);
    expect(result).toEqual({ driftDetected: false, comparisonSupported: true });
    expect(setOutput).toHaveBeenCalledWith("exit-code", "1");
    expect(setOutput).not.toHaveBeenCalledWith("drift-detected", expect.anything());
  });

  it("should return exitCode 0 and comparison not supported when database does not support comparison", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: {
          error: {
            errorCode: "COMPARISON_DATABASE_NOT_SUPPORTED",
            message: "No comparison capability found that supports both types",
          },
        },
        exitCode: 1,
      }),
    );

    const { exitCode, result } = await checkForDrift(driftArgs("jdbc:h2:mem:test"));

    expect(exitCode).toBe(0);
    expect(result).toEqual({ driftDetected: false, comparisonSupported: false });
    expect(setOutput).not.toHaveBeenCalledWith("drift-detected", expect.anything());
    expect(setOutput).toHaveBeenCalledWith("exit-code", "0");
    expect(info).toHaveBeenCalledWith(
      "Drift check could not be run because advanced comparison features are not supported for this database type.",
    );
  });
});
