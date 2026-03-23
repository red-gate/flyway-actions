import { mockExec } from "../src/test-utils.js";

const info = vi.fn();
const exec = vi.fn();

vi.doMock("@actions/core", () => ({
  info,
  error: vi.fn(),
  startGroup: vi.fn(),
  endGroup: vi.fn(),
}));

vi.doMock("@actions/exec", () => ({
  exec,
}));

const { checkForDrift } = await import("../src/check-for-drift.js");

const driftArgs = (url: string) => ["check", "-drift", "-check.failOnDrift=true", `-url=${url}`];

describe("checkForDrift", () => {
  it("should return no drift when exit code is 0", async () => {
    exec.mockResolvedValue(0);

    const { exitCode, result } = await checkForDrift(driftArgs("jdbc:sqlite:test.db"));

    expect(exitCode).toBe(0);
    expect(result).toEqual({ driftDetected: false, comparisonSupported: true });
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
  });

  it("should return no drift when individualResults have empty drift arrays", async () => {
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
  });

  it("should return drift detected when error code is CHECK_DRIFT_DETECTED", async () => {
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
  });

  it("should return no drift when non-drift error occurs", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: { error: { errorCode: "FAULT", message: "Something else failed" } },
        exitCode: 1,
      }),
    );

    const { exitCode, result } = await checkForDrift(driftArgs("jdbc:sqlite:test.db"));

    expect(exitCode).toBe(1);
    expect(result).toEqual({ driftDetected: false, comparisonSupported: true });
  });

  it("should return comparison not supported when database does not support comparison", async () => {
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
    expect(info).toHaveBeenCalledWith(
      "Drift check could not be run because advanced comparison features are not supported for this database type.",
    );
  });
});
