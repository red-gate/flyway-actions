import { mockExec } from "../src/test-utils.js";

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

const { checkForCodeReview } = await import("../src/check-for-code-review.js");

describe("checkForCodeReview", () => {
  it("should set violation count to 0 when no violations found", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: {
          individualResults: [{ operation: "code", results: [{ violations: [] }] }],
        },
      }),
    );

    const result = await checkForCodeReview(["code"]);

    expect(result).toEqual(expect.objectContaining({ exitCode: 0, violationCount: 0, violationCodes: [] }));
    expect(setOutput).toHaveBeenCalledWith("code-violation-count", "0");
    expect(setOutput).toHaveBeenCalledWith("code-violation-codes", "");
  });

  it("should count violations and extract unique codes on success", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: {
          htmlReport: "report.html",
          individualResults: [
            {
              operation: "code",
              results: [{ violations: [{ code: "AM04" }, { code: "RG06" }] }, { violations: [{ code: "AM04" }] }],
            },
          ],
        },
      }),
    );

    const result = await checkForCodeReview(["code"]);

    expect(result).toEqual({
      exitCode: 0,
      reportPath: "report.html",
      violationCount: 3,
      violationCodes: ["AM04", "RG06"],
    });
    expect(setOutput).toHaveBeenCalledWith("code-violation-count", "3");
    expect(setOutput).toHaveBeenCalledWith("code-violation-codes", "AM04,RG06");
  });

  it("should parse violations from error output on failure", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: {
          error: {
            errorCode: "CHECK_CODE_REVIEW_VIOLATION",
            message: "Code Analysis Violation(s) detected",
            results: [{ violations: [{ code: "AM04" }] }],
            htmlReport: "/tmp/report.html",
          },
        },
        exitCode: 1,
      }),
    );

    const result = await checkForCodeReview(["code"]);

    expect(result).toEqual({
      exitCode: 1,
      reportPath: "/tmp/report.html",
      violationCount: 1,
      violationCodes: ["AM04"],
    });
    expect(error).toHaveBeenCalledWith("Code Analysis Violation(s) detected");
    expect(setOutput).toHaveBeenCalledWith("code-violation-count", "1");
    expect(setOutput).toHaveBeenCalledWith("code-violation-codes", "AM04");
  });

  it("should handle error output without results", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: { error: { errorCode: "FAULT", message: "Something failed" } },
        exitCode: 1,
      }),
    );

    const result = await checkForCodeReview(["code"]);

    expect(result).toEqual(expect.objectContaining({ exitCode: 1, violationCount: 0, violationCodes: [] }));
    expect(error).toHaveBeenCalledWith("Something failed");
  });

  it("should ignore non-code individual results", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: {
          individualResults: [
            { operation: "drift" },
            { operation: "code", results: [{ violations: [{ code: "AM04" }] }] },
          ],
        },
      }),
    );

    const result = await checkForCodeReview(["code"]);

    expect(result).toEqual(expect.objectContaining({ violationCount: 1, violationCodes: ["AM04"] }));
  });
});
