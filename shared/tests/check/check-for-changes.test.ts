import { mockExec } from "../../src/test-utils.js";

const info = vi.fn();
const coreError = vi.fn();
const exec = vi.fn();

vi.doMock("@actions/core", () => ({
  info,
  error: coreError,
  startGroup: vi.fn(),
  endGroup: vi.fn(),
}));

vi.doMock("@actions/exec", () => ({
  exec,
}));

const { checkForChanges } = await import("../../src/check/check-for-changes.js");

describe("checkForChanges", () => {
  it("should return zero changes when exit code is 0 with no changes", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: { individualResults: [{ operation: "changes" }] },
      }),
    );

    const result = await checkForChanges(["check", "-changes", "-url=jdbc:sqlite:test.db"]);

    expect(result).toEqual({ exitCode: 0, result: { changedObjectCount: 0 } });
  });

  it("should count changed objects from results", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: {
          individualResults: [
            {
              operation: "changes",
              differences: [{ name: "Table_1" }, { name: "Table_2" }],
              onlyInSource: [{ name: "View_1" }],
              onlyInTarget: [{ name: "Proc_1" }],
            },
          ],
        },
      }),
    );

    const { result } = await checkForChanges(["check", "-changes", "-url=jdbc:sqlite:test.db"]);

    expect(result.changedObjectCount).toBe(4);
  });

  it("should return report path from successful output", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: {
          htmlReport: "/tmp/changes-report.html",
          individualResults: [{ operation: "changes" }],
        },
      }),
    );

    const { result } = await checkForChanges(["check", "-changes", "-url=jdbc:sqlite:test.db"]);

    expect(result.reportPath).toBe("/tmp/changes-report.html");
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

    const result = await checkForChanges(["check", "-changes", "-url=jdbc:h2:mem:test"]);

    expect(result).toEqual({ exitCode: 0 });
    expect(info).toHaveBeenCalledWith(
      "Deployment changes report could not be generated because advanced comparison features are not supported for this database type.",
    );
  });

  it("should not return result on non-comparison error", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: { error: { errorCode: "FAULT", message: "Something went wrong" } },
        exitCode: 1,
      }),
    );

    const result = await checkForChanges(["check", "-changes", "-url=jdbc:sqlite:test.db"]);

    expect(result).toEqual({ exitCode: 1 });
  });

  it("should show build database warning for CHECK_BUILD_NO_PROVISIONER when warnAboutBuildDatabase is true", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: { error: { errorCode: "CHECK_BUILD_NO_PROVISIONER", message: "No provisioner" } },
        exitCode: 1,
      }),
    );

    await checkForChanges(["check", "-changes", "-url=jdbc:sqlite:test.db"], undefined, true);

    expect(coreError).toHaveBeenCalledWith(expect.stringContaining("build-ok-to-erase"));
  });

  it("should show generic error for CHECK_BUILD_NO_PROVISIONER when warnAboutBuildDatabase is false", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: { error: { errorCode: "CHECK_BUILD_NO_PROVISIONER", message: "No provisioner" } },
        exitCode: 1,
      }),
    );

    await checkForChanges(["check", "-changes", "-url=jdbc:sqlite:test.db"], undefined, false);

    expect(coreError).toHaveBeenCalledWith("No provisioner");
    expect(coreError).not.toHaveBeenCalledWith(expect.stringContaining("build-ok-to-erase"));
  });
});
