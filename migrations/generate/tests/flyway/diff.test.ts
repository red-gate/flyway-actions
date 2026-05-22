import { mockExec } from "@flyway-actions/shared/test-utils";

const setOutput = vi.fn();
const info = vi.fn();
const error = vi.fn();
const startGroup = vi.fn();
const endGroup = vi.fn();
const exec = vi.fn();

vi.doMock("@actions/core", () => ({
  info,
  error,
  startGroup,
  endGroup,
  setOutput,
}));

vi.doMock("@actions/exec", () => ({
  exec,
}));

const { diff } = await import("../../src/flyway/diff.js");

describe("diff", () => {
  it("should call flyway with diff command", async () => {
    exec.mockImplementation(mockExec({ stdout: {} }));

    await diff({ source: "schemaModel" });

    expect(exec).toHaveBeenCalledWith(
      "flyway",
      expect.arrayContaining(["diff", "-source=schemaModel"]),
      expect.any(Object),
    );
  });

  it("should throw and set exit-code when diff fails", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: {
          error: { errorCode: "FAULT", message: "Diff failed" },
        },
        exitCode: 1,
      }),
    );

    await expect(diff({ source: "schemaModel" })).rejects.toThrow("Flyway diff failed with exit code 1");

    expect(setOutput).toHaveBeenCalledWith("exit-code", "1");
    expect(error).toHaveBeenCalledWith("Diff failed");
  });

  it("should not set exit-code on success", async () => {
    exec.mockImplementation(mockExec({ stdout: {} }));

    await diff({ source: "schemaModel" });

    expect(setOutput).not.toHaveBeenCalled();
  });

  it("should return the artifact path from the diff output", async () => {
    exec.mockImplementation(mockExec({ stdout: { artifactFilename: "/tmp/diff-artifact" } }));

    const result = await diff({ source: "schemaModel" });

    expect(result.artifactPath).toBe("/tmp/diff-artifact");
  });

  it("should return an undefined artifact path when the field is missing", async () => {
    exec.mockImplementation(mockExec({ stdout: {} }));

    const result = await diff({ source: "schemaModel" });

    expect(result.artifactPath).toBeUndefined();
  });
});
