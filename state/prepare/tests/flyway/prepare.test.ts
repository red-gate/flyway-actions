import { mockExec } from "@flyway-actions/shared/test-utils";

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

const { prepare } = await import("../../src/flyway/prepare.js");

describe("prepare", () => {
  it("should set outputs on success", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: {
          scriptFilename: "deployments/D__deployment.sql",
          undoFilename: "deployments/DU__undo.sql",
        },
      }),
    );

    await prepare({ targetUrl: "jdbc:sqlite:test.db" });

    expect(setOutput).toHaveBeenCalledWith("exit-code", "0");
    expect(setOutput).toHaveBeenCalledWith("script-path", "deployments/D__deployment.sql");
    expect(setOutput).toHaveBeenCalledWith("undo-script-path", "deployments/DU__undo.sql");
  });

  it("should not set script paths when filenames are absent", async () => {
    exec.mockImplementation(mockExec({ stdout: {} }));

    await prepare({ targetUrl: "jdbc:sqlite:test.db" });

    expect(setOutput).toHaveBeenCalledWith("exit-code", "0");
    expect(setOutput).not.toHaveBeenCalledWith("script-path", expect.anything());
    expect(setOutput).not.toHaveBeenCalledWith("undo-script-path", expect.anything());
  });

  it("should throw and set exit-code when prepare fails", async () => {
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

    await expect(prepare({ targetUrl: "jdbc:sqlite:test.db" })).rejects.toThrow(
      "Flyway prepare failed with exit code 1",
    );

    expect(setOutput).toHaveBeenCalledWith("exit-code", "1");
  });

  it("should call flyway with prepare command args", async () => {
    exec.mockImplementation(mockExec({ stdout: { scriptFilename: "deployments/D__deployment.sql" } }));

    await prepare({ targetUrl: "jdbc:sqlite:test.db" });

    expect(exec).toHaveBeenCalledWith(
      "flyway",
      expect.arrayContaining(["prepare", "-source=schemaModel"]),
      expect.any(Object),
    );
  });

  it("should include generate-undo args when enabled", async () => {
    exec.mockImplementation(mockExec({ stdout: { scriptFilename: "deployments/D__deployment.sql" } }));

    await prepare({ targetUrl: "jdbc:sqlite:test.db", generateUndo: true });

    expect(exec).toHaveBeenCalledWith("flyway", expect.arrayContaining(["-types=deploy,undo"]), expect.any(Object));
  });
});
