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

const { generate, extractScripts } = await import("../../src/flyway/generate.js");

describe("generate", () => {
  it("should call flyway with generate command", async () => {
    exec.mockImplementation(mockExec({ stdout: { scripts: [] } }));

    await generate({ migrationDescription: "add" });

    expect(exec).toHaveBeenCalledWith(
      "flyway",
      expect.arrayContaining(["generate", "-description=add"]),
      expect.any(Object),
    );
  });

  it("should set outputs from scripts array", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: {
          scripts: [
            {
              type: "versioned",
              location: "migrations/V001__add.sql",
              differences: [
                {
                  from: { name: "Table1" },
                  to: null,
                  differenceType: "Add",
                  objectType: "Table",
                },
              ],
              warnings: [{ type: "DEP_WARNING", message: "deprecated" }],
            },
            {
              type: "undo",
              location: "migrations/U001__add.sql",
              differences: [],
              warnings: [],
            },
          ],
        },
      }),
    );

    const result = await generate({ source: "schemaModel" });

    expect(result.scripts).toHaveLength(2);
    expect(result.scripts[0].location).toBe("migrations/V001__add.sql");
    expect(result.scripts[0].changes).toEqual([{ name: "Table1", differenceType: "Add", objectType: "Table" }]);
    expect(result.scripts[0].warnings).toEqual([{ type: "DEP_WARNING", message: "deprecated" }]);

    expect(setOutput).toHaveBeenCalledWith("exit-code", "0");
    expect(setOutput).toHaveBeenCalledWith(
      "script-paths",
      JSON.stringify(["migrations/V001__add.sql", "migrations/U001__add.sql"]),
    );
  });

  it("should set empty outputs when no scripts generated", async () => {
    exec.mockImplementation(mockExec({ stdout: {} }));

    const result = await generate({ source: "schemaModel" });

    expect(result.scripts).toEqual([]);
    expect(setOutput).toHaveBeenCalledWith("script-paths", "[]");
  });

  it("should throw and set exit-code when generate fails", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: { error: { errorCode: "FAULT", message: "Generate failed" } },
        exitCode: 1,
      }),
    );

    await expect(generate({ source: "schemaModel" })).rejects.toThrow("Flyway generate failed with exit code 1");

    expect(setOutput).toHaveBeenCalledWith("exit-code", "1");
    expect(error).toHaveBeenCalledWith("Generate failed");
  });

  it("should pass types and description args", async () => {
    exec.mockImplementation(mockExec({ stdout: { scripts: [] } }));

    await generate({ migrationTypes: "versioned,undo", migrationDescription: "add_orders" });

    expect(exec).toHaveBeenCalledWith(
      "flyway",
      expect.arrayContaining(["-types=versioned,undo", "-description=add_orders"]),
      expect.any(Object),
    );
  });
});

describe("extractScripts", () => {
  it("should return empty array when output is undefined", () => {
    expect(extractScripts(undefined)).toEqual([]);
  });

  it("should return empty array when scripts is missing", () => {
    expect(extractScripts({})).toEqual([]);
  });

  it("should drop scripts that lack a location", () => {
    const scripts = extractScripts({
      scripts: [{ type: "versioned", location: "a.sql" }, { type: "versioned" }],
    });

    expect(scripts).toHaveLength(1);
    expect(scripts[0].location).toBe("a.sql");
  });

  it("should prefer to.name over from.name for the change name", () => {
    const scripts = extractScripts({
      scripts: [
        {
          location: "a.sql",
          differences: [
            {
              from: { name: "OldName" },
              to: { name: "NewName" },
              differenceType: "Modify",
              objectType: "Table",
            },
          ],
        },
      ],
    });

    expect(scripts[0].changes[0].name).toBe("NewName");
  });

  it("should fall back to from.name when to is null", () => {
    const scripts = extractScripts({
      scripts: [
        {
          location: "a.sql",
          differences: [
            {
              from: { name: "DroppedTable" },
              to: null,
              differenceType: "Add",
              objectType: "Table",
            },
          ],
        },
      ],
    });

    expect(scripts[0].changes[0].name).toBe("DroppedTable");
  });

  it("should leave change fields empty when difference fields are missing", () => {
    const scripts = extractScripts({
      scripts: [{ location: "a.sql", differences: [{}] }],
    });

    expect(scripts[0].changes[0]).toEqual({ name: "", differenceType: "", objectType: "" });
  });

  it("should normalize warning fields", () => {
    const scripts = extractScripts({
      scripts: [{ location: "a.sql", warnings: [{ type: "X" }, { message: "Y" }, {}] }],
    });

    expect(scripts[0].warnings).toEqual([
      { type: "X", message: "" },
      { type: "", message: "Y" },
      { type: "", message: "" },
    ]);
  });
});
