import * as path from "path";

const getInput = vi.fn();

vi.doMock("@actions/core", () => ({
  getInput,
}));

const { getInputs } = await import("../src/inputs.js");

describe("getInputs", () => {
  beforeEach(() => {
    getInput.mockReturnValue("");
  });

  it("should return reports-folder when provided", () => {
    getInput.mockImplementation((name: string) => (name === "reports-folder" ? "./reports" : ""));

    const inputs = getInputs();

    expect(inputs.reportsFolder).toBe("./reports");
  });

  it("should resolve working-directory to an absolute path", () => {
    getInput.mockImplementation((name: string) => {
      const values: Record<string, string> = {
        "reports-folder": "./reports",
        "working-directory": "./project",
      };
      return values[name] || "";
    });

    const inputs = getInputs();

    expect(inputs.workingDirectory).toBe(path.resolve("./project"));
  });

  it("should leave working-directory undefined when not provided", () => {
    getInput.mockImplementation((name: string) => (name === "reports-folder" ? "./reports" : ""));

    const inputs = getInputs();

    expect(inputs.workingDirectory).toBeUndefined();
  });

  it("should return extra-args when provided", () => {
    getInput.mockImplementation((name: string) => {
      const values: Record<string, string> = {
        "reports-folder": "./reports",
        "extra-args": "-X -someFlag=value",
      };
      return values[name] || "";
    });

    const inputs = getInputs();

    expect(inputs.extraArgs).toBe("-X -someFlag=value");
  });

  it("should resolve report-path to an absolute path under the process cwd by default", () => {
    getInput.mockImplementation((name: string) => (name === "reports-folder" ? "./reports" : ""));

    const inputs = getInputs();

    expect(inputs.reportPath).toBe(path.resolve(process.cwd(), "aggregate-report.html"));
  });

  it("should resolve report-path under working-directory when provided", () => {
    getInput.mockImplementation((name: string) => {
      const values: Record<string, string> = {
        "reports-folder": "./reports",
        "working-directory": "./project",
      };
      return values[name] || "";
    });

    const inputs = getInputs();

    expect(inputs.reportPath).toBe(path.resolve("./project", "aggregate-report.html"));
  });
});
