import { parseCheckOutput, parseCodeErrorOutput } from "../src/outputs.js";

describe("parseCheckOutput", () => {
  it("should parse valid JSON with individualResults", () => {
    const stdout = JSON.stringify({ individualResults: [{ operation: "drift", differences: [] }] });
    const result = parseCheckOutput(stdout);

    expect(result?.individualResults).toHaveLength(1);
    expect(result?.individualResults?.[0].operation).toBe("drift");
  });

  it("should return undefined for invalid JSON", () => {
    expect(parseCheckOutput("not json")).toBeUndefined();
  });

  it("should handle empty object", () => {
    const result = parseCheckOutput("{}");

    expect(result?.individualResults).toBeUndefined();
  });

  it("should parse htmlReport field", () => {
    const stdout = JSON.stringify({
      htmlReport: "custom-report.html",
      individualResults: [{ operation: "drift" }],
    });
    const result = parseCheckOutput(stdout);

    expect(result?.htmlReport).toBe("custom-report.html");
  });
});

describe("parseCodeErrorOutput", () => {
  it("should parse error with results and htmlReport", () => {
    const stdout = JSON.stringify({
      error: {
        errorCode: "CHECK_CODE_REVIEW_VIOLATION",
        message: "Code Analysis Violation(s) detected",
        results: [{ violations: [{ code: "RG0001" }] }],
        htmlReport: "/tmp/report.html",
      },
    });

    const output = parseCodeErrorOutput(stdout);

    expect(output?.error?.errorCode).toBe("CHECK_CODE_REVIEW_VIOLATION");
    expect(output?.error?.results).toHaveLength(1);
    expect(output?.error?.results?.[0].violations?.[0].code).toBe("RG0001");
    expect(output?.error?.htmlReport).toBe("/tmp/report.html");
  });

  it("should return undefined for invalid JSON", () => {
    expect(parseCodeErrorOutput("not json")).toBeUndefined();
  });

  it("should handle error without results", () => {
    const stdout = JSON.stringify({ error: { errorCode: "FAULT", message: "Something failed" } });

    const output = parseCodeErrorOutput(stdout);

    expect(output?.error?.errorCode).toBe("FAULT");
    expect(output?.error?.results).toBeUndefined();
  });
});
