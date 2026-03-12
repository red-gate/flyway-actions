import { parseCheckOutput } from "../src/outputs.js";

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
