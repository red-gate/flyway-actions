import * as path from "node:path";
import { resolvePath } from "../src/resolve-path.js";

describe("resolvePath", () => {
  it("should return undefined when path is undefined", () => {
    expect(resolvePath(undefined, "/app")).toBeUndefined();
  });

  it("should return absolute path as-is", () => {
    expect(resolvePath("/absolute/report.html", "/app")).toBe("/absolute/report.html");
  });

  it("should join relative path with working directory", () => {
    expect(resolvePath("report.html", "/app")).toBe(path.join("/app", "report.html"));
  });

  it("should return relative path as-is when no working directory", () => {
    expect(resolvePath("report.html", undefined)).toBe("report.html");
  });
});
