import { checkMinimumFlywayVersion } from "../src/version-check.js";

describe("checkMinimumFlywayVersion", () => {
  it("should return success when version equals minimum", () => {
    expect(checkMinimumFlywayVersion("12.0.0")).toEqual({ success: true });
  });

  it("should return success when patch version is greater", () => {
    expect(checkMinimumFlywayVersion("12.0.1")).toEqual({ success: true });
  });

  it("should return success when minor version is greater", () => {
    expect(checkMinimumFlywayVersion("12.1.0")).toEqual({ success: true });
  });

  it("should return success when major version is greater", () => {
    expect(checkMinimumFlywayVersion("13.0.0")).toEqual({ success: true });
  });

  it("should ignore suffixes such as -rc1066 when version meets minimum", () => {
    expect(checkMinimumFlywayVersion("12.0.0-rc1066")).toEqual({ success: true });
  });

  it("should return a failure message when patch version is lower", () => {
    const result = checkMinimumFlywayVersion("11.99.9");

    expect(result.success).toBe(false);

    if (!result.success) {
      expect(result.message).toContain("11.99.9");
      expect(result.message).toContain("12.0.0");
      expect(result.message).toContain("upgrade Flyway");
    }
  });

  it("should return a failure message when minor version is lower", () => {
    const result = checkMinimumFlywayVersion("11.20.0");

    expect(result.success).toBe(false);

    if (!result.success) {
      expect(result.message).toContain("11.20.0");
    }
  });

  it("should return a failure message when major version is lower", () => {
    const result = checkMinimumFlywayVersion("10.22.0");

    expect(result.success).toBe(false);

    if (!result.success) {
      expect(result.message).toContain("10.22.0");
    }
  });

  it("should report unknown when actual is empty", () => {
    const result = checkMinimumFlywayVersion("");

    expect(result.success).toBe(false);

    if (!result.success) {
      expect(result.message).toContain("unknown");
    }
  });

  it("should report the raw value when actual is non-numeric", () => {
    const result = checkMinimumFlywayVersion("nightly");

    expect(result.success).toBe(false);

    if (!result.success) {
      expect(result.message).toContain("nightly");
    }
  });

  it("should ignore suffixes when version is below minimum", () => {
    const result = checkMinimumFlywayVersion("11.99.9-rc1066");

    expect(result.success).toBe(false);

    if (!result.success) {
      expect(result.message).toContain("11.99.9-rc1066");
    }
  });
});
