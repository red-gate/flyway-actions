import { getVersionError } from "../src/version-check.js";

describe("getVersionError", () => {
  it("should return undefined when version equals minimum", () => {
    expect(getVersionError("12.0.0")).toBeUndefined();
  });

  it("should return undefined when patch version is greater", () => {
    expect(getVersionError("12.0.1")).toBeUndefined();
  });

  it("should return undefined when minor version is greater", () => {
    expect(getVersionError("12.1.0")).toBeUndefined();
  });

  it("should return undefined when major version is greater", () => {
    expect(getVersionError("13.0.0")).toBeUndefined();
  });

  it("should ignore suffixes such as -rc1066 when version meets minimum", () => {
    expect(getVersionError("12.0.0-rc1066")).toBeUndefined();
  });

  it("should return a failure message when patch version is lower", () => {
    const message = getVersionError("11.99.9");

    expect(message).toContain("11.99.9");
    expect(message).toContain("12.0.0");
    expect(message).toContain("upgrade Flyway");
  });

  it("should return a failure message when minor version is lower", () => {
    expect(getVersionError("11.20.0")).toContain("11.20.0");
  });

  it("should return a failure message when major version is lower", () => {
    expect(getVersionError("10.22.0")).toContain("10.22.0");
  });

  it("should report unknown when actual is empty", () => {
    expect(getVersionError("")).toContain("unknown");
  });

  it("should report the raw value when actual is non-numeric", () => {
    expect(getVersionError("nightly")).toContain("nightly");
  });

  it("should ignore suffixes when version is below minimum", () => {
    expect(getVersionError("11.99.9-rc1066")).toContain("11.99.9-rc1066");
  });
});
