import type { FlywayMigrationsChecksInputs } from "../src/types.js";
import * as path from "path";

const getInput = vi.fn();
const getBooleanInput = vi.fn();
const setSecret = vi.fn();

vi.doMock("@actions/core", () => ({
  getInput,
  getBooleanInput,
  setSecret,
}));

const { getInputs, maskSecrets } = await import("../src/inputs.js");

describe("getInputs", () => {
  beforeEach(() => {
    getInput.mockReturnValue("");
  });

  it("should return target connection inputs when provided", () => {
    getInput.mockImplementation((name: string) => {
      const values: Record<string, string> = {
        "target-url": "jdbc:postgresql://localhost/db",
        "target-user": "admin",
        "target-password": "secret",
        "target-environment": "production",
        "target-schemas": "public,audit",
      };
      return values[name] || "";
    });

    const inputs = getInputs();

    expect(inputs.targetUrl).toBe("jdbc:postgresql://localhost/db");
    expect(inputs.targetUser).toBe("admin");
    expect(inputs.targetPassword).toBe("secret");
    expect(inputs.targetEnvironment).toBe("production");
    expect(inputs.targetSchemas).toBe("public,audit");
  });

  it("should return migration version and cherry pick inputs", () => {
    getInput.mockImplementation((name: string) => {
      const values: Record<string, string> = {
        "target-migration-version": "5.0",
        "cherry-pick": "3.0,4.0",
      };
      return values[name] || "";
    });

    const inputs = getInputs();

    expect(inputs.targetMigrationVersion).toBe("5.0");
    expect(inputs.cherryPick).toBe("3.0,4.0");
  });

  it("should resolve working directory to absolute path", () => {
    getInput.mockImplementation((name: string) => {
      if (name === "working-directory") {
        return "/app/db";
      }
      return "";
    });

    const inputs = getInputs();

    expect(inputs.workingDirectory).toBe(path.resolve("/app/db"));
  });

  it("should return skip-code-review input", () => {
    getBooleanInput.mockReturnValue(true);

    const inputs = getInputs();

    expect(inputs.skipCodeReview).toBe(true);
    expect(getBooleanInput).toHaveBeenCalledWith("skip-code-review");
  });

  it("should return skip-drift-check input", () => {
    getBooleanInput.mockReturnValue(true);

    const inputs = getInputs();

    expect(inputs.skipDriftCheck).toBe(true);
    expect(getBooleanInput).toHaveBeenCalledWith("skip-drift-check");
  });

  it("should return skip-deployment-changes-report input", () => {
    getBooleanInput.mockReturnValue(true);

    const inputs = getInputs();

    expect(inputs.skipDeploymentChangesReport).toBe(true);
    expect(getBooleanInput).toHaveBeenCalledWith("skip-deployment-changes-report");
  });

  it("should return skip-deployment-script-review input", () => {
    getBooleanInput.mockReturnValue(true);

    const inputs = getInputs();

    expect(inputs.skipDeploymentScriptReview).toBe(true);
    expect(getBooleanInput).toHaveBeenCalledWith("skip-deployment-script-review");
  });

  it("should return fail-on-code-review input", () => {
    getBooleanInput.mockReturnValue(true);

    const inputs = getInputs();

    expect(inputs.failOnCodeReview).toBe(true);
    expect(getBooleanInput).toHaveBeenCalledWith("fail-on-code-review");
  });

  it("should return fail-on-drift input", () => {
    getBooleanInput.mockReturnValue(true);

    const inputs = getInputs();

    expect(inputs.failOnDrift).toBe(true);
    expect(getBooleanInput).toHaveBeenCalledWith("fail-on-drift");
  });

  it("should return build-ok-to-erase input", () => {
    getBooleanInput.mockReturnValue(true);

    const inputs = getInputs();

    expect(inputs.buildOkToErase).toBe(true);
    expect(getBooleanInput).toHaveBeenCalledWith("build-ok-to-erase");
  });

  it("should return skip-html-report-upload input", () => {
    getBooleanInput.mockImplementation((name: string) => name === "skip-html-report-upload");

    const inputs = getInputs();

    expect(inputs.skipHtmlReportUpload).toBe(true);
    expect(getBooleanInput).toHaveBeenCalledWith("skip-html-report-upload");
  });

  it("should return report-retention-days input", () => {
    getInput.mockImplementation((name: string) => (name === "report-retention-days" ? "14" : ""));

    const inputs = getInputs();

    expect(inputs.reportRetentionDays).toBe(14);
  });

  it("should return report-name input", () => {
    getInput.mockImplementation((name: string) => (name === "report-name" ? "custom-report" : ""));

    const inputs = getInputs();

    expect(inputs.reportName).toBe("custom-report");
  });

  it("should return extra args", () => {
    getInput.mockImplementation((name: string) => {
      if (name === "extra-args") {
        return "-X -someFlag=value";
      }
      return "";
    });

    const inputs = getInputs();

    expect(inputs.extraArgs).toBe("-X -someFlag=value");
  });

  it("should return build connection inputs when provided", () => {
    getInput.mockImplementation((name: string) => {
      const values: Record<string, string> = {
        "build-environment": "build",
        "build-url": "jdbc:postgresql://localhost/build-db",
        "build-user": "deploy",
        "build-password": "secret",
        "build-schemas": "public,staging",
      };
      return values[name] || "";
    });

    const inputs = getInputs();

    expect(inputs.buildEnvironment).toBe("build");
    expect(inputs.buildUrl).toBe("jdbc:postgresql://localhost/build-db");
    expect(inputs.buildUser).toBe("deploy");
    expect(inputs.buildPassword).toBe("secret");
    expect(inputs.buildSchemas).toBe("public,staging");
  });

  it("should return undefined for optional inputs not provided", () => {
    const inputs = getInputs();

    expect(inputs.targetUrl).toBeUndefined();
    expect(inputs.targetUser).toBeUndefined();
    expect(inputs.targetPassword).toBeUndefined();
    expect(inputs.targetEnvironment).toBeUndefined();
    expect(inputs.targetSchemas).toBeUndefined();
    expect(inputs.targetMigrationVersion).toBeUndefined();
    expect(inputs.cherryPick).toBeUndefined();
    expect(inputs.buildEnvironment).toBeUndefined();
    expect(inputs.buildUrl).toBeUndefined();
    expect(inputs.buildUser).toBeUndefined();
    expect(inputs.buildPassword).toBeUndefined();
    expect(inputs.buildSchemas).toBeUndefined();
    expect(inputs.workingDirectory).toBeUndefined();
    expect(inputs.extraArgs).toBeUndefined();
  });
});

describe("maskSecrets", () => {
  const baseSecretInputs: FlywayMigrationsChecksInputs = {
    skipHtmlReportUpload: false,
    reportRetentionDays: 7,
    reportName: "flyway-report",
  };

  it("should mask target password", () => {
    maskSecrets({ ...baseSecretInputs, targetPassword: "secret123" });

    expect(setSecret).toHaveBeenCalledWith("secret123");
  });

  it("should mask build password", () => {
    maskSecrets({ ...baseSecretInputs, buildPassword: "secret" });

    expect(setSecret).toHaveBeenCalledWith("secret");
  });

  it("should not call setSecret when no passwords present", () => {
    maskSecrets({ ...baseSecretInputs, targetUrl: "jdbc:postgresql://localhost/db" });

    expect(setSecret).not.toHaveBeenCalled();
  });
});
