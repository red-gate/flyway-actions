const info = vi.fn();
const setOutput = vi.fn();
const checkForChanges = vi.fn();

vi.doMock("@actions/core", () => ({
  info,
  error: vi.fn(),
  setOutput,
  startGroup: vi.fn(),
  endGroup: vi.fn(),
}));

vi.doMock("@flyway-actions/shared/check-for-changes", () => ({
  checkForChanges,
}));

const { runCheckChanges } = await import("../../src/flyway/check-changes.js");

describe("runCheckChanges", () => {
  beforeEach(() => {
    checkForChanges.mockResolvedValue({ exitCode: 0, result: { changedObjectCount: 0 } });
  });

  it("should default to a Docker-provisioned build database when no build inputs are provided", async () => {
    await runCheckChanges({ targetUrl: "jdbc:postgresql://localhost/db" }, "enterprise");

    expect(info).toHaveBeenCalledWith(expect.stringContaining("defaulting to a disposable Docker-provisioned"));

    const args = checkForChanges.mock.calls[0][0] as string[];

    expect(args).toContain("-check.buildEnvironment=default_build");
    expect(args).toContain("-environments.default_build.provisioner=docker");
    expect(checkForChanges).toHaveBeenCalledWith(expect.any(Array), undefined, true);
  });

  it("should still default to a Docker-provisioned build database when the target engine can't be inferred from a raw url", async () => {
    await runCheckChanges({ targetUrl: "jdbc:sqlite:test.db" }, "enterprise");

    expect(info).toHaveBeenCalledWith(expect.stringContaining("defaulting to a disposable Docker-provisioned"));
    expect(checkForChanges).toHaveBeenCalled();
  });

  it("should still default to a Docker-provisioned build database when no target url is provided", async () => {
    await runCheckChanges({}, "enterprise");

    expect(info).toHaveBeenCalledWith(expect.stringContaining("defaulting to a disposable Docker-provisioned"));
    expect(checkForChanges).toHaveBeenCalled();
  });

  it("should skip for community edition", async () => {
    const result = await runCheckChanges({ buildUrl: "jdbc:sqlite:build.db" }, "community");

    expect(result).toBeUndefined();
    expect(info).toHaveBeenCalledWith(expect.stringContaining("Community"));
    expect(checkForChanges).not.toHaveBeenCalled();
  });

  it("should skip for teams edition", async () => {
    const result = await runCheckChanges({ buildUrl: "jdbc:sqlite:build.db" }, "teams");

    expect(result).toBeUndefined();
    expect(info).toHaveBeenCalledWith(expect.stringContaining("Teams"));
    expect(checkForChanges).not.toHaveBeenCalled();
  });

  it("should skip when skipDeploymentChangesReport is true", async () => {
    const result = await runCheckChanges(
      { skipDeploymentChangesReport: true, buildUrl: "jdbc:sqlite:build.db" },
      "enterprise",
    );

    expect(result).toBeUndefined();
    expect(info).toHaveBeenCalledWith(expect.stringContaining("skip-deployment-changes-report"));
    expect(checkForChanges).not.toHaveBeenCalled();
  });

  it("should pass args with check and -changes", async () => {
    await runCheckChanges({ buildUrl: "jdbc:sqlite:build.db" }, "enterprise");

    const args = checkForChanges.mock.calls[0][0] as string[];

    expect(args[0]).toBe("check");
    expect(args).toContain("-changes");
  });

  it("should include target and build environment args", async () => {
    await runCheckChanges(
      { targetUrl: "jdbc:postgresql://localhost/db", buildUrl: "jdbc:sqlite:build.db" },
      "enterprise",
    );

    const args = checkForChanges.mock.calls[0][0] as string[];

    expect(args).toContain("-url=jdbc:postgresql://localhost/db");
    expect(args).toContain("-check.buildEnvironment=default_build");
    expect(args).toContain("-environments.default_build.url=jdbc:sqlite:build.db");
  });

  it("should include target migration version and cherry pick", async () => {
    await runCheckChanges(
      {
        targetUrl: "jdbc:postgresql://localhost/db",
        buildUrl: "jdbc:sqlite:build.db",
        targetMigrationVersion: "5.0",
        cherryPick: "3.0,4.0",
      },
      "enterprise",
    );

    const args = checkForChanges.mock.calls[0][0] as string[];

    expect(args).toContain("-target=5.0");
    expect(args).toContain("-cherryPick=3.0,4.0");
  });

  it("should pass workingDirectory and warnAboutBuildDatabase to checkForChanges", async () => {
    await runCheckChanges({ buildUrl: "jdbc:sqlite:build.db", workingDirectory: "/app/db" }, "enterprise");

    expect(checkForChanges).toHaveBeenCalledWith(expect.any(Array), "/app/db", true);
  });

  it("should pass warnAboutBuildDatabase as true when buildOkToErase is false", async () => {
    await runCheckChanges({ buildUrl: "jdbc:sqlite:build.db" }, "enterprise");

    expect(checkForChanges).toHaveBeenCalledWith(expect.any(Array), undefined, true);
  });

  it("should pass warnAboutBuildDatabase as false when buildOkToErase is true", async () => {
    await runCheckChanges({ buildUrl: "jdbc:sqlite:build.db", buildOkToErase: true }, "enterprise");

    expect(checkForChanges).toHaveBeenCalledWith(expect.any(Array), undefined, false);
  });

  it("should return exitCode and reportPath from result", async () => {
    checkForChanges.mockResolvedValue({
      exitCode: 0,
      result: { reportPath: "/tmp/report.html", changedObjectCount: 2 },
    });

    const result = await runCheckChanges({ buildUrl: "jdbc:sqlite:build.db" }, "enterprise");

    expect(result).toEqual({ exitCode: 0, reportPath: "/tmp/report.html", changedObjectCount: 2 });
  });

  it("should set changed-object-count output", async () => {
    checkForChanges.mockResolvedValue({
      exitCode: 0,
      result: { changedObjectCount: 4 },
    });

    await runCheckChanges({ buildUrl: "jdbc:sqlite:build.db" }, "enterprise");

    expect(setOutput).toHaveBeenCalledWith("changed-object-count", "4");
  });

  it("should not set changed-object-count output when result is undefined", async () => {
    checkForChanges.mockResolvedValue({ exitCode: 1 });

    const result = await runCheckChanges({ buildUrl: "jdbc:sqlite:build.db" }, "enterprise");

    expect(result).toEqual({ exitCode: 1, reportPath: undefined, changedObjectCount: undefined });
    expect(setOutput).not.toHaveBeenCalledWith("changed-object-count", expect.anything());
  });
});
