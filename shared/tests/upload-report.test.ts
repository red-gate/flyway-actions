const existsSync = vi.fn();
const info = vi.fn();
const warning = vi.fn();
const startGroup = vi.fn();
const endGroup = vi.fn();
const uploadArtifact = vi.fn();

const setupMocks = () => {
  vi.doMock("fs", () => ({ existsSync }));
  vi.doMock("@actions/core", () => ({ info, warning, startGroup, endGroup }));
  vi.doMock("@actions/artifact", () => ({
    DefaultArtifactClient: class {
      uploadArtifact = uploadArtifact;
    },
  }));
};

describe("uploadReport", () => {
  beforeEach(() => {
    vi.resetModules();
    setupMocks();
  });

  it("should skip upload when report.html does not exist", async () => {
    existsSync.mockReturnValue(false);

    const { uploadReport } = await import("../src/upload-report.js");
    await uploadReport({ workingDirectory: "/some/directory" });

    expect(existsSync).toHaveBeenCalledWith("/some/directory/report.html");
    expect(info).toHaveBeenCalledWith("No report found, skipping upload");
    expect(startGroup).not.toHaveBeenCalled();
    expect(uploadArtifact).not.toHaveBeenCalled();
  });

  it("should upload report when report.html exists", async () => {
    existsSync.mockReturnValue(true);
    uploadArtifact.mockResolvedValue({ id: 42, size: 1024 });

    const { uploadReport } = await import("../src/upload-report.js");
    await uploadReport({ workingDirectory: "/project" });

    expect(uploadArtifact).toHaveBeenCalledWith("flyway-report", ["/project/report.html"], "/project", undefined);
    expect(info).toHaveBeenCalledWith("Artifact uploaded: ID 42, size 1024 bytes");
    expect(endGroup).toHaveBeenCalled();
  });

  it("should fall back to process.cwd() when no options provided", async () => {
    existsSync.mockReturnValue(false);

    const { uploadReport } = await import("../src/upload-report.js");
    await uploadReport();

    expect(existsSync).toHaveBeenCalledWith(expect.stringContaining("report.html"));
    expect(existsSync).toHaveBeenCalledWith(`${process.cwd()}/report.html`);
  });

  it("should use custom artifact name when provided", async () => {
    existsSync.mockReturnValue(true);
    uploadArtifact.mockResolvedValue({ id: 10, size: 512 });

    const { uploadReport } = await import("../src/upload-report.js");
    await uploadReport({ workingDirectory: "/project", artifactName: "custom-report" });

    expect(uploadArtifact).toHaveBeenCalledWith("custom-report", ["/project/report.html"], "/project", undefined);
  });

  it("should pass retention days as upload options", async () => {
    existsSync.mockReturnValue(true);
    uploadArtifact.mockResolvedValue({ id: 10, size: 512 });

    const { uploadReport } = await import("../src/upload-report.js");
    await uploadReport({ workingDirectory: "/project", retentionDays: 14 });

    expect(uploadArtifact).toHaveBeenCalledWith("flyway-report", ["/project/report.html"], "/project", {
      retentionDays: 14,
    });
  });

  it("should pass both custom name and retention days", async () => {
    existsSync.mockReturnValue(true);
    uploadArtifact.mockResolvedValue({ id: 10, size: 512 });

    const { uploadReport } = await import("../src/upload-report.js");
    await uploadReport({ workingDirectory: "/project", artifactName: "my-report", retentionDays: 30 });

    expect(uploadArtifact).toHaveBeenCalledWith("my-report", ["/project/report.html"], "/project", {
      retentionDays: 30,
    });
  });

  it("should log warning when upload throws", async () => {
    existsSync.mockReturnValue(true);
    uploadArtifact.mockRejectedValue(new Error("network timeout"));

    const { uploadReport } = await import("../src/upload-report.js");
    await uploadReport({ workingDirectory: "/project" });

    expect(warning).toHaveBeenCalledWith("Failed to upload report artifact: network timeout");
    expect(endGroup).toHaveBeenCalled();
  });

  it("should call endGroup even on failure", async () => {
    existsSync.mockReturnValue(true);
    uploadArtifact.mockRejectedValue(new Error("upload failed"));

    const { uploadReport } = await import("../src/upload-report.js");
    await uploadReport({ workingDirectory: "/project" });

    expect(startGroup).toHaveBeenCalledWith("Uploading Flyway report");
    expect(endGroup).toHaveBeenCalled();
  });
});
