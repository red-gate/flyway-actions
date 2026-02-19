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
    await uploadReport("/some/directory");

    expect(existsSync).toHaveBeenCalledWith("/some/directory/report.html");
    expect(info).toHaveBeenCalledWith("No report found, skipping upload");
    expect(startGroup).not.toHaveBeenCalled();
    expect(uploadArtifact).not.toHaveBeenCalled();
  });

  it("should upload report when report.html exists", async () => {
    existsSync.mockReturnValue(true);
    uploadArtifact.mockResolvedValue({ id: 42, size: 1024 });

    const { uploadReport } = await import("../src/upload-report.js");
    await uploadReport("/project");

    expect(uploadArtifact).toHaveBeenCalledWith("flyway-report", ["/project/report.html"], "/project");
    expect(info).toHaveBeenCalledWith("Artifact uploaded: ID 42, size 1024 bytes");
    expect(endGroup).toHaveBeenCalled();
  });

  it("should fall back to process.cwd() when no working directory provided", async () => {
    existsSync.mockReturnValue(false);

    const { uploadReport } = await import("../src/upload-report.js");
    await uploadReport();

    expect(existsSync).toHaveBeenCalledWith(expect.stringContaining("report.html"));
    expect(existsSync).toHaveBeenCalledWith(`${process.cwd()}/report.html`);
  });

  it("should log warning when upload throws", async () => {
    existsSync.mockReturnValue(true);
    uploadArtifact.mockRejectedValue(new Error("network timeout"));

    const { uploadReport } = await import("../src/upload-report.js");
    await uploadReport("/project");

    expect(warning).toHaveBeenCalledWith("Failed to upload report artifact: network timeout");
    expect(endGroup).toHaveBeenCalled();
  });

  it("should call endGroup even on failure", async () => {
    existsSync.mockReturnValue(true);
    uploadArtifact.mockRejectedValue(new Error("upload failed"));

    const { uploadReport } = await import("../src/upload-report.js");
    await uploadReport("/project");

    expect(startGroup).toHaveBeenCalledWith("Uploading Flyway report");
    expect(endGroup).toHaveBeenCalled();
  });
});
