const info = vi.fn();
const warning = vi.fn();
const unlink = vi.fn();

vi.doMock("@actions/core", () => ({
  info,
  warning,
}));

vi.doMock("node:fs/promises", () => ({
  unlink,
}));

const { deleteDiffArtifact } = await import("../../src/flyway/cleanup.js");

describe("deleteDiffArtifact", () => {
  it("should be a no-op when no path is given", async () => {
    await deleteDiffArtifact(undefined);

    expect(unlink).not.toHaveBeenCalled();
    expect(info).toHaveBeenCalledWith(expect.stringContaining("nothing to clean up"));
  });

  it("should delete the artifact at the given path", async () => {
    unlink.mockResolvedValue(undefined);

    await deleteDiffArtifact("/tmp/artifact");

    expect(unlink).toHaveBeenCalledWith("/tmp/artifact");
    expect(info).toHaveBeenCalledWith(expect.stringContaining("/tmp/artifact"));
    expect(warning).not.toHaveBeenCalled();
  });

  it("should warn but not throw if the delete fails", async () => {
    unlink.mockRejectedValue(new Error("ENOENT"));

    await deleteDiffArtifact("/tmp/missing");

    expect(unlink).toHaveBeenCalledWith("/tmp/missing");
    expect(warning).toHaveBeenCalledWith(expect.stringContaining("/tmp/missing"));
    expect(warning).toHaveBeenCalledWith(expect.stringContaining("ENOENT"));
  });
});
