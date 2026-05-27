import { unlink } from "node:fs/promises";
import * as core from "@actions/core";

const deleteDiffArtifact = async (artifactPath: string | undefined): Promise<void> => {
  if (!artifactPath) {
    core.info("No diff artifact path captured; nothing to clean up.");
    return;
  }
  try {
    await unlink(artifactPath);
    core.info(`Deleted diff artifact: ${artifactPath}`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    core.warning(`Failed to delete diff artifact at ${artifactPath}: ${message}`);
  }
};

export { deleteDiffArtifact };
