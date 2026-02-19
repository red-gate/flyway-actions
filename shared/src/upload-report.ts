import * as fs from "fs";
import * as path from "path";
import { DefaultArtifactClient } from "@actions/artifact";
import * as core from "@actions/core";

const ARTIFACT_NAME = "flyway-report";
const REPORT_FILE = "report.html";

const uploadReport = async (workingDirectory?: string): Promise<void> => {
  const directory = workingDirectory || process.cwd();
  const reportPath = path.join(directory, REPORT_FILE);

  if (!fs.existsSync(reportPath)) {
    core.info("No report found, skipping upload");
    return;
  }

  core.startGroup("Uploading Flyway report");
  try {
    const client = new DefaultArtifactClient();
    const response = await client.uploadArtifact(ARTIFACT_NAME, [reportPath], directory);
    core.info(`Artifact uploaded: ID ${response.id}, size ${response.size} bytes`);
  } catch (error) {
    core.warning(`Failed to upload report artifact: ${error instanceof Error ? error.message : String(error)}`);
  } finally {
    core.endGroup();
  }
};

export { uploadReport };
