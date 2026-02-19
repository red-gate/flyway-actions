import * as fs from "fs";
import * as path from "path";
import { DefaultArtifactClient } from "@actions/artifact";
import * as core from "@actions/core";

const REPORT_FILE = "report.html";
const DEFAULT_ARTIFACT_NAME = "flyway-report";

type UploadReportOptions = {
  workingDirectory?: string;
  retentionDays?: number;
  artifactName?: string;
};

const uploadReport = async (options?: UploadReportOptions): Promise<void> => {
  const directory = options?.workingDirectory || process.cwd();
  const reportPath = path.join(directory, REPORT_FILE);

  if (!fs.existsSync(reportPath)) {
    core.info("No report found, skipping upload");
    return;
  }

  const artifactName = options?.artifactName || DEFAULT_ARTIFACT_NAME;

  core.startGroup("Uploading Flyway report");
  try {
    const client = new DefaultArtifactClient();
    const uploadOptions = options?.retentionDays ? { retentionDays: options.retentionDays } : undefined;
    const response = await client.uploadArtifact(artifactName, [reportPath], directory, uploadOptions);
    core.info(`Artifact uploaded: ID ${response.id}, size ${response.size} bytes`);
  } catch (error) {
    core.warning(`Failed to upload report artifact: ${error instanceof Error ? error.message : String(error)}`);
  } finally {
    core.endGroup();
  }
};

export type { UploadReportOptions };
export { uploadReport };
