import type { FlywayStatePrepareInputs } from "../types.js";
import * as core from "@actions/core";
import { checkForDrift } from "@flyway-actions/shared/check-for-drift";
import { resolvePath } from "@flyway-actions/shared/resolve-path";
import { getCommonArgs } from "./arg-builders.js";

const getDriftArgs = (inputs: FlywayStatePrepareInputs): string[] => [
  "check",
  "-drift",
  "-check.failOnDrift=true",
  ...getCommonArgs(inputs),
  ...(inputs.preDeploymentReportName ? [`-reportFilename=${inputs.preDeploymentReportName}`] : []),
];

const runCheckDrift = async (inputs: FlywayStatePrepareInputs) => {
  const { exitCode, result } = await checkForDrift(getDriftArgs(inputs), inputs.workingDirectory);
  const reportPath = resolvePath(result.reportPath, inputs.workingDirectory);
  const driftResolutionFolder = resolvePath(result.driftResolutionFolder, inputs.workingDirectory);

  core.setOutput("exit-code", exitCode.toString());
  result.driftDetected !== undefined && core.setOutput("drift-detected", result.driftDetected.toString());
  reportPath !== undefined && core.setOutput("report-path", reportPath);
  driftResolutionFolder !== undefined && core.setOutput("drift-resolution-folder", driftResolutionFolder);
  return { exitCode, result };
};

export { runCheckDrift };
