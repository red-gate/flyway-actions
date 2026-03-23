import type { FlywayMigrationsDeploymentInputs } from "../types.js";
import * as core from "@actions/core";
import { checkForDrift } from "@flyway-actions/shared/check-for-drift";
import { getCommonArgs } from "./arg-builders.js";

const getDriftArgs = (inputs: FlywayMigrationsDeploymentInputs): string[] => [
  "check",
  "-drift",
  "-check.failOnDrift=true",
  ...getCommonArgs(inputs),
  ...(inputs.deploymentReportName ? [`-reportFilename=${inputs.deploymentReportName}`] : []),
];

const runCheckDrift = async (inputs: FlywayMigrationsDeploymentInputs) => {
  const { exitCode, result } = await checkForDrift(getDriftArgs(inputs), inputs.workingDirectory);

  core.setOutput("exit-code", exitCode.toString());
  core.setOutput("drift-detected", result.driftDetected.toString());
  result.reportPath !== undefined && core.setOutput("report-path", result.reportPath);
  result.driftResolutionFolder !== undefined && core.setOutput("drift-resolution-folder", result.driftResolutionFolder);
  return { exitCode, result };
};

export { runCheckDrift };
