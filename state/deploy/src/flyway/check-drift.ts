import type { FlywayStateDeploymentInputs } from "../types.js";
import * as core from "@actions/core";
import { checkForDrift } from "@flyway-actions/shared/check-for-drift";
import { getCommonArgs } from "./arg-builders.js";

const getDriftArgs = (inputs: FlywayStateDeploymentInputs): string[] => [
  "check",
  "-drift",
  "-check.failOnDrift=true",
  ...getCommonArgs(inputs),
  ...(inputs.driftReportName ? [`-reportFilename=${inputs.driftReportName}`] : []),
];

const runCheckDrift = async (inputs: FlywayStateDeploymentInputs) => {
  const result = await checkForDrift(getDriftArgs(inputs), inputs.workingDirectory);
  core.setOutput("exit-code", result.exitCode.toString());
  result.driftDetected !== undefined && core.setOutput("drift-detected", result.driftDetected.toString());
  result.reportPath !== undefined && core.setOutput("report-path", result.reportPath);
  result.driftResolutionFolder !== undefined && core.setOutput("drift-resolution-folder", result.driftResolutionFolder);
  return result;
};

export { runCheckDrift };
