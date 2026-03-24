import type { FlywayStatePrepareInputs } from "../types.js";
import * as core from "@actions/core";
import { checkForCodeReviewViolations } from "@flyway-actions/shared/check-for-code-review-violations";
import { parseExtraArgs } from "@flyway-actions/shared/flyway-runner";
import { getTargetEnvironmentArgs } from "./arg-builders.js";

const getCodeArgs = (inputs: FlywayStatePrepareInputs, scriptFilename: string): string[] | undefined => {
  if (inputs.skipCodeReview) {
    core.info('Skipping code review: "skip-code-review" set to true');
    return undefined;
  }
  return [
    "check",
    "-code",
    ...getTargetEnvironmentArgs(inputs),
    ...(inputs.workingDirectory ? [`-workingDirectory=${inputs.workingDirectory}`] : []),
    ...(inputs.extraArgs ? parseExtraArgs(inputs.extraArgs) : []),
    ...(inputs.failOnCodeReview ? ["-check.code.failOnError=true"] : []),
    ...(inputs.preDeploymentReportName ? [`-reportFilename=${inputs.preDeploymentReportName}`] : []),
    "-check.scope=script",
    `-check.scriptFilename=${scriptFilename}`,
  ];
};

const runCheckCode = async (inputs: FlywayStatePrepareInputs, scriptFilename: string) => {
  const args = getCodeArgs(inputs, scriptFilename);
  if (!args) {
    return undefined;
  }
  const codeReviewResult = await checkForCodeReviewViolations(args, inputs.workingDirectory);
  core.setOutput("code-violation-count", codeReviewResult.result.violationCount.toString());
  core.setOutput("code-violation-codes", codeReviewResult.result.violationCodes.join(","));
  return codeReviewResult;
};

export { getCodeArgs, runCheckCode };
