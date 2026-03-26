import type { FlywayMigrationsChecksInputs } from "../types.js";
import * as core from "@actions/core";
import { checkForCodeReviewViolations } from "@flyway-actions/shared/check-for-code-review-violations";
import { getCheckCommandArgs, getTargetEnvironmentArgs } from "./arg-builders.js";

const getCodeArgs = (inputs: FlywayMigrationsChecksInputs): string[] | undefined => {
  if (inputs.skipCodeReview) {
    core.info('Skipping code review: "skip-code-review" set to true');
    return undefined;
  }
  return [
    ...getCheckCommandArgs(inputs),
    "-code",
    ...getTargetEnvironmentArgs(inputs),
    ...(inputs.failOnCodeReview ? ["-check.code.failOnError=true"] : []),
  ];
};

const runCheckCode = async (inputs: FlywayMigrationsChecksInputs) => {
  const args = getCodeArgs(inputs);
  if (!args) {
    return undefined;
  }
  const { exitCode, result } = await checkForCodeReviewViolations(args, inputs.workingDirectory);
  core.setOutput("code-violation-count", result.violationCount.toString());
  core.setOutput("code-violation-codes", result.violationCodes.join(","));
  return {
    exitCode,
    reportPath: result.reportPath,
    sarifReportPath: result.sarifReportPath,
    violationCount: result.violationCount,
  };
};

export { runCheckCode };
