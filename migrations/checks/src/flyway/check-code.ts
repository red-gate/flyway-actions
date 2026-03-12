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
  const result = await checkForCodeReviewViolations(args, inputs.workingDirectory);
  return { exitCode: result.exitCode, reportPath: result.reportPath };
};

export { runCheckCode };
