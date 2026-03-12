import type { FlywayStatePrepareInputs } from "../types.js";
import * as core from "@actions/core";
import { checkForCodeReview } from "@flyway-actions/shared/check-for-code-review";
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
    ...(inputs.failOnCodeReview ? ["-check.code.failOnError=true"] : []),
    "-check.scope=script",
    `-check.scriptFilename=${scriptFilename}`,
  ];
};

const runCheckCode = async (inputs: FlywayStatePrepareInputs, scriptFilename: string) => {
  const args = getCodeArgs(inputs, scriptFilename);
  if (!args) {
    return undefined;
  }
  return checkForCodeReview(args, inputs.workingDirectory);
};

export { getCodeArgs, runCheckCode };
