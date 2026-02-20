import type { Code, FlywayCheckOutput, FlywayMigrationsChecksInputs } from "../types.js";
import * as core from "@actions/core";
import { runFlyway } from "@flyway-actions/shared";
import { parseCheckOutput } from "../outputs.js";
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
  core.startGroup("Running Flyway check: code review");
  try {
    const result = await runFlyway(args, inputs.workingDirectory);
    setCodeOutputs(parseCheckOutput(result.stdout));
    return { exitCode: result.exitCode };
  } finally {
    core.endGroup();
  }
};

const setCodeOutputs = (output: FlywayCheckOutput | undefined): void => {
  const codeResults = output?.individualResults?.filter((r): r is Code => r.operation === "code");
  if (codeResults?.length) {
    const violations = codeResults.flatMap((r) => r.results?.flatMap((v) => v.violations ?? []) ?? []);
    const codes = violations.map((v) => v.code).filter((c): c is string => !!c);
    core.setOutput("code-violation-count", codes.length.toString());
    core.setOutput("code-violation-codes", [...new Set(codes)].join(","));
  }
};

export { getCodeArgs, runCheckCode, setCodeOutputs };
