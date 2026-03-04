import type { Code, CodeResultItem, FlywayMigrationsChecksInputs } from "../types.js";
import * as core from "@actions/core";
import { runFlyway } from "@flyway-actions/shared/flyway-runner";
import { parseCheckOutput, parseCodeErrorOutput } from "../outputs.js";
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
    if (result.exitCode !== 0) {
      const errorOutput = parseCodeErrorOutput(result.stdout);
      errorOutput?.error?.message && core.error(errorOutput.error.message);
      errorOutput?.error?.results && setCodeOutputs(errorOutput.error.results);

      return { exitCode: result.exitCode, reportPath: errorOutput?.error?.htmlReport };
    }

    const output = parseCheckOutput(result.stdout);
    const codeResults = output?.individualResults?.filter((r): r is Code => r.operation === "code");
    codeResults?.length && setCodeOutputs(codeResults.flatMap((r) => r.results ?? []));

    return { exitCode: result.exitCode, reportPath: output?.htmlReport };
  } finally {
    core.endGroup();
  }
};

const setCodeOutputs = (results: CodeResultItem[]): void => {
  const violations = results.flatMap((r) => r.violations ?? []);
  const codes = violations.map((v) => v.code).filter((c): c is string => !!c);
  core.setOutput("code-violation-count", codes.length.toString());
  core.setOutput("code-violation-codes", [...new Set(codes)].join(","));
};

export { getCodeArgs, runCheckCode, setCodeOutputs };
