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
      const violationCount = errorOutput?.error?.results ? setCodeOutputs(errorOutput.error.results) : 0;

      return { exitCode: result.exitCode, reportPath: errorOutput?.error?.htmlReport, violationCount };
    }

    const output = parseCheckOutput(result.stdout);
    const codeResults = output?.individualResults?.filter((r): r is Code => r.operation === "code");
    const violationCount = codeResults?.length ? setCodeOutputs(codeResults.flatMap((r) => r.results ?? [])) : 0;

    return { exitCode: result.exitCode, reportPath: output?.htmlReport, violationCount };
  } finally {
    core.endGroup();
  }
};

const setCodeOutputs = (results: CodeResultItem[]): number => {
  const violations = results.flatMap((r) => r.violations ?? []);
  const codes = violations.map((v) => v.code).filter((c): c is string => !!c);
  core.setOutput("code-violation-count", codes.length.toString());
  core.setOutput("code-violation-codes", [...new Set(codes)].join(","));
  return codes.length;
};

export { getCodeArgs, runCheckCode, setCodeOutputs };
