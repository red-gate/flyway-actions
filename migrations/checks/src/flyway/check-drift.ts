import type { Drift, FlywayCheckOutput, FlywayMigrationsChecksInputs } from "../types.js";
import type { FlywayEdition } from "@flyway-actions/shared";
import * as core from "@actions/core";
import { runFlyway } from "@flyway-actions/shared";
import { parseCheckOutput } from "../outputs.js";
import { getCheckCommandArgs, getTargetEnvironmentArgs } from "./arg-builders.js";

const getDriftArgs = (inputs: FlywayMigrationsChecksInputs, edition: FlywayEdition): string[] | undefined => {
  if (edition !== "enterprise") {
    core.info(`Skipping drift check: not available in ${edition === "community" ? "Community" : "Teams"} edition`);
    return undefined;
  }
  if (inputs.skipDriftCheck) {
    core.info('Skipping drift check: "skip-drift-check" set to true');
    return undefined;
  }
  return [
    ...getCheckCommandArgs(inputs),
    "-drift",
    ...getTargetEnvironmentArgs(inputs),
    ...(inputs.failOnDrift ? ["-check.failOnDrift=true"] : []),
  ];
};

const runCheckDrift = async (inputs: FlywayMigrationsChecksInputs, edition: FlywayEdition) => {
  const args = getDriftArgs(inputs, edition);
  if (!args) {
    return undefined;
  }
  core.startGroup("Running Flyway check: drift");
  try {
    const result = await runFlyway(args, inputs.workingDirectory);
    const exitCode = result.exitCode;
    const output = parseCheckOutput(result.stdout);
    core.setOutput("drift-detected", isDriftDetected(output).toString());
    return { exitCode };
  } finally {
    core.endGroup();
  }
};

const isDriftDetected = (output:FlywayCheckOutput | undefined): boolean => !!output?.individualResults
  ?.filter((r): r is Drift => r.operation === "drift")
  .some((r) => r.onlyInSource?.length || r.onlyInTarget?.length || r.differences?.length);

export { getDriftArgs, runCheckDrift };
