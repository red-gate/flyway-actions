import type { Drift, FlywayCheckOutput, FlywayMigrationsChecksInputs } from "../types.js";
import type { FlywayEdition } from "@flyway-actions/shared";
import * as core from "@actions/core";
import { runFlyway } from "@flyway-actions/shared";
import { parseCheckOutput } from "../outputs.js";
import { getBaseArgs, getCheckCommandArgs, getTargetEnvironmentArgs } from "./arg-builders.js";

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
    ...getCheckCommandArgs(),
    "-drift",
    ...(inputs.failOnDrift ? ["-check.failOnDrift=true"] : []),
    ...getTargetEnvironmentArgs(inputs),
    ...getBaseArgs(inputs),
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
    const output = parseCheckOutput(result.stdout);
    setDriftOutputs(output);
    return {
      exitCode: result.exitCode,
      output,
      stdout: result.stdout,
    };
  } finally {
    core.endGroup();
  }
};

const setDriftOutputs = (output: FlywayCheckOutput | undefined): void => {
  const driftResults = output?.individualResults?.filter((r): r is Drift => r.operation === "drift");
  if (driftResults?.length) {
    const drift = driftResults.some((r) => r.onlyInSource?.length || r.onlyInTarget?.length || r.differences?.length);
    core.setOutput("drift-detected", drift.toString());
  }
};

export { getDriftArgs, runCheckDrift, setDriftOutputs };
