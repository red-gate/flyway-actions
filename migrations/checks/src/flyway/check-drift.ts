import type { Drift, FlywayCheckOutput, FlywayMigrationsChecksInputs } from "../types.js";
import type { FlywayEdition } from "@flyway-actions/shared";
import * as path from "node:path";
import * as core from "@actions/core";
import { parseErrorOutput, runFlyway } from "@flyway-actions/shared";
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
    let exitCode = result.exitCode;

    if (exitCode !== 0) {
      const errorOutput = parseErrorOutput(result.stdout);
      if (errorOutput?.error?.errorCode === "CHECK_DRIFT_DETECTED") {
        setOutput(true);
      } else if (errorOutput?.error?.errorCode === "COMPARISON_DATABASE_NOT_SUPPORTED") {
        core.info(
          "Drift check could not be run because advanced comparison features are not supported for this database type.",
        );
        exitCode = 0;
      } else {
        errorOutput?.error?.message && core.error(errorOutput.error.message);
      }
      return { exitCode };
    }

    const output = parseCheckOutput(result.stdout);
    setOutput(isDriftDetected(output), getDriftResolutionFolder(inputs, output));
    return { exitCode, reportPath: output?.htmlReport };
  } finally {
    core.endGroup();
  }
};

const isDriftDetected = (output: FlywayCheckOutput | undefined): boolean =>
  !!output?.individualResults
    ?.filter((r): r is Drift => r.operation === "drift")
    .some((r) => r.onlyInSource?.length || r.onlyInTarget?.length || r.differences?.length);

const getDriftResolutionFolder = (inputs: FlywayMigrationsChecksInputs, output: FlywayCheckOutput | undefined) => {
  const folder = output?.individualResults?.find(
    (r): r is Drift => r.operation === "drift" && !!r.driftResolutionFolder,
  )?.driftResolutionFolder;
  if (!folder) {
    return undefined;
  }
  if (path.isAbsolute(folder)) {
    return folder;
  }
  return inputs.workingDirectory ? path.join(inputs.workingDirectory, folder) : folder;
};

const setOutput = (driftDetected: boolean, driftResolutionFolder?: string) => {
  core.setOutput("drift-detected", driftDetected.toString());
  driftResolutionFolder && core.setOutput("drift-resolution-folder", driftResolutionFolder);
};

export { getDriftArgs, runCheckDrift };
