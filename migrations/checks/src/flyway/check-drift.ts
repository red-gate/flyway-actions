import type { FlywayMigrationsChecksInputs } from "../types.js";
import type { FlywayEdition } from "@flyway-actions/shared/types";
import * as core from "@actions/core";
import { checkForDrift } from "@flyway-actions/shared/check-for-drift";
import { resolvePath } from "@flyway-actions/shared/resolve-path";
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
  const result = await checkForDrift(args, inputs.workingDirectory);
  const driftResolutionFolder = resolvePath(result.driftResolutionFolder, inputs.workingDirectory);

  if (result.driftDetected || (result.exitCode === 0 && result.comparisonSupported)) {
    core.setOutput("drift-detected", result.driftDetected.toString());
    driftResolutionFolder !== undefined && core.setOutput("drift-resolution-folder", driftResolutionFolder);
  }
  return { exitCode: result.exitCode, reportPath: result.reportPath };
};

export { getDriftArgs, runCheckDrift };
