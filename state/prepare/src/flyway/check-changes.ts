import type { FlywayStatePrepareInputs } from "../types.js";
import type { FlywayEdition } from "@flyway-actions/shared/types";
import * as core from "@actions/core";
import { checkForChanges } from "@flyway-actions/shared/check-for-changes";
import { parseExtraArgs } from "@flyway-actions/shared/flyway-runner";
import { getTargetEnvironmentArgs } from "./arg-builders.js";

const getChangesArgs = (inputs: FlywayStatePrepareInputs): string[] => [
  "check",
  "-changes",
  ...getTargetEnvironmentArgs(inputs),
  "-changesSource=schemaModel",
  ...(inputs.workingDirectory ? [`-workingDirectory=${inputs.workingDirectory}`] : []),
  ...(inputs.extraArgs ? parseExtraArgs(inputs.extraArgs) : []),
  ...(inputs.preDeploymentReportName ? [`-reportFilename=${inputs.preDeploymentReportName}`] : []),
];

const runCheckChanges = async (inputs: FlywayStatePrepareInputs, edition: FlywayEdition) => {
  if (edition !== "enterprise") {
    core.info(
      `Skipping deployment changes report: not available in ${edition === "community" ? "Community" : "Teams"} edition`,
    );
    return undefined;
  }
  if (inputs.skipDeploymentChangesReport) {
    core.info('Skipping deployment changes report: "skip-deployment-changes-report" set to true');
    return undefined;
  }
  return checkForChanges(getChangesArgs(inputs), inputs.workingDirectory);
};

export { runCheckChanges };
