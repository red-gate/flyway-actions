import type { FlywayMigrationsDeploymentInputs } from "../types.js";
import { checkForDrift as sharedCheckForDrift } from "@flyway-actions/shared/check-for-drift";
import { getCommonArgs } from "./arg-builders.js";

const checkForDrift = (inputs: FlywayMigrationsDeploymentInputs) =>
  sharedCheckForDrift(getCommonArgs(inputs), inputs.workingDirectory, inputs.driftReportName);

export { checkForDrift };
