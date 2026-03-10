import type { FlywayMigrationsUndoInputs } from "../types.js";
import { checkForDrift as sharedCheckForDrift } from "@flyway-actions/shared/check-for-drift";
import { getCommonArgs } from "./arg-builders.js";

const checkForDrift = (inputs: FlywayMigrationsUndoInputs) =>
  sharedCheckForDrift(getCommonArgs(inputs), inputs.workingDirectory, inputs.driftReportName);

export { checkForDrift };
