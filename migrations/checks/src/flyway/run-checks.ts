import type { FlywayMigrationsChecksInputs } from "../types.js";
import type { FlywayEdition } from "@flyway-actions/shared";
import * as core from "@actions/core";
import { runChangesCheck } from "./check-changes.js";
import { runCodeCheck } from "./check-code.js";
import { runDriftCheck } from "./check-drift.js";
import { runDryrunCheck } from "./check-dryrun.js";

const runChecks = async (inputs: FlywayMigrationsChecksInputs, edition: FlywayEdition): Promise<void> => {
  const results = [
    await runDryrunCheck(inputs, edition),
    await runCodeCheck(inputs),
    await runDriftCheck(inputs, edition),
    await runChangesCheck(inputs, edition),
  ];

  const failed = results.find((r) => r !== undefined && r.exitCode !== 0);
  core.setOutput("exit-code", (failed?.exitCode ?? 0).toString());

  if (failed) {
    throw new Error("Flyway checks failed");
  }
};

export { runChecks };
