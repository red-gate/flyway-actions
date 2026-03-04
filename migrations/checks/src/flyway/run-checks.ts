import type { ProvisionedDatabase } from "../docker/provision-build-database.js";
import type { FlywayMigrationsChecksInputs } from "../types.js";
import type { FlywayEdition } from "@flyway-actions/shared";
import * as core from "@actions/core";
import { resolvePath } from "@flyway-actions/shared";
import { hasBuildInputs } from "./arg-builders.js";
import { runCheckChanges } from "./check-changes.js";
import { runCheckCode } from "./check-code.js";
import { runCheckDrift } from "./check-drift.js";
import { runCheckDryrun } from "./check-dryrun.js";

const maybeProvisionBuildDatabase = async (
  inputs: FlywayMigrationsChecksInputs,
  edition: FlywayEdition,
): Promise<ProvisionedDatabase | undefined> => {
  if (hasBuildInputs(inputs)) {
    return undefined;
  }
  if (edition !== "enterprise") {
    return undefined;
  }
  if (inputs.skipDeploymentChangesReport) {
    return undefined;
  }
  if (!inputs.targetUrl) {
    return undefined;
  }

  try {
    const { provisionBuildDatabase } = await import("../docker/provision-build-database.js");
    return await provisionBuildDatabase(inputs.targetUrl);
  } catch (err) {
    core.warning(`Failed to auto-provision build database: ${err}`);
    return undefined;
  }
};

const runChecks = async (inputs: FlywayMigrationsChecksInputs, edition: FlywayEdition): Promise<void> => {
  const provisioner = await maybeProvisionBuildDatabase(inputs, edition);

  try {
    const effectiveInputs: FlywayMigrationsChecksInputs = provisioner
      ? {
          ...inputs,
          buildUrl: provisioner.jdbcUrl,
          buildUser: provisioner.user,
          buildPassword: provisioner.password,
          buildOkToErase: true,
        }
      : inputs;

    const results = [
      await runCheckDryrun(effectiveInputs, edition),
      await runCheckCode(effectiveInputs),
      await runCheckDrift(effectiveInputs, edition),
      await runCheckChanges(effectiveInputs, edition),
    ];

    const reportFile = results.find((r) => r?.reportPath)?.reportPath;
    core.setOutput("report-path", resolvePath(reportFile ?? "report.html", inputs.workingDirectory));

    const failed = results.find((r) => r !== undefined && r.exitCode !== 0);
    core.setOutput("exit-code", (failed?.exitCode ?? 0).toString());

    if (failed) {
      throw new Error("Flyway checks failed");
    }
  } finally {
    if (provisioner) {
      await provisioner.cleanup();
    }
  }
};

export { runChecks };
