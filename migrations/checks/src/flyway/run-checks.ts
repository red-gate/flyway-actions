import type { FlywayMigrationsChecksInputs } from "../types.js";
import type { FlywayEdition } from "@flyway-actions/shared";
import * as core from "@actions/core";
import { runFlyway } from "@flyway-actions/shared";
import { getBaseArgs, getBuildEnvironmentArgs, getTargetEnvironmentArgs, hasBuildInputs } from "./arg-builders.js";

const getCheckDryrunArgs = (inputs: FlywayMigrationsChecksInputs, edition: FlywayEdition): string[] => {
  if (edition === "community") {
    core.info("Skipping deployment script review: not available in Community edition");
    return [];
  }

  if (inputs.skipDeploymentScriptReview) {
    core.info('Skipping deployment script review: "skip-deployment-script-review" set to true');
    return [];
  }

  return ["-dryrun"];
};

const getCheckCodeArgs = (inputs: FlywayMigrationsChecksInputs): string[] => {
  if (inputs.skipCodeReview) {
    core.info('Skipping code review: "skip-code-review" set to true');
    return [];
  }

  return ["-code", ...(inputs.failOnCodeReview ? ["-check.failOnError=true"] : [])];
};

const getCheckDriftArgs = (inputs: FlywayMigrationsChecksInputs, edition: FlywayEdition): string[] => {
  if (edition !== "enterprise") {
    core.info(`Skipping drift check: not available in ${edition === "community" ? "Community" : "Teams"} edition`);
    return [];
  }

  if (inputs.skipDriftCheck) {
    core.info('Skipping drift check: "skip-drift-check" set to true');
    return [];
  }

  return ["-drift", ...(inputs.failOnDrift ? ["-check.failOnDrift=true"] : [])];
};

const getCheckChangesArgs = (inputs: FlywayMigrationsChecksInputs, edition: FlywayEdition): string[] => {
  if (edition !== "enterprise") {
    core.info(
      `Skipping deployment changes report: not available in ${edition === "community" ? "Community" : "Teams"} edition`,
    );
    return [];
  }

  if (inputs.skipDeploymentChangesReport && hasBuildInputs(inputs)) {
    core.info('Skipping deployment changes report: "skip-deployment-changes-report" set to true');
    return [];
  }

  if (!hasBuildInputs(inputs)) {
    core.info('Skipping deployment changes report: no "build-environment" or "build-url" provided');
    return [];
  }

  return ["-changes", ...getBuildEnvironmentArgs(inputs)];
};

const getCheckArgs = (inputs: FlywayMigrationsChecksInputs, edition: FlywayEdition): string[] => {
  const args = [
    "check",
    ...getCheckDryrunArgs(inputs, edition),
    ...getCheckCodeArgs(inputs),
    ...getCheckDriftArgs(inputs, edition),
    ...getCheckChangesArgs(inputs, edition),
    ...getTargetEnvironmentArgs(inputs),
    ...getBaseArgs(inputs),
  ];

  if (inputs.targetMigrationVersion) {
    args.push(`-target=${inputs.targetMigrationVersion}`);
  }

  if (inputs.cherryPick) {
    args.push(`-cherryPick=${inputs.cherryPick}`);
  }

  return args;
};

const runChecks = async (inputs: FlywayMigrationsChecksInputs, edition: FlywayEdition): Promise<number> => {
  core.startGroup("Running Flyway checks");
  try {
    const args = getCheckArgs(inputs, edition);
    const result = await runFlyway(args, inputs.workingDirectory);

    if (result.stderr?.includes("configure a provisioner") && !inputs.buildOkToErase) {
      core.error(
        'The build database needs to be erasable. Set the "build-ok-to-erase" input to true to allow Flyway to clean the build database before use. Note that this will drop all schema objects and data from the database.',
      );
    } else if (result.stderr) {
      core.error(result.stderr);
    }

    return result.exitCode;
  } finally {
    core.endGroup();
  }
};

export { getCheckArgs, runChecks };
