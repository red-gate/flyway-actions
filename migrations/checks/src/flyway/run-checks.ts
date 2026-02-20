import type { Changes, Code, Drift, FlywayCheckOutput, FlywayMigrationsChecksInputs } from "../types.js";
import type { FlywayEdition } from "@flyway-actions/shared";
import * as core from "@actions/core";
import { parseErrorOutput, runFlyway } from "@flyway-actions/shared";
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
  return ["-code", ...(inputs.failOnCodeReview ? ["-check.code.failOnError=true"] : [])];
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
    "-outputType=json",
    "-outputLogsInJson=true",
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

const runChecks = async (inputs: FlywayMigrationsChecksInputs, edition: FlywayEdition): Promise<void> => {
  core.startGroup("Running Flyway checks");
  try {
    const args = getCheckArgs(inputs, edition);
    const result = await runFlyway(args, inputs.workingDirectory);

    const checkOutput = parseCheckOutput(result.stdout);
    setOutputs(checkOutput, result.exitCode);

    if (result.exitCode !== 0) {
      const errorOutput = parseErrorOutput(result.stdout);
      if (errorOutput?.error?.message?.includes("configure a provisioner") && !inputs.buildOkToErase) {
        core.error(
          'The build database needs to be erasable. Set the "build-ok-to-erase" input to "true" to allow Flyway to erase the build database. Note that this will drop all schema objects and data from the database.',
        );
      }
      throw new Error("Flyway checks failed");
    }
  } finally {
    core.endGroup();
  }
};

const parseCheckOutput = (stdout: string): FlywayCheckOutput | undefined => {
  try {
    return JSON.parse(stdout) as FlywayCheckOutput;
  } catch {
    return undefined;
  }
};

const setOutputs = (output: FlywayCheckOutput | undefined, exitCode: number): void => {
  core.setOutput("exit-code", exitCode.toString());

  const driftResults = output?.individualResults?.filter((r): r is Drift => r.operation === "drift");
  const changesResults = output?.individualResults?.filter((r): r is Changes => r.operation === "changes");
  const codeResults = output?.individualResults?.filter((r): r is Code => r.operation === "code");

  if (driftResults?.length) {
    const drift = driftResults.some((r) => r.onlyInSource?.length || r.onlyInTarget?.length || r.differences?.length);
    core.setOutput("drift-detected", drift.toString());
  }

  if (changesResults?.length) {
    const changes = changesResults.reduce(
      (acc, r) => acc + (r.onlyInSource?.length ?? 0) + (r.onlyInTarget?.length ?? 0) + (r.differences?.length ?? 0),
      0,
    );
    core.setOutput("changed-object-count", changes.toString());
  }

  if (codeResults?.length) {
    const violations = codeResults.flatMap((r) => r.results?.flatMap((v) => v.violations ?? []) ?? []);
    const codes = violations.map((v) => v.code).filter((c): c is string => !!c);
    core.setOutput("code-violation-count", codes.length.toString());
    core.setOutput("code-violation-codes", [...new Set(codes)].join(","));
  }
};

export { getCheckArgs, parseCheckOutput, runChecks, setOutputs };
