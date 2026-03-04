import type { FlywayMigrateOutput, FlywayMigrationsDeploymentInputs } from "../types.js";
import * as core from "@actions/core";
import { parseErrorOutput, runFlyway } from "@flyway-actions/shared";
import { getCommonArgs } from "./arg-builders.js";

const getMigrateArgs = (inputs: FlywayMigrationsDeploymentInputs): string[] => {
  const args: string[] = ["migrate", ...getCommonArgs(inputs)];

  if (inputs.targetMigrationVersion) {
    args.push(`-target=${inputs.targetMigrationVersion}`);
  }

  if (inputs.cherryPick) {
    args.push(`-cherryPick=${inputs.cherryPick}`);
  }

  if (inputs.baselineOnMigrate) {
    args.push("-baselineOnMigrate=true");
  }

  if (inputs.saveSnapshot) {
    args.push("-migrate.saveSnapshot=true");
  }

  return args;
};

const migrate = async (inputs: FlywayMigrationsDeploymentInputs): Promise<void> => {
  core.startGroup("Running migrations");
  try {
    const args = getMigrateArgs(inputs);
    const result = await runFlyway(args, inputs.workingDirectory);

    if (result.exitCode !== 0) {
      const errorOutput = parseErrorOutput(result.stdout);
      if (errorOutput?.error?.errorCode === "COMPARISON_DATABASE_NOT_SUPPORTED") {
        core.info(
          "No snapshot was generated or stored in the target database as snapshots are not supported for this database type.",
        );
        setOutput(0);
        return;
      }
      errorOutput?.error?.message && core.error(errorOutput.error.message);
      setOutput(result.exitCode);
      throw new Error(`Flyway migrate failed with exit code ${result.exitCode}`);
    }

    const { migrationsApplied, schemaVersion } = parseFlywayOutput(result.stdout);
    setOutput(result.exitCode, migrationsApplied, schemaVersion);
  } finally {
    core.endGroup();
  }
};

const parseFlywayOutput = (stdout: string): { migrationsApplied: number; schemaVersion: string } => {
  try {
    const json = JSON.parse(stdout) as FlywayMigrateOutput;
    return { migrationsApplied: json.migrationsExecuted ?? 0, schemaVersion: json.targetSchemaVersion ?? "unknown" };
  } catch {
    return { migrationsApplied: 0, schemaVersion: "unknown" };
  }
};

const setOutput = (exitCode: number, migrationsApplied?: number, schemaVersion?: string) => {
  core.setOutput("exit-code", exitCode.toString());
  migrationsApplied !== undefined && core.setOutput("migrations-applied", migrationsApplied.toString());
  schemaVersion !== undefined && core.setOutput("schema-version", schemaVersion);
};

export { getMigrateArgs, migrate, parseFlywayOutput };
