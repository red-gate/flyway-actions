import type { FlywayMigrateOutput, FlywayMigrationsDeploymentInputs, Migration } from "../types.js";
import type { ErrorOutput } from "@flyway-actions/shared/types";
import * as core from "@actions/core";
import { parseOutput, runFlyway } from "@flyway-actions/shared/flyway-runner";
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
  if (!inputs.skipSnapshot) {
    args.push("-migrate.saveSnapshot=true");
  }
  return args;
};

type MigrateResult = { migrationsApplied: number; schemaVersion: string; migrations: Required<Migration>[] };

const migrate = async (inputs: FlywayMigrationsDeploymentInputs): Promise<MigrateResult> => {
  core.startGroup("Running migrations");
  try {
    const args = getMigrateArgs(inputs);
    const result = await runFlyway(args, inputs.workingDirectory);

    if (result.exitCode !== 0) {
      const errorOutput = parseOutput<ErrorOutput>(result.stdout);
      if (errorOutput?.error?.errorCode === "COMPARISON_DATABASE_NOT_SUPPORTED") {
        core.info(
          "No snapshot was generated or stored in the target database as snapshots are not supported for this database type.",
        );
        setOutput(0);
        return { migrationsApplied: 0, schemaVersion: "unknown", migrations: [] };
      }
      errorOutput?.error?.message && core.error(errorOutput.error.message);
      setOutput(result.exitCode);
      throw new Error(`Flyway migrate failed with exit code ${result.exitCode}`);
    }

    const { migrationsApplied, schemaVersion, migrations } = parseFlywayOutput(result.stdout);
    setOutput(result.exitCode, migrationsApplied, schemaVersion);
    return { migrationsApplied, schemaVersion, migrations };
  } finally {
    core.endGroup();
  }
};

const parseFlywayOutput = (stdout: string): MigrateResult => {
  const json = parseOutput<FlywayMigrateOutput>(stdout);
  const migrations: Required<Migration>[] = (json?.migrations ?? []).map((m) => ({
    category: m.category ?? "unknown",
    version: m.version ?? "",
    description: m.description ?? "",
    type: m.type ?? "unknown",
    filepath: m.filepath ?? "",
    executionTime: m.executionTime ?? 0,
  }));
  return {
    migrationsApplied: json?.migrationsExecuted ?? 0,
    schemaVersion: json?.targetSchemaVersion ?? "unknown",
    migrations,
  };
};

const setOutput = (exitCode: number, migrationsApplied?: number, schemaVersion?: string) => {
  core.setOutput("exit-code", exitCode.toString());
  migrationsApplied !== undefined && core.setOutput("migrations-applied", migrationsApplied.toString());
  schemaVersion !== undefined && core.setOutput("schema-version", schemaVersion);
};

export { getMigrateArgs, migrate, parseFlywayOutput };
export type { MigrateResult };
