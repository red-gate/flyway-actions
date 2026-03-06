import type { FlywayMigrationsUndoInputs, FlywayUndoOutput } from "../types.js";
import * as core from "@actions/core";
import { parseErrorOutput, runFlyway } from "@flyway-actions/shared/flyway-runner";
import { getCommonArgs } from "./arg-builders.js";

const getUndoArgs = (inputs: FlywayMigrationsUndoInputs): string[] => {
  const args: string[] = ["undo", ...getCommonArgs(inputs)];
  if (inputs.targetMigrationVersion) {
    args.push(`-target=${inputs.targetMigrationVersion}`);
  }
  if (inputs.cherryPick) {
    args.push(`-cherryPick=${inputs.cherryPick}`);
  }
  if (inputs.saveSnapshot) {
    args.push("-undo.saveSnapshot=true");
  }
  return args;
};

type UndoResult = { migrationsUndone: number; schemaVersion: string };

const undo = async (inputs: FlywayMigrationsUndoInputs): Promise<UndoResult> => {
  core.startGroup("Running undo");
  try {
    const args = getUndoArgs(inputs);
    const result = await runFlyway(args, inputs.workingDirectory);

    if (result.exitCode !== 0) {
      const errorOutput = parseErrorOutput(result.stdout);
      if (errorOutput?.error?.errorCode === "COMPARISON_DATABASE_NOT_SUPPORTED") {
        core.info(
          "No snapshot was generated or stored in the target database as snapshots are not supported for this database type.",
        );
        setOutput(0);
        return { migrationsUndone: 0, schemaVersion: "unknown" };
      }
      errorOutput?.error?.message && core.error(errorOutput.error.message);
      setOutput(result.exitCode);
      throw new Error(`Flyway undo failed with exit code ${result.exitCode}`);
    }

    const { migrationsUndone, schemaVersion } = parseFlywayOutput(result.stdout);
    setOutput(result.exitCode, migrationsUndone, schemaVersion);
    return { migrationsUndone, schemaVersion };
  } finally {
    core.endGroup();
  }
};

const parseFlywayOutput = (stdout: string): { migrationsUndone: number; schemaVersion: string } => {
  try {
    const json = JSON.parse(stdout) as FlywayUndoOutput;
    return { migrationsUndone: json.migrationsUndone ?? 0, schemaVersion: json.targetSchemaVersion ?? "unknown" };
  } catch {
    return { migrationsUndone: 0, schemaVersion: "unknown" };
  }
};

const setOutput = (exitCode: number, migrationsUndone?: number, schemaVersion?: string) => {
  core.setOutput("exit-code", exitCode.toString());
  migrationsUndone !== undefined && core.setOutput("migrations-undone", migrationsUndone.toString());
  schemaVersion !== undefined && core.setOutput("schema-version", schemaVersion);
};

export { getUndoArgs, parseFlywayOutput, undo };
export type { UndoResult };
