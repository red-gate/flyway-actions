import type {
  FlywayMigrateOutput,
  FlywayMigrationsDeploymentInputs,
  FlywayMigrationsDeploymentOutputs,
} from "../types.js";
import * as core from "@actions/core";
import { runFlyway } from "@flyway-actions/shared";
import { getCommonArgs } from "./arg-builders.js";

const getMigrateArgs = (inputs: FlywayMigrationsDeploymentInputs): string[] => {
  const args: string[] = ["migrate", "-outputType=json", "-outputLogsInJson=true", ...getCommonArgs(inputs)];

  if (inputs.targetMigrationVersion) {
    args.push(`-target=${inputs.targetMigrationVersion}`);
  }

  if (inputs.cherryPick) {
    args.push(`-cherryPick=${inputs.cherryPick}`);
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

    const { migrationsApplied, schemaVersion } = parseFlywayOutput(result.stdout);
    setOutputs({ exitCode: result.exitCode, migrationsApplied, schemaVersion });

    if (result.exitCode !== 0) {
      throw new Error(`Flyway migrate failed with exit code ${result.exitCode}`);
    }
  } finally {
    core.endGroup();
  }
};

const setOutputs = (outputs: FlywayMigrationsDeploymentOutputs): void => {
  core.setOutput("exit-code", outputs.exitCode.toString());
  core.setOutput("migrations-applied", outputs.migrationsApplied.toString());
  core.setOutput("schema-version", outputs.schemaVersion);
};

const parseFlywayOutput = (stdout: string): { migrationsApplied: number; schemaVersion: string } => {
  try {
    const json = JSON.parse(stdout) as FlywayMigrateOutput;
    return { migrationsApplied: json.migrationsExecuted ?? 0, schemaVersion: json.targetSchemaVersion ?? "unknown" };
  } catch {
    return { migrationsApplied: 0, schemaVersion: "unknown" };
  }
};

export { getMigrateArgs, migrate, parseFlywayOutput };
