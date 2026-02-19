import type { FlywayMigrationsDeploymentInputs, FlywayMigrationsDeploymentOutputs } from "../types.js";
import * as core from "@actions/core";
import { runFlyway } from "@flyway-actions/shared";
import { getCommonArgs } from "./arg-builders.js";

const getMigrateArgs = (inputs: FlywayMigrationsDeploymentInputs): string[] => {
  const args: string[] = ["migrate", ...getCommonArgs(inputs)];

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

    if (result.stderr) {
      core.error(result.stderr);
    }

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

const extractSchemaVersion = (stdout: string): string => {
  const finalVersionMatch = stdout.match(/now\s+at\s+version\s+v?(\d+(?:\.\d+)*)/i);
  if (finalVersionMatch) {
    return finalVersionMatch[1];
  }

  const versionMatch = stdout.match(
    /(?:Schema\s+version|Current\s+version\s+of\s+schema(?:\s+"[^"]*")?):\s*v?(\d+(?:\.\d+)*)/i,
  );
  if (versionMatch) {
    return versionMatch[1];
  }

  return "unknown";
};

const parseFlywayOutput = (stdout: string): { migrationsApplied: number; schemaVersion: string } => {
  let migrationsApplied = 0;
  let schemaVersion = extractSchemaVersion(stdout);

  const migrationsMatch = stdout.match(/Successfully\s+applied\s+(\d+)\s+migration/i);
  if (migrationsMatch) {
    migrationsApplied = parseInt(migrationsMatch[1], 10);
  }

  try {
    const jsonMatch = stdout.match(/\{[\s\S]*"schemaVersion"[\s\S]*}/);
    if (jsonMatch) {
      const json = JSON.parse(jsonMatch[0]);
      if (json.migrationsExecuted !== undefined) {
        migrationsApplied = json.migrationsExecuted;
      }
      if (json.schemaVersion) {
        schemaVersion = json.schemaVersion;
      }
    }
  } catch {
    // JSON parsing failed, continue with regex results
  }

  return { migrationsApplied, schemaVersion };
};

export { getMigrateArgs, migrate, parseFlywayOutput };
