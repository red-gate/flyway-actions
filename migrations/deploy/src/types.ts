import type { FlywayDetails, FlywayEdition, FlywayRunResult } from "@flyway-actions/shared";

type FlywayMigrationsDeploymentInputs = {
  targetEnvironment?: string;
  targetUrl?: string;
  targetUser?: string;
  targetPassword?: string;
  targetSchemas?: string;
  targetMigrationVersion?: string;
  cherryPick?: string;
  skipDriftCheck?: boolean;
  workingDirectory?: string;
  extraArgs?: string;
  saveSnapshot?: boolean;
};

type FlywayMigrationsDeploymentOutputs = {
  exitCode: number;
  migrationsApplied: number;
  schemaVersion: string;
};

export type {
  FlywayDetails,
  FlywayEdition,
  FlywayMigrationsDeploymentInputs,
  FlywayMigrationsDeploymentOutputs,
  FlywayRunResult,
};
