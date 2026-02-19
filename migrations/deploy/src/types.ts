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

type FlywayMigrateOutput = { migrationsExecuted?: number; targetSchemaVersion?: string };

export type { FlywayMigrateOutput, FlywayMigrationsDeploymentInputs, FlywayMigrationsDeploymentOutputs };
