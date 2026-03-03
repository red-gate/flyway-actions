type FlywayMigrationsDeploymentInputs = {
  targetEnvironment?: string;
  targetUrl?: string;
  targetUser?: string;
  targetPassword?: string;
  targetSchemas?: string;
  targetMigrationVersion?: string;
  cherryPick?: string;
  baselineOnMigrate?: boolean;
  skipDriftCheck?: boolean;
  workingDirectory?: string;
  extraArgs?: string;
  driftReportName?: string;
  saveSnapshot?: boolean;
};

type FlywayMigrateOutput = { migrationsExecuted?: number; targetSchemaVersion?: string };

export type { FlywayMigrateOutput, FlywayMigrationsDeploymentInputs };
