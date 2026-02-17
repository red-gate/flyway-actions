type FlywayMigrationsChecksInputs = {
  targetEnvironment?: string;
  targetUrl?: string;
  targetUser?: string;
  targetPassword?: string;
  targetSchemas?: string;
  targetMigrationVersion?: string;
  cherryPick?: string;
  workingDirectory?: string;
  extraArgs?: string;
};

export type { FlywayMigrationsChecksInputs };
