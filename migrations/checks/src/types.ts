type FlywayMigrationsChecksInputs = {
  targetEnvironment?: string;
  targetUrl?: string;
  targetUser?: string;
  targetPassword?: string;
  targetSchemas?: string;
  targetMigrationVersion?: string;
  cherryPick?: string;
  failOnCodeReview?: boolean;
  workingDirectory?: string;
  extraArgs?: string;
};

export type { FlywayMigrationsChecksInputs };
