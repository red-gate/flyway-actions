type FlywayMigrationsChecksInputs = {
  targetEnvironment?: string;
  targetUrl?: string;
  targetUser?: string;
  targetPassword?: string;
  targetSchemas?: string;
  targetMigrationVersion?: string;
  cherryPick?: string;
  buildEnvironment?: string;
  buildUrl?: string;
  buildUser?: string;
  buildPassword?: string;
  buildSchemas?: string;
  buildOkToErase?: boolean;
  skipCodeReview?: boolean;
  skipDriftCheck?: boolean;
  skipDeploymentChangesReport?: boolean;
  skipDeploymentScriptReview?: boolean;
  failOnCodeReview?: boolean;
  failOnDrift?: boolean;
  workingDirectory?: string;
  extraArgs?: string;
  skipHtmlReportUpload: boolean;
  reportRetentionDays: number;
  reportName: string;
};

export type { FlywayMigrationsChecksInputs };
