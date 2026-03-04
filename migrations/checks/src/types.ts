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
  preDeploymentReportName?: string;
  extraArgs?: string;
};

type Drift = {
  operation?: "drift";
  onlyInSource?: unknown[];
  onlyInTarget?: unknown[];
  differences?: unknown[];
  driftResolutionFolder?: string;
};

type Changes = { operation?: "changes"; onlyInSource?: unknown[]; onlyInTarget?: unknown[]; differences?: unknown[] };

type Code = {
  operation?: "code";
  results?: CodeResultItem[];
};

type Dryrun = { operation?: "dryrun" };

type FlywayCheckOutput = { htmlReport?: string; individualResults?: (Drift | Changes | Code | Dryrun)[] };

type CodeResultItem = { violations?: { code?: string }[] };

type CodeErrorOutput = {
  error?: { errorCode?: string; message?: string; results?: CodeResultItem[]; htmlReport?: string };
};

export type { Changes, Code, CodeErrorOutput, CodeResultItem, Drift, FlywayCheckOutput, FlywayMigrationsChecksInputs };
