type FlywayStatePrepareInputs = {
  targetEnvironment?: string;
  targetUrl?: string;
  targetUser?: string;
  targetPassword?: string;
  targetSchemas?: string;
  generateUndo?: boolean;
  failOnDrift?: boolean;
  failOnCodeReview?: boolean;
  skipDriftCheck?: boolean;
  skipCodeReview?: boolean;
  skipDeploymentChangesReport?: boolean;
  workingDirectory?: string;
  extraArgs?: string;
  preDeploymentReportName?: string;
  deploymentScriptName?: string;
  undoScriptName?: string;
};

export type { FlywayStatePrepareInputs };
