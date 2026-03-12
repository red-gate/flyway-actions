type FlywayStatePrepareInputs = {
  targetEnvironment?: string;
  targetUrl?: string;
  targetUser?: string;
  targetPassword?: string;
  targetSchemas?: string;
  generateUndo?: boolean;
  failOnDrift?: boolean;
  skipDriftCheck?: boolean;
  workingDirectory?: string;
  extraArgs?: string;
  driftReportName?: string;
};

export type { FlywayStatePrepareInputs };
