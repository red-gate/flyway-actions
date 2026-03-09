type FlywayStateDeploymentInputs = {
  scriptPath?: string;
  targetEnvironment?: string;
  targetUrl?: string;
  targetUser?: string;
  targetPassword?: string;
  targetSchemas?: string;
  skipDriftCheck?: boolean;
  workingDirectory?: string;
  extraArgs?: string;
  driftReportName?: string;
  saveSnapshot?: boolean;
};

export type { FlywayStateDeploymentInputs };
