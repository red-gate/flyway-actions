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
  deploymentReportName?: string;
  saveSnapshot?: boolean;
};

export type { FlywayStateDeploymentInputs };
