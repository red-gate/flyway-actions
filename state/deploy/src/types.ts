type FlywayStateDeploymentInputs = {
  scriptPath?: string;
  targetEnvironment?: string;
  targetUrl?: string;
  targetUser?: string;
  targetPassword?: string;
  targetSchemas?: string;
  skipDriftCheck?: boolean;
  skipSnapshot?: boolean;
  provisionMode?: string;
  workingDirectory?: string;
  extraArgs?: string;
  deploymentReportName?: string;
};

export type { FlywayStateDeploymentInputs };
