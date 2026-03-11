type FlywayStatePrepareInputs = {
  targetEnvironment?: string;
  targetUrl?: string;
  targetUser?: string;
  targetPassword?: string;
  targetSchemas?: string;
  generateUndo?: boolean;
  workingDirectory?: string;
  extraArgs?: string;
};

export type { FlywayStatePrepareInputs };
