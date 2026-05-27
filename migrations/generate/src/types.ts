type CommitInputs = {
  migrations: boolean;
  message: string;
  userName: string;
  userEmail: string;
  branch?: string;
};

type FlywayCommandInputs = {
  source?: string;
  migrationTypes?: string;
  migrationDescription?: string;
  buildEnvironment?: string;
  buildUrl?: string;
  buildUser?: string;
  buildPassword?: string;
  buildSchemas?: string;
  workingDirectory?: string;
  extraArgs?: string;
};

type FlywayMigrationsGenerateInputs = FlywayCommandInputs & { commit: CommitInputs };

export type { CommitInputs, FlywayCommandInputs, FlywayMigrationsGenerateInputs };
