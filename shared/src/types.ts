type FlywayEdition = "community" | "teams" | "enterprise";

type FlywayDetails = { installed: false } | { installed: true; edition: FlywayEdition; version: string };

type FlywayRunResult = { exitCode: number; stdout: string; stderr: string };

type FlywayVersionOutput = { edition?: string; version?: string };

type JsonLogModel = { level?: "DEBUG" | "INFO" | "WARN" | "ERROR" | "NOTICE"; message?: string };

type ErrorCode =
  | "CHECK_BUILD_NO_PROVISIONER"
  | "CHECK_DRIFT_DETECTED"
  | "COMPARISON_DATABASE_NOT_SUPPORTED"
  | "DOCKER_EULA_NOT_ACCEPTED"
  | "DOCKER_NOT_INSTALLED"
  | "DOCKER_NOT_RUNNING";

type ErrorOutput = { error?: { errorCode?: ErrorCode; message?: string } };

export type { ErrorOutput, FlywayDetails, FlywayEdition, FlywayRunResult, FlywayVersionOutput, JsonLogModel };
