type FlywayEdition = "community" | "teams" | "enterprise";

type FlywayDetails = { installed: false } | { installed: true; edition: FlywayEdition };

type FlywayRunResult = { exitCode: number; stdout: string; stderr: string };

type FlywayVersionOutput = { edition?: string };

type JsonLogModel = { level?: "DEBUG" | "INFO" | "WARN" | "ERROR" | "NOTICE"; message?: string };

type ErrorCode = "CHECK_BUILD_NO_PROVISIONER" | "CHECK_DRIFT_DETECTED" | "COMPARISON_DATABASE_NOT_SUPPORTED";

type ErrorOutput = { error?: { errorCode?: ErrorCode; message?: string } };

type DriftErrorOutput = { error?: ErrorOutput["error"] & { htmlReport?: string; driftResolutionFolderPath?: string } };

export type {
  DriftErrorOutput,
  ErrorOutput,
  FlywayDetails,
  FlywayEdition,
  FlywayRunResult,
  FlywayVersionOutput,
  JsonLogModel,
};
