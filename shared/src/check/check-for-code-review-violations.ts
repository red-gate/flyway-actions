import * as core from "@actions/core";
import { parseOutput, runFlyway } from "../flyway-runner.js";

type CodeResultItem = { violations?: { code?: string }[] };

type CodeReviewSuccessOutput = {
  htmlReport?: string;
  sarifReport?: string;
  individualResults?: { operation?: string; results?: CodeResultItem[] }[];
};

type CodeReviewErrorOutput = {
  error?: {
    errorCode?: string;
    message?: string;
    results?: CodeResultItem[];
    htmlReport?: string;
    sarifReport?: string;
  };
};

type CheckForCodeReviewResult = {
  exitCode: number;
  result: {
    reportPath?: string;
    sarifReportPath?: string;
    violationCount: number;
    violationCodes: string[];
  };
};

const checkForCodeReviewViolations = async (
  args: string[],
  workingDirectory?: string,
): Promise<CheckForCodeReviewResult> => {
  core.startGroup("Running code review");
  try {
    const result = await runFlyway(args, workingDirectory);

    if (result.exitCode !== 0) {
      const errorOutput = parseOutput<CodeReviewErrorOutput>(result.stdout);
      errorOutput?.error?.message && core.error(errorOutput.error.message);
      const violations = extractViolations(errorOutput?.error?.results ?? []);
      return {
        exitCode: result.exitCode,
        result: {
          reportPath: errorOutput?.error?.htmlReport,
          sarifReportPath: errorOutput?.error?.sarifReport,
          ...violations,
        },
      };
    }

    const output = parseOutput<CodeReviewSuccessOutput>(result.stdout);
    const codeResults = output?.individualResults?.filter((r) => r.operation === "code");
    const resultItems = codeResults?.flatMap((r) => r.results ?? []) ?? [];
    const violations = extractViolations(resultItems);
    return {
      exitCode: result.exitCode,
      result: { reportPath: output?.htmlReport, sarifReportPath: output?.sarifReport, ...violations },
    };
  } finally {
    core.endGroup();
  }
};

const extractViolations = (results: CodeResultItem[]): { violationCount: number; violationCodes: string[] } => {
  const codes = results
    .flatMap((r) => r.violations ?? [])
    .map((v) => v.code)
    .filter((c): c is string => !!c);
  return { violationCount: codes.length, violationCodes: [...new Set(codes)] };
};

export { checkForCodeReviewViolations };
