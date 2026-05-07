const MIN_FLYWAY_VERSION = "12.0.0";

type ParsedVersion = { major: number; minor: number; patch: number };

const parseVersion = (version: string): ParsedVersion | undefined => {
  const match = /^(\d+)\.(\d+)\.(\d+)/.exec(version.trim());
  if (!match) {
    return undefined;
  }
  return { major: Number(match[1]), minor: Number(match[2]), patch: Number(match[3]) };
};

const compareVersions = (a: ParsedVersion, b: ParsedVersion): number => {
  if (a.major !== b.major) {
    return a.major - b.major;
  }
  if (a.minor !== b.minor) {
    return a.minor - b.minor;
  }
  return a.patch - b.patch;
};

const meetsMinimumVersion = (actual: string): boolean => {
  const actualParsed = parseVersion(actual);
  const minimumParsed = parseVersion(MIN_FLYWAY_VERSION);
  if (!actualParsed || !minimumParsed) {
    return false;
  }
  return compareVersions(actualParsed, minimumParsed) >= 0;
};

const getVersionError = (actual: string): string | undefined => {
  if (meetsMinimumVersion(actual)) {
    return undefined;
  }
  const reportedVersion = actual.trim() || "unknown";
  return `Flyway version ${reportedVersion} is below the minimum required version ${MIN_FLYWAY_VERSION}. Please upgrade Flyway.`;
};

export { getVersionError };
