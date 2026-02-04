import * as core from '@actions/core';
import { FlywayMigrateInputs, InputDefinition } from './types.js';

/**
 * Map of input names to Flyway argument names and types
 */
export const INPUT_DEFINITIONS: InputDefinition[] = [
  // Connection
  { inputName: 'url', flywayArg: 'url', type: 'string', isSecret: false },
  { inputName: 'user', flywayArg: 'user', type: 'string', isSecret: false },
  { inputName: 'password', flywayArg: 'password', type: 'string', isSecret: true },
  { inputName: 'driver', flywayArg: 'driver', type: 'string' },
  { inputName: 'connect-retries', flywayArg: 'connectRetries', type: 'number' },
  { inputName: 'connect-retries-interval', flywayArg: 'connectRetriesInterval', type: 'number' },
  { inputName: 'init-sql', flywayArg: 'initSql', type: 'string' },

  // General
  { inputName: 'locations', flywayArg: 'locations', type: 'string' },
  { inputName: 'schemas', flywayArg: 'schemas', type: 'string' },
  { inputName: 'default-schema', flywayArg: 'defaultSchema', type: 'string' },
  { inputName: 'table', flywayArg: 'table', type: 'string' },
  { inputName: 'tablespace', flywayArg: 'tablespace', type: 'string' },
  { inputName: 'target', flywayArg: 'target', type: 'string' },

  // Behavior
  { inputName: 'baseline-on-migrate', flywayArg: 'baselineOnMigrate', type: 'boolean' },
  { inputName: 'baseline-version', flywayArg: 'baselineVersion', type: 'string' },
  { inputName: 'baseline-description', flywayArg: 'baselineDescription', type: 'string' },
  { inputName: 'out-of-order', flywayArg: 'outOfOrder', type: 'boolean' },
  { inputName: 'validate-on-migrate', flywayArg: 'validateOnMigrate', type: 'boolean' },
  { inputName: 'validate-migration-naming', flywayArg: 'validateMigrationNaming', type: 'boolean' },
  { inputName: 'mixed', flywayArg: 'mixed', type: 'boolean' },
  { inputName: 'group', flywayArg: 'group', type: 'boolean' },
  { inputName: 'installed-by', flywayArg: 'installedBy', type: 'string' },
  { inputName: 'skip-executing-migrations', flywayArg: 'skipExecutingMigrations', type: 'boolean' },

  // Teams/Enterprise
  { inputName: 'cherry-pick', flywayArg: 'cherryPick', type: 'string' },
  { inputName: 'dry-run-output', flywayArg: 'dryRunOutput', type: 'string' },
  { inputName: 'batch', flywayArg: 'batch', type: 'boolean' },
  { inputName: 'stream', flywayArg: 'stream', type: 'boolean' },
  { inputName: 'error-overrides', flywayArg: 'errorOverrides', type: 'string' },
  { inputName: 'fail-on-missing-target', flywayArg: 'failOnMissingTarget', type: 'boolean' },

  // Placeholders
  { inputName: 'placeholder-replacement', flywayArg: 'placeholderReplacement', type: 'boolean' },
  { inputName: 'placeholder-prefix', flywayArg: 'placeholderPrefix', type: 'string' },
  { inputName: 'placeholder-suffix', flywayArg: 'placeholderSuffix', type: 'string' },
  { inputName: 'placeholder-separator', flywayArg: 'placeholderSeparator', type: 'string' },
  { inputName: 'placeholders', flywayArg: 'placeholders', type: 'placeholders' },
  { inputName: 'script-placeholder-prefix', flywayArg: 'scriptPlaceholderPrefix', type: 'string' },
  { inputName: 'script-placeholder-suffix', flywayArg: 'scriptPlaceholderSuffix', type: 'string' },

  // Migration naming
  { inputName: 'sql-migration-prefix', flywayArg: 'sqlMigrationPrefix', type: 'string' },
  { inputName: 'sql-migration-separator', flywayArg: 'sqlMigrationSeparator', type: 'string' },
  { inputName: 'sql-migration-suffixes', flywayArg: 'sqlMigrationSuffixes', type: 'string' },
  {
    inputName: 'repeatable-sql-migration-prefix',
    flywayArg: 'repeatableSqlMigrationPrefix',
    type: 'string',
  },
  { inputName: 'undo-sql-migration-prefix', flywayArg: 'undoSqlMigrationPrefix', type: 'string' },

  // Secrets - Vault
  { inputName: 'vault-url', flywayArg: 'vault.url', type: 'string' },
  { inputName: 'vault-token', flywayArg: 'vault.token', type: 'string', isSecret: true },
  { inputName: 'vault-secrets', flywayArg: 'vault.secrets', type: 'string' },

  // Secrets - GCSM
  { inputName: 'gcsm-project', flywayArg: 'gcsm.project', type: 'string' },
  { inputName: 'gcsm-secrets', flywayArg: 'gcsm.secrets', type: 'string' },

  // Secrets - Dapr
  { inputName: 'dapr-url', flywayArg: 'dapr.url', type: 'string' },
  { inputName: 'dapr-secrets', flywayArg: 'dapr.secrets', type: 'string' },

  // Database-specific - Oracle
  { inputName: 'oracle-sqlplus', flywayArg: 'oracle.sqlplus', type: 'boolean' },
  { inputName: 'oracle-sqlplus-warn', flywayArg: 'oracle.sqlplusWarn', type: 'boolean' },
  { inputName: 'oracle-wallet-location', flywayArg: 'oracle.walletLocation', type: 'string' },
  {
    inputName: 'oracle-kerberos-cache-file',
    flywayArg: 'oracle.kerberosCacheFile',
    type: 'string',
  },

  // Database-specific - PostgreSQL
  {
    inputName: 'postgresql-transactional-lock',
    flywayArg: 'postgresql.transactional.lock',
    type: 'boolean',
  },

  // Database-specific - SQL Server
  {
    inputName: 'sqlserver-kerberos-login-file',
    flywayArg: 'sqlserver.kerberosLoginFile',
    type: 'string',
  },

  // Advanced
  { inputName: 'config-files', flywayArg: 'configFiles', type: 'string' },
  { inputName: 'jar-dirs', flywayArg: 'jarDirs', type: 'string' },
  { inputName: 'encoding', flywayArg: 'encoding', type: 'string' },
  { inputName: 'callbacks', flywayArg: 'callbacks', type: 'string' },
  { inputName: 'loggers', flywayArg: 'loggers', type: 'string' },
  { inputName: 'output-type', flywayArg: 'outputType', type: 'string' },
  { inputName: 'color', flywayArg: 'color', type: 'boolean' },
  { inputName: 'edition', flywayArg: 'edition', type: 'string' },
  { inputName: 'environment', flywayArg: 'environment', type: 'string' },
  { inputName: 'detect-encoding', flywayArg: 'detectEncoding', type: 'boolean' },
  { inputName: 'execute-in-transaction', flywayArg: 'executeInTransaction', type: 'boolean' },
  { inputName: 'lock-retry-count', flywayArg: 'lockRetryCount', type: 'number' },
  { inputName: 'fail-on-missing-locations', flywayArg: 'failOnMissingLocations', type: 'boolean' },
  { inputName: 'report-filename', flywayArg: 'reportFilename', type: 'string' },
  { inputName: 'report-enabled', flywayArg: 'reportEnabled', type: 'boolean' },
  { inputName: 'skip-default-callbacks', flywayArg: 'skipDefaultCallbacks', type: 'boolean' },
  { inputName: 'skip-default-resolvers', flywayArg: 'skipDefaultResolvers', type: 'boolean' },
  { inputName: 'clean-disabled', flywayArg: 'cleanDisabled', type: 'boolean' },
  { inputName: 'clean-on-validation-error', flywayArg: 'cleanOnValidationError', type: 'boolean' },
  {
    inputName: 'community-db-support-enabled',
    flywayArg: 'communityDBSupportEnabled',
    type: 'boolean',
  },
];

/**
 * Parse boolean input from string
 */
export function parseBoolean(value: string | undefined): boolean | undefined {
  if (value === undefined || value === '') {
    return undefined;
  }
  const lower = value.toLowerCase();
  if (lower === 'true' || lower === 'yes' || lower === '1') {
    return true;
  }
  if (lower === 'false' || lower === 'no' || lower === '0') {
    return false;
  }
  throw new Error(`Invalid boolean value: ${value}`);
}

/**
 * Parse number input from string
 */
export function parseNumber(value: string | undefined): number | undefined {
  if (value === undefined || value === '') {
    return undefined;
  }
  const num = parseInt(value, 10);
  if (isNaN(num)) {
    throw new Error(`Invalid number value: ${value}`);
  }
  return num;
}

/**
 * Parse placeholders from comma-separated key=value pairs
 * Format: "key1=value1,key2=value2"
 */
export function parsePlaceholders(value: string | undefined): Record<string, string> | undefined {
  if (value === undefined || value === '') {
    return undefined;
  }

  const placeholders: Record<string, string> = {};
  const pairs = value.split(',');

  for (const pair of pairs) {
    const trimmed = pair.trim();
    if (!trimmed) continue;

    const eqIndex = trimmed.indexOf('=');
    if (eqIndex === -1) {
      throw new Error(`Invalid placeholder format: ${trimmed}. Expected key=value`);
    }

    const key = trimmed.substring(0, eqIndex).trim();
    const val = trimmed.substring(eqIndex + 1).trim();

    if (!key) {
      throw new Error(`Empty placeholder key in: ${trimmed}`);
    }

    placeholders[key] = val;
  }

  return Object.keys(placeholders).length > 0 ? placeholders : undefined;
}

/**
 * Get all inputs from the GitHub Action context
 */
export function getInputs(): FlywayMigrateInputs {
  const url = core.getInput('url', { required: true });

  const inputs: FlywayMigrateInputs = { url };

  // Process all defined inputs
  for (const def of INPUT_DEFINITIONS) {
    if (def.inputName === 'url') continue; // Already handled

    const rawValue = core.getInput(def.inputName);
    if (!rawValue) continue;

    const propName = toCamelCase(def.inputName);

    switch (def.type) {
      case 'boolean':
        (inputs as Record<string, unknown>)[propName] = parseBoolean(rawValue);
        break;
      case 'number':
        (inputs as Record<string, unknown>)[propName] = parseNumber(rawValue);
        break;
      case 'placeholders':
        (inputs as Record<string, unknown>)[propName] = parsePlaceholders(rawValue);
        break;
      default:
        (inputs as Record<string, unknown>)[propName] = rawValue;
    }
  }

  // Handle working directory separately
  const workingDirectory = core.getInput('working-directory');
  if (workingDirectory) {
    inputs.workingDirectory = workingDirectory;
  }

  // Handle extra args separately
  const extraArgs = core.getInput('extra-args');
  if (extraArgs) {
    inputs.extraArgs = extraArgs;
  }

  return inputs;
}

/**
 * Convert kebab-case to camelCase
 */
export function toCamelCase(str: string): string {
  return str.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
}

/**
 * Mask secret inputs in the log
 */
export function maskSecrets(inputs: FlywayMigrateInputs): void {
  if (inputs.password) {
    core.setSecret(inputs.password);
  }
  if (inputs.vaultToken) {
    core.setSecret(inputs.vaultToken);
  }
}
