import { describe, it, expect, vi } from 'vitest';
import {
  buildFlywayArgs,
  parseExtraArgs,
  maskArgsForLog,
  parseFlywayOutput,
} from '../src/flyway-runner.js';
import { FlywayMigrateInputs } from '../src/types.js';

vi.mock('@actions/core');
vi.mock('@actions/exec');

describe('buildFlywayArgs', () => {
  it('should build args with only required url', () => {
    const inputs: FlywayMigrateInputs = {
      url: 'jdbc:postgresql://localhost/db',
    };

    const args = buildFlywayArgs(inputs);

    expect(args).toContain('migrate');
    expect(args).toContain('-url=jdbc:postgresql://localhost/db');
  });

  it('should build args with connection parameters', () => {
    const inputs: FlywayMigrateInputs = {
      url: 'jdbc:postgresql://localhost/db',
      user: 'admin',
      password: 'secret',
    };

    const args = buildFlywayArgs(inputs);

    expect(args).toContain('-url=jdbc:postgresql://localhost/db');
    expect(args).toContain('-user=admin');
    expect(args).toContain('-password=secret');
  });

  it('should build args with config files', () => {
    const inputs: FlywayMigrateInputs = {
      url: 'jdbc:postgresql://localhost/db',
      configFiles: 'flyway.conf,flyway-local.conf',
    };

    const args = buildFlywayArgs(inputs);

    expect(args).toContain('-configFiles=flyway.conf,flyway-local.conf');
  });

  it('should include extra args', () => {
    const inputs: FlywayMigrateInputs = {
      url: 'jdbc:postgresql://localhost/db',
      extraArgs: '-X -custom=value',
    };

    const args = buildFlywayArgs(inputs);

    expect(args).toContain('-X');
    expect(args).toContain('-custom=value');
  });

  it('should not include undefined values', () => {
    const inputs: FlywayMigrateInputs = {
      url: 'jdbc:postgresql://localhost/db',
      user: undefined,
      password: undefined,
    };

    const args = buildFlywayArgs(inputs);

    expect(args).not.toContain('-user=undefined');
    expect(args).not.toContain('-password=undefined');
    expect(args.filter((a) => a.includes('user')).length).toBe(0);
    expect(args.filter((a) => a.includes('password')).length).toBe(0);
  });
});

describe('parseExtraArgs', () => {
  it('should parse simple space-separated args', () => {
    const result = parseExtraArgs('-X -Y -Z');
    expect(result).toEqual(['-X', '-Y', '-Z']);
  });

  it('should handle quoted strings with spaces', () => {
    const result = parseExtraArgs('-message="Hello World" -flag');
    expect(result).toEqual(['-message=Hello World', '-flag']);
  });

  it('should handle single-quoted strings', () => {
    const result = parseExtraArgs("-message='Hello World' -flag");
    expect(result).toEqual(['-message=Hello World', '-flag']);
  });

  it('should handle empty string', () => {
    const result = parseExtraArgs('');
    expect(result).toEqual([]);
  });

  it('should handle multiple spaces', () => {
    const result = parseExtraArgs('-X    -Y     -Z');
    expect(result).toEqual(['-X', '-Y', '-Z']);
  });

  it('should handle args with equals signs', () => {
    const result = parseExtraArgs('-key=value -another=test');
    expect(result).toEqual(['-key=value', '-another=test']);
  });
});

describe('maskArgsForLog', () => {
  it('should mask password argument', () => {
    const args = ['-url=jdbc:postgresql://localhost/db', '-password=secret123'];
    const masked = maskArgsForLog(args);

    expect(masked).toContain('-url=jdbc:postgresql://localhost/db');
    expect(masked).toContain('-password=***');
    expect(masked).not.toContain('-password=secret123');
  });

  it('should mask user argument', () => {
    const args = ['-url=jdbc:postgresql://localhost/db', '-user=admin'];
    const masked = maskArgsForLog(args);

    expect(masked).toContain('-user=***');
  });

  it('should not mask non-sensitive args', () => {
    const args = ['-url=jdbc:postgresql://localhost/db', '-configFiles=flyway.conf'];
    const masked = maskArgsForLog(args);

    expect(masked).toEqual(args);
  });

  it('should handle mixed sensitive and non-sensitive args', () => {
    const args = [
      '-url=jdbc:postgresql://localhost/db',
      '-user=admin',
      '-password=secret',
      '-configFiles=flyway.conf',
    ];
    const masked = maskArgsForLog(args);

    expect(masked[0]).toBe('-url=jdbc:postgresql://localhost/db');
    expect(masked[1]).toBe('-user=***');
    expect(masked[2]).toBe('-password=***');
    expect(masked[3]).toBe('-configFiles=flyway.conf');
  });
});

describe('parseFlywayOutput', () => {
  it('should parse migration count from success message', () => {
    const stdout = `
Flyway Community Edition 10.0.0 by Redgate
Database: jdbc:postgresql://localhost/test
Successfully applied 3 migrations to schema "public" (execution time 00:00.150s)
    `;

    const result = parseFlywayOutput(stdout);

    expect(result.migrationsApplied).toBe(3);
  });

  it('should parse schema version', () => {
    const stdout = `
Flyway Community Edition 10.0.0 by Redgate
Database: jdbc:postgresql://localhost/test
Schema version: 2.0.1
    `;

    const result = parseFlywayOutput(stdout);

    expect(result.schemaVersion).toBe('2.0.1');
  });

  it('should parse current version of schema format', () => {
    const stdout = `
Current version of schema "public": 1.5
    `;

    const result = parseFlywayOutput(stdout);

    expect(result.schemaVersion).toBe('1.5');
  });

  it('should return defaults when no patterns match', () => {
    const stdout = 'Some unrelated output';

    const result = parseFlywayOutput(stdout);

    expect(result.migrationsApplied).toBe(0);
    expect(result.schemaVersion).toBe('unknown');
  });

  it('should parse JSON output if present', () => {
    const stdout = `
{"schemaVersion": "3.0", "migrationsExecuted": 5}
    `;

    const result = parseFlywayOutput(stdout);

    expect(result.migrationsApplied).toBe(5);
    expect(result.schemaVersion).toBe('3.0');
  });

  it('should handle validated migrations message', () => {
    const stdout = `
Successfully validated 10 migrations
    `;

    const result = parseFlywayOutput(stdout);

    expect(result.migrationsApplied).toBe(10);
  });

  it('should handle zero migrations', () => {
    const stdout = `
Schema "public" is up to date. No migration necessary.
    `;

    const result = parseFlywayOutput(stdout);

    expect(result.migrationsApplied).toBe(0);
  });
});
