import * as path from 'path';
import type { ExecOptions } from '@actions/exec';
import type { FlywayMigrateInputs } from '../src/types.js';

const mockInfo = vi.fn();
const mockSetOutput = vi.fn();
const mockExec = vi.fn();

vi.doMock('@actions/core', () => ({
  info: mockInfo,
  setOutput: mockSetOutput,
}));

vi.doMock('@actions/exec', () => ({
  exec: mockExec,
}));

const {
  buildFlywayArgs,
  parseExtraArgs,
  maskArgsForLog,
  parseFlywayOutput,
  runFlyway,
  checkFlywayInstalled,
  setOutputs,
  getFlywayDetails,
} = await import('../src/flyway-runner.js');

describe('buildFlywayArgs', () => {
  it('should build args with defaults only', () => {
    const inputs: FlywayMigrateInputs = {
      baselineOnMigrate: true,
    };

    const args = buildFlywayArgs(inputs);

    expect(args).toContain('migrate');
    expect(args).toContain('-baselineOnMigrate=true');
    expect(args.some((a) => a.includes('saveSnapshot'))).toBe(false);
  });

  it('should build args with url connection', () => {
    const inputs: FlywayMigrateInputs = {
      url: 'jdbc:postgresql://localhost/db',
      user: 'admin',
      password: 'secret',
      baselineOnMigrate: true,
      saveSnapshot: true,
    };

    const args = buildFlywayArgs(inputs);

    expect(args).toContain('-url=jdbc:postgresql://localhost/db');
    expect(args).toContain('-user=admin');
    expect(args).toContain('-password=secret');
  });

  it('should build args with environment', () => {
    const inputs: FlywayMigrateInputs = {
      environment: 'production',
      baselineOnMigrate: true,
      saveSnapshot: true,
    };

    const args = buildFlywayArgs(inputs);

    expect(args).toContain('-environment=production');
  });

  it('should build args with target', () => {
    const inputs: FlywayMigrateInputs = {
      url: 'jdbc:postgresql://localhost/db',
      target: '5.0',
      baselineOnMigrate: true,
      saveSnapshot: true,
    };

    const args = buildFlywayArgs(inputs);

    expect(args).toContain('-target=5.0');
  });

  it('should build args with cherry-pick', () => {
    const inputs: FlywayMigrateInputs = {
      url: 'jdbc:postgresql://localhost/db',
      cherryPick: '2.0,2.1',
      baselineOnMigrate: true,
      saveSnapshot: true,
    };

    const args = buildFlywayArgs(inputs);

    expect(args).toContain('-cherryPick=2.0,2.1');
  });

  it('should respect baselineOnMigrate=false', () => {
    const inputs: FlywayMigrateInputs = {
      url: 'jdbc:postgresql://localhost/db',
      baselineOnMigrate: false,
      saveSnapshot: true,
    };

    const args = buildFlywayArgs(inputs);

    expect(args).toContain('-baselineOnMigrate=false');
  });

  it('should include -saveSnapshot=true when set', () => {
    const inputs: FlywayMigrateInputs = {
      url: 'jdbc:postgresql://localhost/db',
      baselineOnMigrate: true,
      saveSnapshot: true,
    };

    const args = buildFlywayArgs(inputs);

    expect(args).toContain('-saveSnapshot=true');
  });

  it('should include -saveSnapshot=false when explicitly false', () => {
    const inputs: FlywayMigrateInputs = {
      url: 'jdbc:postgresql://localhost/db',
      baselineOnMigrate: true,
      saveSnapshot: false,
    };

    const args = buildFlywayArgs(inputs);

    expect(args).toContain('-saveSnapshot=false');
  });

  it('should omit -saveSnapshot when undefined', () => {
    const inputs: FlywayMigrateInputs = {
      url: 'jdbc:postgresql://localhost/db',
      baselineOnMigrate: true,
    };

    const args = buildFlywayArgs(inputs);

    expect(args.some((a) => a.includes('saveSnapshot'))).toBe(false);
  });

  it('should include working directory', () => {
    const inputs: FlywayMigrateInputs = {
      workingDirectory: '/app/db',
      baselineOnMigrate: true,
    };

    const args = buildFlywayArgs(inputs);

    expect(args).toContain(`-workingDirectory=${path.resolve('/app/db')}`);
  });

  it('should include extra args', () => {
    const inputs: FlywayMigrateInputs = {
      url: 'jdbc:postgresql://localhost/db',
      extraArgs: '-X -custom=value',
      baselineOnMigrate: true,
      saveSnapshot: true,
    };

    const args = buildFlywayArgs(inputs);

    expect(args).toContain('-X');
    expect(args).toContain('-custom=value');
  });

  it('should not include undefined optional values', () => {
    const inputs: FlywayMigrateInputs = {
      baselineOnMigrate: true,
    };

    const args = buildFlywayArgs(inputs);

    expect(args.filter((a) => a.includes('url')).length).toBe(0);
    expect(args.filter((a) => a.includes('user')).length).toBe(0);
    expect(args.filter((a) => a.includes('password')).length).toBe(0);
    expect(args.filter((a) => a.includes('environment')).length).toBe(0);
    expect(args.filter((a) => a.includes('target')).length).toBe(0);
    expect(args.filter((a) => a.includes('cherryPick')).length).toBe(0);
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

  it('should handle unclosed quotes', () => {
    const result = parseExtraArgs('-message="hello world');
    expect(result).toEqual(['-message=hello world']);
  });

  it('should handle mixed quote types', () => {
    const result = parseExtraArgs(`-a="double" -b='single'`);
    expect(result).toEqual(['-a=double', '-b=single']);
  });
});

describe('maskArgsForLog', () => {
  it('should mask password argument', () => {
    const args = ['-password=secret123'];
    const masked = maskArgsForLog(args);

    expect(masked).toContain('-password=***');
    expect(masked).not.toContain('-password=secret123');
  });

  it('should mask user argument', () => {
    const args = ['-user=admin'];
    const masked = maskArgsForLog(args);

    expect(masked).toContain('-user=***');
  });

  it('should mask url argument', () => {
    const args = ['-url=jdbc:postgresql://user:pass@localhost/db'];
    const masked = maskArgsForLog(args);

    expect(masked).toContain('-url=***');
    expect(masked).not.toContain('pass');
  });

  it('should handle empty array', () => {
    expect(maskArgsForLog([])).toEqual([]);
  });

  it('should mask case-insensitively', () => {
    const masked = maskArgsForLog(['-Password=secret', '-USER=admin', '-URL=jdbc:test']);
    expect(masked).toEqual(['-Password=***', '-USER=***', '-URL=***']);
  });

  it('should not mask non-sensitive args', () => {
    const args = ['-baselineOnMigrate=true', '-saveSnapshot=true'];
    const masked = maskArgsForLog(args);

    expect(masked).toEqual(args);
  });

  it('should handle mixed sensitive and non-sensitive args', () => {
    const args = [
      '-url=jdbc:postgresql://localhost/db',
      '-user=admin',
      '-password=secret',
      '-baselineOnMigrate=true',
    ];
    const masked = maskArgsForLog(args);

    expect(masked[0]).toBe('-url=***');
    expect(masked[1]).toBe('-user=***');
    expect(masked[2]).toBe('-password=***');
    expect(masked[3]).toBe('-baselineOnMigrate=true');
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

  it('should handle empty string', () => {
    const result = parseFlywayOutput('');
    expect(result.migrationsApplied).toBe(0);
    expect(result.schemaVersion).toBe('unknown');
  });

  it('should fall back to regex when JSON is malformed', () => {
    const stdout = `
Successfully applied 2 migrations
Schema version: 4.0
{"schemaVersion": broken json}
    `;

    const result = parseFlywayOutput(stdout);

    expect(result.migrationsApplied).toBe(2);
    expect(result.schemaVersion).toBe('4.0');
  });
});

describe('runFlyway', () => {
  it('should execute flyway with correct arguments', async () => {
    mockExec.mockResolvedValue(0);
    const inputs: FlywayMigrateInputs = {
      url: 'jdbc:sqlite:test.db',
      baselineOnMigrate: true,
    };

    await runFlyway(inputs);

    expect(mockExec).toHaveBeenCalledWith(
      'flyway',
      expect.arrayContaining(['migrate', '-url=jdbc:sqlite:test.db']),
      expect.any(Object)
    );
  });

  it('should return exit code, stdout, and stderr', async () => {
    mockExec.mockImplementation(async (_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stdout?.(Buffer.from('success output'));
      options?.listeners?.stderr?.(Buffer.from('warning output'));
      return 0;
    });

    const result = await runFlyway({ baselineOnMigrate: true, url: 'jdbc:sqlite:test.db' });

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe('success output');
    expect(result.stderr).toBe('warning output');
  });

  it('should return non-zero exit code on failure', async () => {
    mockExec.mockResolvedValue(1);

    const result = await runFlyway({ baselineOnMigrate: true, url: 'jdbc:sqlite:test.db' });

    expect(result.exitCode).toBe(1);
  });

  it('should set cwd when working directory is provided', async () => {
    mockExec.mockResolvedValue(0);
    const inputs: FlywayMigrateInputs = {
      url: 'jdbc:sqlite:test.db',
      baselineOnMigrate: true,
      workingDirectory: '/app/db',
    };

    await runFlyway(inputs);

    expect(mockExec).toHaveBeenCalledWith(
      'flyway',
      expect.any(Array),
      expect.objectContaining({ cwd: path.resolve('/app/db') })
    );
  });

  it('should not set cwd when no working directory', async () => {
    mockExec.mockResolvedValue(0);

    await runFlyway({ baselineOnMigrate: true, url: 'jdbc:sqlite:test.db' });

    expect(mockExec).toHaveBeenCalledWith(
      'flyway',
      expect.any(Array),
      expect.not.objectContaining({ cwd: expect.anything() })
    );
  });

  it('should log masked command', async () => {
    mockExec.mockResolvedValue(0);

    await runFlyway({
      url: 'jdbc:sqlite:test.db',
      password: 'secret',
      baselineOnMigrate: true,
    });

    expect(mockInfo).toHaveBeenCalledWith(expect.stringContaining('-password=***'));
    expect(mockInfo).toHaveBeenCalledWith(expect.not.stringContaining('secret'));
  });
});

describe('checkFlywayInstalled', () => {
  it('should return false when flyway is not found', async () => {
    mockExec.mockRejectedValue(new Error('Command not found'));

    const result = await checkFlywayInstalled();

    expect(result).toBe(false);
  });

  it('should return true when flyway is found', async () => {
    mockExec.mockResolvedValue(0);

    const result = await checkFlywayInstalled();

    expect(result).toBe(true);
  });
});

describe('setOutputs', () => {
  it('should set all outputs correctly', () => {
    setOutputs({
      exitCode: 0,
      migrationsApplied: 3,
      schemaVersion: '2.0',
    });

    expect(mockSetOutput).toHaveBeenCalledWith('exit-code', '0');
    expect(mockSetOutput).toHaveBeenCalledWith('migrations-applied', '3');
    expect(mockSetOutput).toHaveBeenCalledWith('schema-version', '2.0');
  });
});

describe('getFlywayDetails', () => {
  it('should detect Community edition', async () => {
    mockExec.mockImplementation(async (_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stdout?.(Buffer.from('Flyway Community Edition 10.0.0 by Redgate\n'));
      return 0;
    });

    const info = await getFlywayDetails();

    expect(info.edition).toBe('community');
  });

  it('should detect Teams edition', async () => {
    mockExec.mockImplementation(async (_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stdout?.(Buffer.from('Flyway Teams Edition 10.5.0 by Redgate\n'));
      return 0;
    });

    const info = await getFlywayDetails();

    expect(info.edition).toBe('teams');
  });

  it('should detect Enterprise edition', async () => {
    mockExec.mockImplementation(async (_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stdout?.(Buffer.from('Flyway Enterprise Edition 11.0.0 by Redgate\n'));
      return 0;
    });

    const info = await getFlywayDetails();

    expect(info.edition).toBe('enterprise');
  });

  it('should default to community for unparseable output', async () => {
    mockExec.mockImplementation(async (_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stdout?.(Buffer.from('Something unexpected\n'));
      return 0;
    });

    const info = await getFlywayDetails();

    expect(info.edition).toBe('community');
  });
});
