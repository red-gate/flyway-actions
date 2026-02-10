import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('@actions/core', () => ({
  getInput: vi.fn(),
  getBooleanInput: vi.fn(),
  setOutput: vi.fn(),
  setFailed: vi.fn(),
  setSecret: vi.fn(),
  info: vi.fn(),
  warning: vi.fn(),
}));

vi.mock('@actions/exec', () => ({
  exec: vi.fn(),
}));

import * as core from '@actions/core';
import * as exec from '@actions/exec';

describe('main', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  it('should check if flyway is installed', async () => {
    vi.mocked(exec.exec).mockRejectedValue(new Error('Command not found'));
    vi.mocked(core.getInput).mockReturnValue('jdbc:postgresql://localhost/db');

    const { checkFlywayInstalled } = await import('../src/flyway-runner.js');
    const result = await checkFlywayInstalled();

    expect(result).toBe(false);
  });

  it('should detect when flyway is installed', async () => {
    vi.mocked(exec.exec).mockResolvedValue(0);

    const { checkFlywayInstalled } = await import('../src/flyway-runner.js');
    const result = await checkFlywayInstalled();

    expect(result).toBe(true);
  });

  it('should set outputs correctly', async () => {
    const { setOutputs } = await import('../src/flyway-runner.js');

    setOutputs({
      exitCode: 0,
      migrationsApplied: 3,
      schemaVersion: '2.0',
    });

    expect(core.setOutput).toHaveBeenCalledWith('exit-code', '0');
    expect(core.setOutput).toHaveBeenCalledWith('migrations-applied', '3');
    expect(core.setOutput).toHaveBeenCalledWith('schema-version', '2.0');
  });

  it('should get flyway edition for Community edition', async () => {
    vi.mocked(exec.exec).mockImplementation(
      async (_cmd: string, _args?: string[], options?: exec.ExecOptions) => {
        if (options?.listeners?.stdout) {
          options.listeners.stdout(Buffer.from('Flyway Community Edition 10.0.0 by Redgate\n'));
        }
        return 0;
      }
    );

    const { getFlywayDetails } = await import('../src/flyway-runner.js');
    const info = await getFlywayDetails();

    expect(info.edition).toBe('community');
  });

  it('should get flyway edition for Teams edition', async () => {
    vi.mocked(exec.exec).mockImplementation(
      async (_cmd: string, _args?: string[], options?: exec.ExecOptions) => {
        if (options?.listeners?.stdout) {
          options.listeners.stdout(Buffer.from('Flyway Teams Edition 10.5.0 by Redgate\n'));
        }
        return 0;
      }
    );

    const { getFlywayDetails } = await import('../src/flyway-runner.js');
    const info = await getFlywayDetails();

    expect(info.edition).toBe('teams');
  });

  it('should get flyway edition for Enterprise edition', async () => {
    vi.mocked(exec.exec).mockImplementation(
      async (_cmd: string, _args?: string[], options?: exec.ExecOptions) => {
        if (options?.listeners?.stdout) {
          options.listeners.stdout(Buffer.from('Flyway Enterprise Edition 11.0.0 by Redgate\n'));
        }
        return 0;
      }
    );

    const { getFlywayDetails } = await import('../src/flyway-runner.js');
    const info = await getFlywayDetails();

    expect(info.edition).toBe('enterprise');
  });

  it('should default to community for unparseable output', async () => {
    vi.mocked(exec.exec).mockImplementation(
      async (_cmd: string, _args?: string[], options?: exec.ExecOptions) => {
        if (options?.listeners?.stdout) {
          options.listeners.stdout(Buffer.from('Something unexpected\n'));
        }
        return 0;
      }
    );

    const { getFlywayDetails } = await import('../src/flyway-runner.js');
    const info = await getFlywayDetails();

    expect(info.edition).toBe('community');
  });
});

describe('run', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.resetModules();
  });

  const setupFlywayMock = (edition: string, migrateExitCode: number, migrateOutput = '') => {
    let callCount = 0;
    vi.mocked(exec.exec).mockImplementation(
      async (_cmd: string, _args?: string[], options?: exec.ExecOptions) => {
        callCount++;
        if (callCount <= 2) {
          if (options?.listeners?.stdout) {
            options.listeners.stdout(Buffer.from(`Flyway ${edition} Edition 10.0.0 by Redgate\n`));
          }
          return 0;
        }
        if (migrateOutput && options?.listeners?.stdout) {
          options.listeners.stdout(Buffer.from(migrateOutput));
        }
        return migrateExitCode;
      }
    );
  };

  it('should fail when flyway is not installed', async () => {
    vi.mocked(exec.exec).mockRejectedValue(new Error('Command not found'));

    await import('../src/main.js');
    await vi.dynamicImportSettled();

    expect(core.setFailed).toHaveBeenCalledWith(expect.stringContaining('Flyway is not installed'));
  });

  it('should fail when neither url nor environment is provided', async () => {
    setupFlywayMock('Community', 0);
    vi.mocked(core.getInput).mockReturnValue('');

    await import('../src/main.js');
    await vi.dynamicImportSettled();

    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining('Either "url" or "environment" must be provided')
    );
  });

  it('should clear saveSnapshot for community edition', async () => {
    setupFlywayMock('Community', 0, 'Successfully applied 1 migrations\n');
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      if (name === 'url') return 'jdbc:sqlite:test.db';
      if (name === 'save-snapshot') return 'true';
      if (name === 'baseline-on-migrate') return 'true';
      return '';
    });

    await import('../src/main.js');
    await vi.dynamicImportSettled();

    const execCalls = vi.mocked(exec.exec).mock.calls;
    const migrateCall = execCalls.find(
      (call) => Array.isArray(call[1]) && call[1].includes('migrate')
    );
    const migrateArgs = migrateCall?.[1] as string[];
    expect(migrateArgs.some((a) => a.includes('saveSnapshot'))).toBe(false);
  });

  it('should fail when flyway returns non-zero exit code', async () => {
    setupFlywayMock('Community', 1);
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      if (name === 'url') return 'jdbc:sqlite:test.db';
      if (name === 'baseline-on-migrate') return 'true';
      return '';
    });

    await import('../src/main.js');
    await vi.dynamicImportSettled();

    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining('Flyway migrate failed with exit code 1')
    );
  });

  it('should log stderr as warning', async () => {
    let callCount = 0;
    vi.mocked(exec.exec).mockImplementation(
      async (_cmd: string, _args?: string[], options?: exec.ExecOptions) => {
        callCount++;
        if (callCount <= 2) {
          if (options?.listeners?.stdout) {
            options.listeners.stdout(Buffer.from('Flyway Community Edition 10.0.0 by Redgate\n'));
          }
          return 0;
        }
        if (options?.listeners?.stdout) {
          options.listeners.stdout(Buffer.from('Successfully applied 1 migrations\n'));
        }
        if (options?.listeners?.stderr) {
          options.listeners.stderr(Buffer.from('some warning'));
        }
        return 0;
      }
    );
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      if (name === 'url') return 'jdbc:sqlite:test.db';
      if (name === 'baseline-on-migrate') return 'true';
      return '';
    });

    await import('../src/main.js');
    await vi.dynamicImportSettled();

    expect(core.warning).toHaveBeenCalledWith('some warning');
  });

  it('should set outputs on successful execution', async () => {
    setupFlywayMock('Community', 0, 'Successfully applied 3 migrations\nSchema now at version 3\n');
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      if (name === 'url') return 'jdbc:sqlite:test.db';
      if (name === 'baseline-on-migrate') return 'true';
      return '';
    });

    await import('../src/main.js');
    await vi.dynamicImportSettled();

    expect(core.setOutput).toHaveBeenCalledWith('exit-code', '0');
    expect(core.setOutput).toHaveBeenCalledWith('migrations-applied', '3');
    expect(core.setOutput).toHaveBeenCalledWith('schema-version', '3');
  });
});
