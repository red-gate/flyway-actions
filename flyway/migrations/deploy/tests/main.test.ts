import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('@actions/core', () => ({
  getInput: vi.fn(),
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
