import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock modules before importing
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
    // Mock flyway not installed
    vi.mocked(exec.exec).mockRejectedValue(new Error('Command not found'));
    vi.mocked(core.getInput).mockReturnValue('jdbc:postgresql://localhost/db');

    // Import and run
    const { checkFlywayInstalled } = await import('../src/flyway-runner.js');
    const result = await checkFlywayInstalled();

    expect(result).toBe(false);
  });

  it('should detect when flyway is installed', async () => {
    // Mock flyway installed
    vi.mocked(exec.exec).mockResolvedValue(0);

    const { checkFlywayInstalled } = await import('../src/flyway-runner.js');
    const result = await checkFlywayInstalled();

    expect(result).toBe(true);
  });

  it('should set outputs correctly', async () => {
    const { setOutputs } = await import('../src/flyway-runner.js');

    setOutputs({
      exitCode: 0,
      flywayVersion: '10.0.0',
      migrationsApplied: 3,
      schemaVersion: '2.0',
    });

    expect(core.setOutput).toHaveBeenCalledWith('exit-code', '0');
    expect(core.setOutput).toHaveBeenCalledWith('flyway-version', '10.0.0');
    expect(core.setOutput).toHaveBeenCalledWith('migrations-applied', '3');
    expect(core.setOutput).toHaveBeenCalledWith('schema-version', '2.0');
  });

  it('should get flyway version from output', async () => {
    vi.mocked(exec.exec).mockImplementation(
      async (_cmd: string, _args?: string[], options?: exec.ExecOptions) => {
        if (options?.listeners?.stdout) {
          options.listeners.stdout(Buffer.from('Flyway Community Edition 10.0.0 by Redgate\n'));
        }
        return 0;
      }
    );

    const { getFlywayVersion } = await import('../src/flyway-runner.js');
    const version = await getFlywayVersion();

    expect(version).toBe('10.0.0');
  });

  it('should handle Teams edition version', async () => {
    vi.mocked(exec.exec).mockImplementation(
      async (_cmd: string, _args?: string[], options?: exec.ExecOptions) => {
        if (options?.listeners?.stdout) {
          options.listeners.stdout(Buffer.from('Flyway Teams Edition 10.5.0 by Redgate\n'));
        }
        return 0;
      }
    );

    const { getFlywayVersion } = await import('../src/flyway-runner.js');
    const version = await getFlywayVersion();

    expect(version).toBe('10.5.0');
  });

  it('should handle Enterprise edition version', async () => {
    vi.mocked(exec.exec).mockImplementation(
      async (_cmd: string, _args?: string[], options?: exec.ExecOptions) => {
        if (options?.listeners?.stdout) {
          options.listeners.stdout(Buffer.from('Flyway Enterprise Edition 11.0.0 by Redgate\n'));
        }
        return 0;
      }
    );

    const { getFlywayVersion } = await import('../src/flyway-runner.js');
    const version = await getFlywayVersion();

    expect(version).toBe('11.0.0');
  });

  it('should return unknown for unparseable version', async () => {
    vi.mocked(exec.exec).mockImplementation(
      async (_cmd: string, _args?: string[], options?: exec.ExecOptions) => {
        if (options?.listeners?.stdout) {
          options.listeners.stdout(Buffer.from('Something unexpected\n'));
        }
        return 0;
      }
    );

    const { getFlywayVersion } = await import('../src/flyway-runner.js');
    const version = await getFlywayVersion();

    expect(version).toBe('unknown');
  });
});
