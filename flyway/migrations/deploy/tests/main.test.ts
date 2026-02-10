import type { ExecOptions } from '@actions/exec';

const mockGetInput = vi.fn();
const mockGetBooleanInput = vi.fn();
const mockSetOutput = vi.fn();
const mockSetFailed = vi.fn();
const mockSetSecret = vi.fn();
const mockInfo = vi.fn();
const mockWarning = vi.fn();
const mockExec = vi.fn();

const setupMocks = () => {
  vi.doMock('@actions/core', () => ({
    getInput: mockGetInput,
    getBooleanInput: mockGetBooleanInput,
    setOutput: mockSetOutput,
    setFailed: mockSetFailed,
    setSecret: mockSetSecret,
    info: mockInfo,
    warning: mockWarning,
  }));

  vi.doMock('@actions/exec', () => ({
    exec: mockExec,
  }));
};

describe('run', () => {
  beforeEach(() => {
    vi.resetModules();
    setupMocks();
  });

  const setupFlywayMock = (edition: string, migrateExitCode: number, migrateOutput = '') => {
    let callCount = 0;
    mockExec.mockImplementation(async (_cmd: string, _args?: string[], options?: ExecOptions) => {
      callCount++;
      // First two exec calls are checkFlywayInstalled and getFlywayDetails
      if (callCount <= 2) {
        options?.listeners?.stdout?.(Buffer.from(`Flyway ${edition} Edition 10.0.0 by Redgate\n`));
        return 0;
      }
      if (migrateOutput) {
        options?.listeners?.stdout?.(Buffer.from(migrateOutput));
      }
      return migrateExitCode;
    });
  };

  it('should fail when flyway is not installed', async () => {
    mockExec.mockRejectedValue(new Error('Command not found'));

    await import('../src/main.js');
    await vi.dynamicImportSettled();

    expect(mockSetFailed).toHaveBeenCalledWith(expect.stringContaining('Flyway is not installed'));
  });

  it('should fail when neither url nor environment is provided', async () => {
    setupFlywayMock('Community', 0);
    mockGetInput.mockReturnValue('');

    await import('../src/main.js');
    await vi.dynamicImportSettled();

    expect(mockSetFailed).toHaveBeenCalledWith(
      expect.stringContaining('Either "url" or "environment" must be provided')
    );
  });

  it('should clear saveSnapshot for community edition', async () => {
    setupFlywayMock('Community', 0, 'Successfully applied 1 migrations\n');
    mockGetInput.mockImplementation((name: string) => {
      if (name === 'url') return 'jdbc:sqlite:test.db';
      return '';
    });

    await import('../src/main.js');
    await vi.dynamicImportSettled();

    expect(mockExec).toHaveBeenCalledWith(
      'flyway',
      expect.not.arrayContaining([expect.stringContaining('saveSnapshot')]),
      expect.any(Object)
    );
  });

  it('should fail when flyway returns non-zero exit code', async () => {
    setupFlywayMock('Community', 1);
    mockGetInput.mockImplementation((name: string) => {
      if (name === 'url') return 'jdbc:sqlite:test.db';
      return '';
    });

    await import('../src/main.js');
    await vi.dynamicImportSettled();

    expect(mockSetFailed).toHaveBeenCalledWith(
      expect.stringContaining('Flyway migrate failed with exit code 1')
    );
  });

  it('should log stderr as warning', async () => {
    let callCount = 0;
    mockExec.mockImplementation(async (_cmd: string, _args?: string[], options?: ExecOptions) => {
      callCount++;
      if (callCount <= 2) {
        options?.listeners?.stdout?.(Buffer.from('Flyway Community Edition 10.0.0 by Redgate\n'));
        return 0;
      }
      options?.listeners?.stdout?.(Buffer.from('Successfully applied 1 migrations\n'));
      options?.listeners?.stderr?.(Buffer.from('some warning'));
      return 0;
    });
    mockGetInput.mockImplementation((name: string) => {
      if (name === 'url') return 'jdbc:sqlite:test.db';
      return '';
    });

    await import('../src/main.js');
    await vi.dynamicImportSettled();

    expect(mockWarning).toHaveBeenCalledWith('some warning');
  });

  it('should set outputs on successful execution', async () => {
    setupFlywayMock('Community', 0, 'Successfully applied 3 migrations\nSchema now at version 3\n');
    mockGetInput.mockImplementation((name: string) => {
      if (name === 'url') return 'jdbc:sqlite:test.db';
      return '';
    });

    await import('../src/main.js');
    await vi.dynamicImportSettled();

    expect(mockSetOutput).toHaveBeenCalledWith('exit-code', '0');
    expect(mockSetOutput).toHaveBeenCalledWith('migrations-applied', '3');
    expect(mockSetOutput).toHaveBeenCalledWith('schema-version', '3');
  });
});
