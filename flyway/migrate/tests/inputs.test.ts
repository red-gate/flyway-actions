import { describe, it, expect, vi, beforeEach } from 'vitest';
import { getInputs, maskSecrets } from '../src/inputs.js';
import * as core from '@actions/core';

vi.mock('@actions/core');

describe('getInputs', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('should return url when provided', () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      if (name === 'url') return 'jdbc:postgresql://localhost/db';
      return '';
    });

    const inputs = getInputs();
    expect(inputs.url).toBe('jdbc:postgresql://localhost/db');
  });

  it('should return undefined for url when not provided', () => {
    vi.mocked(core.getInput).mockReturnValue('');

    const inputs = getInputs();
    expect(inputs.url).toBeUndefined();
  });

  it('should get connection inputs', () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      const values: Record<string, string> = {
        url: 'jdbc:postgresql://localhost/db',
        user: 'admin',
        password: 'secret',
      };
      return values[name] || '';
    });

    const inputs = getInputs();
    expect(inputs.url).toBe('jdbc:postgresql://localhost/db');
    expect(inputs.user).toBe('admin');
    expect(inputs.password).toBe('secret');
  });

  it('should get environment input', () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      if (name === 'environment') return 'production';
      return '';
    });

    const inputs = getInputs();
    expect(inputs.environment).toBe('production');
  });

  it('should get target and cherry-pick inputs', () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      const values: Record<string, string> = {
        target: '5.0',
        'cherry-pick': '3.0,4.0',
      };
      return values[name] || '';
    });

    const inputs = getInputs();
    expect(inputs.target).toBe('5.0');
    expect(inputs.cherryPick).toBe('3.0,4.0');
  });

  it('should default baselineOnMigrate to true', () => {
    vi.mocked(core.getInput).mockReturnValue('');

    const inputs = getInputs();
    expect(inputs.baselineOnMigrate).toBe(true);
  });

  it('should set baselineOnMigrate to false when explicitly set', () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      if (name === 'baseline-on-migrate') return 'false';
      return '';
    });

    const inputs = getInputs();
    expect(inputs.baselineOnMigrate).toBe(false);
  });

  it('should default saveSnapshot to true', () => {
    vi.mocked(core.getInput).mockReturnValue('');

    const inputs = getInputs();
    expect(inputs.saveSnapshot).toBe(true);
  });

  it('should set saveSnapshot to false when explicitly set', () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      if (name === 'save-snapshot') return 'false';
      return '';
    });

    const inputs = getInputs();
    expect(inputs.saveSnapshot).toBe(false);
  });

  it('should get working directory and extra args', () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      const values: Record<string, string> = {
        'working-directory': '/app/db',
        'extra-args': '-X -someFlag=value',
      };
      return values[name] || '';
    });

    const inputs = getInputs();
    expect(inputs.workingDirectory).toBe('/app/db');
    expect(inputs.extraArgs).toBe('-X -someFlag=value');
  });

  it('should return undefined for optional inputs not provided', () => {
    vi.mocked(core.getInput).mockReturnValue('');

    const inputs = getInputs();
    expect(inputs.url).toBeUndefined();
    expect(inputs.user).toBeUndefined();
    expect(inputs.password).toBeUndefined();
    expect(inputs.environment).toBeUndefined();
    expect(inputs.target).toBeUndefined();
    expect(inputs.cherryPick).toBeUndefined();
    expect(inputs.workingDirectory).toBeUndefined();
    expect(inputs.extraArgs).toBeUndefined();
  });
});

describe('maskSecrets', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('should mask password', () => {
    const inputs = {
      password: 'secret123',
      baselineOnMigrate: true,
      saveSnapshot: true,
    };

    maskSecrets(inputs);

    expect(core.setSecret).toHaveBeenCalledWith('secret123');
  });

  it('should not call setSecret when no password present', () => {
    const inputs = {
      url: 'jdbc:postgresql://localhost/db',
      user: 'admin',
      baselineOnMigrate: true,
      saveSnapshot: true,
    };

    maskSecrets(inputs);

    expect(core.setSecret).not.toHaveBeenCalled();
  });
});
