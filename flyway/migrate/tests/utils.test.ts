import { describe, it, expect } from 'vitest';
import { toCamelCase } from '../src/utils.js';

describe('toCamelCase', () => {
  it('should convert kebab-case to camelCase', () => {
    expect(toCamelCase('baseline-on-migrate')).toBe('baselineOnMigrate');
  });

  it('should handle single word', () => {
    expect(toCamelCase('url')).toBe('url');
  });

  it('should handle multiple dashes', () => {
    expect(toCamelCase('validate-migration-naming')).toBe('validateMigrationNaming');
  });

  it('should handle already camelCase', () => {
    expect(toCamelCase('alreadyCamel')).toBe('alreadyCamel');
  });
});
