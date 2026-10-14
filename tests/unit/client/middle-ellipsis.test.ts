import { describe, expect, it } from 'vitest';
import { middleEllipsis } from '../../../client/src/middle-ellipsis.js';

describe('middleEllipsis', () => {
  it('leaves short text alone and keeps the end of long text', () => {
    expect(middleEllipsis('C:\\Tools\\op.exe')).toBe('C:\\Tools\\op.exe');
    const long = 'C:\\Users\\jakub\\AppData\\Local\\Microsoft\\WinGet\\Packages\\AgileBits.1Password.CLI_Microsoft.Winget.Source_8wekyb3d8bbwe\\op.exe';
    const short = middleEllipsis(long);
    expect(Array.from(short)).toHaveLength(64);
    expect(short.startsWith('C:\\Users\\jakub\\AppData')).toBe(true);
    expect(short.endsWith('8wekyb3d8bbwe\\op.exe')).toBe(true);
    expect(short).toContain('…');
  });

  it('counts characters, not bytes', () => {
    expect(middleEllipsis('ééééé', 5)).toBe('ééééé');
    expect(middleEllipsis('éééééé', 5)).toBe('é…ééé');
  });
});
