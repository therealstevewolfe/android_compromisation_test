import { renderHook } from '@testing-library/react';
import { useAutoPunctuation } from './useAutoPunctuation';

describe('useAutoPunctuation', () => {
  it('adds ending punctuation and capitalises sentences', () => {
    const { result } = renderHook(() => useAutoPunctuation());
    const transform = result.current;
    const output = transform('hello world this is listen bot');
    expect(output).toBe('Hello world this is listen bot.');
  });

  it('preserves existing punctuation', () => {
    const { result } = renderHook(() => useAutoPunctuation());
    const transform = result.current;
    expect(transform('ready?')).toBe('Ready?');
  });
});
