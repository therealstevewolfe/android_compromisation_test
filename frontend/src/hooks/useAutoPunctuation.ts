import { useCallback } from 'react';

const sentenceEndPattern = /([.!?])$/;
const needsCapitalisation = /(^|[.!?]\s+)([a-z])/g;

const smartCapitalize = (text: string) => text.replace(needsCapitalisation, (match, prefix, char) => `${prefix}${char.toUpperCase()}`);

export const useAutoPunctuation = () => {
  return useCallback((incoming: string) => {
    if (!incoming.trim()) return '';
    const compacted = incoming.replace(/\s+/g, ' ').trim();

    const withPauses = compacted.replace(/(,?\s)(and|but|so)\s/gi, (match) => `${match.trim()} `);

    const normalised = sentenceEndPattern.test(withPauses) ? withPauses : `${withPauses}.`;

    return smartCapitalize(normalised);
  }, []);
};
