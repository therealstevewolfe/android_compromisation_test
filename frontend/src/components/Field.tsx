import { useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { TranscriptSegment, TaggedToken } from '../types';

interface FieldProps {
  segments: TranscriptSegment[];
  liveText: string;
  status: string;
}

const entityPattern = /\b([A-Z][a-z]+(?:\s[A-Z][a-z]+)*)\b/g;
const timePattern = /\b(\d{1,2}:\d{2}(?:am|pm)?|tomorrow|today|tonight)\b/gi;
const codeTriggers = /(const |function |class |=>|```)/;

const tokenise = (text: string): TaggedToken[] => {
  const tokens: TaggedToken[] = [];
  const words = text.split(/(\s+)/);
  for (const word of words) {
    if (!word.trim()) {
      tokens.push({ value: word, tag: 'text' });
      continue;
    }
    if (codeTriggers.test(word)) {
      tokens.push({ value: word, tag: 'code' });
    } else if (timePattern.test(word)) {
      tokens.push({ value: word, tag: 'time' });
    } else if (entityPattern.test(word)) {
      tokens.push({ value: word, tag: 'entity' });
    } else if (/^\d+[kKmM]?$/.test(word)) {
      tokens.push({ value: word, tag: 'number' });
    } else {
      tokens.push({ value: word, tag: 'text' });
    }
    entityPattern.lastIndex = 0;
    timePattern.lastIndex = 0;
  }
  return tokens;
};

export const Field = ({ segments, liveText, status }: FieldProps) => {
  const [focusedToken, setFocusedToken] = useState<TaggedToken | null>(null);

  const preparedSegments = useMemo(
    () =>
      segments.map((segment) => ({
        ...segment,
        tokens: segment.tokens ?? tokenise(segment.content),
        hasCode: segment.hasCode || codeTriggers.test(segment.content),
      })),
    [segments],
  );

  const active = status === 'listening' || preparedSegments.length > 0 || Boolean(liveText);

  return (
    <div className={`field-shell ${active ? 'field-active' : ''} ${focusedToken ? 'field-focused' : ''}`}>
      <div className="field-header">
        <div className="pill">Live transcript</div>
        <div className={`status-dot ${status}`} aria-live="polite" aria-label={`Listening status: ${status}`}></div>
      </div>

      <div className="field-body" aria-live="polite" aria-atomic={false}>
        {preparedSegments.map((segment) => (
          <div key={segment.id} className="segment-row">
            {segment.hasCode ? (
              <motion.pre
                layout
                className="code-block"
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.25 }}
              >
                {segment.content}
              </motion.pre>
            ) : (
              <p>
                {segment.tokens?.map((token, index) => (
                  <span
                    key={`${segment.id}-${index}`}
                    className={`token token-${token.tag}`}
                    role={token.tag !== 'text' ? 'button' : undefined}
                    tabIndex={token.tag !== 'text' ? 0 : undefined}
                    onClick={() => (token.tag !== 'text' ? setFocusedToken(token) : undefined)}
                  >
                    {token.value}
                  </span>
                ))}
              </p>
            )}
          </div>
        ))}

        {liveText && (
          <p className="live-line" data-animate>
            {tokenise(liveText).map((token, index) => (
              <span key={`${token.value}-${index}`} className={`token token-${token.tag}`}>
                {token.value}
              </span>
            ))}
          </p>
        )}
      </div>

      <AnimatePresence>
        {focusedToken ? (
          <motion.div
            className="focus-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            role="dialog"
            aria-modal="true"
            onClick={() => setFocusedToken(null)}
          >
            <div className="focus-card" onClick={(e) => e.stopPropagation()}>
              <p className="pill">Focus</p>
              <h3>{focusedToken.value}</h3>
              <p className="muted">Tap outside to resume the live flow.</p>
            </div>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </div>
  );
};
