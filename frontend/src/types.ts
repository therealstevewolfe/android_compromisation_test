export type VoiceStatus = 'idle' | 'listening' | 'paused' | 'error';

export type TokenTag = 'text' | 'entity' | 'time' | 'code' | 'number';

export interface TaggedToken {
  value: string;
  tag: TokenTag;
}

export interface TranscriptSegment {
  id: string;
  content: string;
  timestamp: number;
  isFinal: boolean;
  origin: 'voice' | 'text';
  hasCode: boolean;
  tokens?: TaggedToken[];
}

export interface VoiceControls {
  startListening: () => Promise<void>;
  stopListening: () => void;
  feedText: (text: string) => void;
}
