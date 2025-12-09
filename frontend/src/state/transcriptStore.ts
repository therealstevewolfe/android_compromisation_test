import { create } from 'zustand';
import { nanoid } from '../utils/nanoid';
import { TranscriptSegment, VoiceStatus } from '../types';

const MAX_SEGMENTS = 600;

interface TranscriptState {
  segments: TranscriptSegment[];
  liveText: string;
  status: VoiceStatus;
  permission: 'prompt' | 'granted' | 'denied';
  quietMode: boolean;
  minimalAcknowledgement: boolean;
  acknowledgementQueue: string[];
  error?: string;
  setStatus: (status: VoiceStatus) => void;
  setPermission: (permission: 'prompt' | 'granted' | 'denied') => void;
  setLiveText: (text: string) => void;
  addSegment: (payload: Omit<TranscriptSegment, 'id' | 'timestamp'>) => void;
  setError: (message?: string) => void;
  setQuietMode: (value: boolean) => void;
  setMinimalAcknowledgement: (value: boolean) => void;
  pushAcknowledgement: (value: string) => void;
  reset: () => void;
}

export const useTranscriptStore = create<TranscriptState>((set) => ({
  segments: [],
  liveText: '',
  status: 'idle',
  permission: 'prompt',
  quietMode: true,
  minimalAcknowledgement: false,
  acknowledgementQueue: [],
  error: undefined,
  setStatus: (status) => set({ status }),
  setPermission: (permission) => set({ permission }),
  setLiveText: (text) => set({ liveText: text }),
  addSegment: (payload) =>
    set((state) => {
      const next: TranscriptSegment = {
        id: payload.id ?? nanoid(),
        timestamp: Date.now(),
        ...payload,
      };
      const windowed = [...state.segments, next].slice(-MAX_SEGMENTS);
      return { segments: windowed, liveText: '' };
    }),
  setError: (message) => set({ error: message }),
  setQuietMode: (value) => set({ quietMode: value }),
  setMinimalAcknowledgement: (value) => set({ minimalAcknowledgement: value }),
  pushAcknowledgement: (value) =>
    set((state) => ({ acknowledgementQueue: [...state.acknowledgementQueue, value].slice(-5) })),
  reset: () =>
    set({
      segments: [],
      liveText: '',
      status: 'idle',
      permission: 'prompt',
      acknowledgementQueue: [],
      error: undefined,
    }),
}));
