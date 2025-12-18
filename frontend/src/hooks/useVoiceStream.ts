import { useCallback, useEffect, useRef } from 'react';
import { useAutoPunctuation } from './useAutoPunctuation';
import { useTranscriptStore } from '../state/transcriptStore';
import { TranscriptSegment, VoiceControls } from '../types';

const affirmationPool = ['mm-hm', 'yeah', 'got you', 'listening'];

export const useVoiceStream = (): VoiceControls & { segments: TranscriptSegment[]; liveText: string; status: string; error?: string } => {
  const recognitionRef = useRef<SpeechRecognition | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const lastSegmentRef = useRef<string>('');
  const punctuate = useAutoPunctuation();

  const {
    setStatus,
    setPermission,
    setLiveText,
    addSegment,
    setError,
    pushAcknowledgement,
    minimalAcknowledgement,
    quietMode,
    segments,
    liveText,
    status,
  } = useTranscriptStore();

  const handleResult = useCallback(
    (event: SpeechRecognitionEvent) => {
      let interim = '';
      for (let i = event.resultIndex; i < event.results.length; i += 1) {
        const transcript = event.results[i][0].transcript;
        if (event.results[i].isFinal) {
          const processed = punctuate(transcript);
          addSegment({ content: processed, isFinal: true, origin: 'voice', hasCode: /```|\bfunction\b|const\b/.test(processed) });
          lastSegmentRef.current = processed;
        } else {
          interim += transcript;
        }
      }
      if (interim) {
        setLiveText(punctuate(interim));
      }
    },
    [addSegment, punctuate, setLiveText],
  );

  const setUpRecognition = useCallback(() => {
    const SpeechRecognitionClass = (window as unknown as { webkitSpeechRecognition?: typeof SpeechRecognition }).webkitSpeechRecognition ||
      (window as unknown as { SpeechRecognition?: typeof SpeechRecognition }).SpeechRecognition;

    if (!SpeechRecognitionClass) {
      setError('Speech recognition not available in this browser. Use text input or connect a streaming backend.');
      setStatus('error');
      return;
    }

    const recognition = new SpeechRecognitionClass();
    recognition.continuous = true;
    recognition.interimResults = true;
    recognition.lang = 'en-US';

    recognition.onresult = handleResult;
    recognition.onerror = (event) => {
      setError(event.error);
      setStatus('error');
    };
    recognition.onend = () => {
      if (status === 'listening') {
        recognition.start();
      }
    };

    recognitionRef.current = recognition;
  }, [handleResult, setError, setStatus, status]);

  const startListening = useCallback(async () => {
    setError(undefined);
    try {
      if (!recognitionRef.current) {
        setUpRecognition();
      }
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      streamRef.current = stream;
      setPermission('granted');
      recognitionRef.current?.start();
      setStatus('listening');
    } catch (err) {
      setError((err as Error).message);
      setPermission('denied');
      setStatus('error');
    }
  }, [setError, setPermission, setStatus, setUpRecognition]);

  const stopListening = useCallback(() => {
    recognitionRef.current?.stop();
    streamRef.current?.getTracks().forEach((track) => track.stop());
    setStatus('paused');
  }, [setStatus]);

  const feedText = useCallback(
    (text: string) => {
      if (!text.trim()) return;
      const processed = punctuate(text);
      addSegment({ content: processed, isFinal: true, origin: 'text', hasCode: /```/.test(processed) });
      lastSegmentRef.current = processed;
    },
    [addSegment, punctuate],
  );

  useEffect(() => {
    const shouldAffirm = minimalAcknowledgement && quietMode && lastSegmentRef.current.endsWith('?');
    if (shouldAffirm) {
      const acknowledgement = affirmationPool[Math.floor(Math.random() * affirmationPool.length)];
      pushAcknowledgement(acknowledgement);
      lastSegmentRef.current = '';
    }
  }, [minimalAcknowledgement, pushAcknowledgement, quietMode, segments.length]);

  useEffect(() => () => stopListening(), [stopListening]);

  return {
    startListening,
    stopListening,
    feedText,
    segments,
    liveText,
    status,
    error: useTranscriptStore.getState().error,
  };
};
