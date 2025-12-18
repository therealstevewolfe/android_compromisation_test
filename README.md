# 🎧 Listen-Bot — Voice-First Companion

Listen-Bot is a silence-first, production-grade Ionic + React + Vite application that listens continuously, streams live transcripts, and keeps the UI disciplined for long-form sessions. It is engineered for Whisper/Deepgram style backends while remaining fully functional with on-device Web Speech fallback and keyboard input.

## ✨ What’s inside
- **Field.tsx** — sliding glass transcript surface with semantic highlights, entity taps, and focus overlay.
- **useVoiceStream.ts** — microphone + SpeechRecognition pipeline with rolling buffer, quiet-mode aware acknowledgements, and typed-text fallback.
- **useAutoPunctuation.ts** — post-processor for streaming text.
- **QuietMode.tsx** — quiet listening + minimal acknowledgement toggles.
- **AppShell.tsx** — responsive Ionic shell with live status badge.
- **styles/theme.css** — flat, shadow-free theme tuned for mobile-first responsiveness.

## 📦 Requirements
- Node.js **18+** and npm.
- Modern Chromium-based browser for Web Speech fallback.
- Optional backend keys via environment variables:
  - `VITE_API_URL` — streaming transcription endpoint (WebSocket/HTTP).
  - `VITE_TRANSCRIBE_KEY` — Whisper/Deepgram auth token.
  - `VITE_TTS_KEY` — reserved for future TTS output.

## 🚀 Setup
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173` and allow microphone access. If SpeechRecognition is unavailable, use the keyboard fallback textarea — both paths feed the same rendering pipeline.

## 🧪 Testing
```bash
cd frontend
npm test
```
Vitest runs with a jsdom environment and covers auto-punctuation logic plus interactive Field semantics.

## 📱 Usage
- Tap **Start listening** to request mic access and render the Field surface.
- Speak naturally; transcripts stream continuously with auto punctuation.
- Tap highlighted entities, dates, or times to focus; tap outside to resume flow.
- Enable **Quiet mode** to keep Listen-Bot silent unless prompted. Turn on **Minimal acknowledgements** for subtle affirmations when you explicitly invite them.
- Use the **Keyboard fallback** textarea to inject text into the same pipeline when silence is required.

## 🧭 Deployment
- Build with `npm run build`; output lives in `frontend/dist`.
- Ionic + Vite bundles are PWA-ready and can be wrapped with Capacitor for Android/iOS deployment.

## 🔒 Security & Privacy
- No transcripts leave the browser unless you wire in an authenticated backend with `VITE_API_URL` and keys.
- Microphone permission is requested only on demand and can be revoked at any time via browser controls.
