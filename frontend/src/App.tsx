import { useMemo, useState } from 'react';
import {
  IonButton,
  IonButtons,
  IonCard,
  IonCardContent,
  IonGrid,
  IonIcon,
  IonRow,
  IonCol,
  IonText,
  IonTextarea,
} from '@ionic/react';
import { mic, micOff, pulse, flash } from 'ionicons/icons';
import { AppShell } from './components/AppShell';
import { Field } from './components/Field';
import { QuietMode } from './components/QuietMode';
import { useVoiceStream } from './hooks/useVoiceStream';
import { useTranscriptStore } from './state/transcriptStore';

const statusColor: Record<string, string> = {
  idle: 'muted',
  listening: 'success',
  paused: 'warning',
  error: 'danger',
};

const LiveStatus = ({ status }: { status: string }) => (
  <div className={`badge badge-${statusColor[status] ?? 'muted'}`}>
    <IonIcon icon={status === 'listening' ? pulse : status === 'paused' ? flash : mic} />
    <span>{status}</span>
  </div>
);

const heroCopy = {
  title: 'Silence-first AI listening',
  subtitle:
    'Listen-Bot stays focused on your words. Streaming text, semantic highlights, and calm controls keep you in the flow across any device.',
};

const App = () => {
  const { startListening, stopListening, feedText, segments, liveText, status, error } = useVoiceStream();
  const { quietMode, minimalAcknowledgement, acknowledgementQueue, setMinimalAcknowledgement, setQuietMode } = useTranscriptStore();
  const [manualText, setManualText] = useState('');

  const listening = status === 'listening';

  const lastAcknowledgement = useMemo(() => acknowledgementQueue[acknowledgementQueue.length - 1], [acknowledgementQueue]);

  const handleManualSubmit = () => {
    feedText(manualText);
    setManualText('');
  };

  return (
    <AppShell statusBadge={<LiveStatus status={status} />}>
      <div className="hero">
        <div>
          <p className="pill">Voice-first · Ionic + React</p>
          <h1>{heroCopy.title}</h1>
          <p className="lead">{heroCopy.subtitle}</p>
          <IonButtons className="cta-row">
            <IonButton color="primary" shape="round" onClick={listening ? stopListening : startListening}>
              <IonIcon slot="start" icon={listening ? micOff : mic} />
              {listening ? 'Stop listening' : 'Start listening'}
            </IonButton>
            <IonButton shape="round" fill="outline" onClick={handleManualSubmit} disabled={!manualText.trim()}>
              Send typed text
            </IonButton>
          </IonButtons>
        </div>
        <div className="pulse-wrapper" aria-hidden="true">
          <span className={`pulse ${listening ? 'active' : ''}`}></span>
        </div>
      </div>

      <IonGrid fixed={true} className="layout-grid">
        <IonRow>
          <IonCol size="12" sizeMd="8">
            <Field segments={segments} liveText={liveText} status={status} />
          </IonCol>
          <IonCol size="12" sizeMd="4">
            <IonCard className="glass">
              <IonCardContent>
                <h3>Session controls</h3>
                <p className="muted">Toggle voice capture and feed in typed context when you need silence.</p>
                <div className="control-row">
                  <IonButton expand="block" color={listening ? 'danger' : 'success'} onClick={listening ? stopListening : startListening}>
                    <IonIcon slot="start" icon={listening ? micOff : mic} />
                    {listening ? 'Pause listening' : 'Begin listening'}
                  </IonButton>
                </div>
                <IonTextarea
                  label="Keyboard fallback"
                  labelPlacement="stacked"
                  placeholder="Type to push into the transcript pipeline"
                  value={manualText}
                  autoGrow={true}
                  onIonChange={(event) => setManualText(event.detail.value ?? '')}
                />
                <IonButton expand="block" fill="outline" onClick={handleManualSubmit} disabled={!manualText.trim()}>
                  Push typed text
                </IonButton>
                {lastAcknowledgement ? (
                  <IonText color="success">
                    <p className="muted">Minimal acknowledgement: {lastAcknowledgement}</p>
                  </IonText>
                ) : null}
                {error ? (
                  <IonText color="danger">
                    <p className="muted">{error}</p>
                  </IonText>
                ) : null}
              </IonCardContent>
            </IonCard>

            <QuietMode
              quietMode={quietMode}
              minimalAcknowledgement={minimalAcknowledgement}
              onQuietChange={setQuietMode}
              onMinimalChange={setMinimalAcknowledgement}
            />
          </IonCol>
        </IonRow>
      </IonGrid>
    </AppShell>
  );
};

export default App;
