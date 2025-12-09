import { IonItem, IonLabel, IonToggle } from '@ionic/react';

interface QuietModeProps {
  quietMode: boolean;
  minimalAcknowledgement: boolean;
  onQuietChange: (value: boolean) => void;
  onMinimalChange: (value: boolean) => void;
}

export const QuietMode = ({ quietMode, minimalAcknowledgement, onQuietChange, onMinimalChange }: QuietModeProps) => (
  <div className="quiet-panel glass">
    <IonItem lines="none" className="inline-item">
      <IonLabel>Quiet mode</IonLabel>
      <IonToggle
        aria-label="Toggle quiet listening"
        checked={quietMode}
        onIonChange={(event) => onQuietChange(event.detail.checked)}
      />
    </IonItem>
    <IonItem lines="none" className="inline-item">
      <IonLabel>Minimal acknowledgements</IonLabel>
      <IonToggle
        aria-label="Toggle minimal acknowledgements"
        checked={minimalAcknowledgement}
        disabled={!quietMode}
        onIonChange={(event) => onMinimalChange(event.detail.checked)}
      />
    </IonItem>
    <p className="muted">Listen indefinitely. Respond only when invited — gentle affirmations when you ask for them.</p>
  </div>
);
