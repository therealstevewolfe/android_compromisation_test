import { PropsWithChildren } from 'react';
import { IonContent, IonHeader, IonTitle, IonToolbar } from '@ionic/react';

interface AppShellProps extends PropsWithChildren {
  statusBadge: React.ReactNode;
}

export const AppShell = ({ children, statusBadge }: AppShellProps) => (
  <div className="app-shell">
    <IonHeader translucent={true} collapse="fade">
      <IonToolbar className="glass" color="light">
        <IonTitle>Listen-Bot</IonTitle>
        <div className="toolbar-badge" slot="end">
          {statusBadge}
        </div>
      </IonToolbar>
    </IonHeader>
    <IonContent fullscreen={true} className="content-shell">
      {children}
    </IonContent>
  </div>
);
