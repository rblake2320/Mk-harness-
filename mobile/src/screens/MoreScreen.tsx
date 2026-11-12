import { Button, H1, P, Screen } from '../components/ui';
import type { Route } from '../logic/navigation';

export default function MoreScreen({ push, who, onSignOut }: { push: (r: Route) => void; who: string; onSignOut: () => void }) {
  return (
    <Screen>
      <H1>More</H1>
      <P muted>{who}</P>
      <Button kind="ghost" label="Status and governance" text="Status & governance" onPress={() => push({ name: 'status' })}
              hint="Whether sending is possible right now, kill switches, sending numbers and passkeys" />
      <Button kind="ghost" label="Ask anything" onPress={() => push({ name: 'chat' })} />
      <Button kind="ghost" label="Skin studio" onPress={() => push({ name: 'skin' })} />
      <P small muted>Settings, passkeys, billing, exports and account deletion are on the web app.</P>
      <Button kind="danger" label="Sign out" onPress={onSignOut} />
    </Screen>
  );
}
