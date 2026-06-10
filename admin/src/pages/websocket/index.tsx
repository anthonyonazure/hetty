import { Layout, Page } from "features/Layout";
import WebSocketHistory from "features/websocket/components/WebSocket";

function Index(): JSX.Element {
  return (
    <Layout page={Page.WebSocket} title="WebSockets">
      <WebSocketHistory />
    </Layout>
  );
}

export default Index;
