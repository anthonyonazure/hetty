import { Layout, Page } from "features/Layout";
import Sessions from "features/session/components/Sessions";

function Index(): JSX.Element {
  return (
    <Layout page={Page.Sessions} title="Auth Profiles">
      <Sessions />
    </Layout>
  );
}

export default Index;
