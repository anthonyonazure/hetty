import { Layout, Page } from "features/Layout";
import Authz from "features/authz/components/Authz";

function Index(): JSX.Element {
  return (
    <Layout page={Page.Authz} title="Authz">
      <Authz />
    </Layout>
  );
}

export default Index;
