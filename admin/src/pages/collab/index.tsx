import { Layout, Page } from "features/Layout";
import Collab from "features/collab/components/Collab";

function Index(): JSX.Element {
  return (
    <Layout page={Page.Collab} title="Collaborator">
      <Collab />
    </Layout>
  );
}

export default Index;
