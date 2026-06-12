import { Layout, Page } from "features/Layout";
import Workflows from "features/workflows/components/Workflows";

function Index(): JSX.Element {
  return (
    <Layout page={Page.Workflows} title="Workflows">
      <Workflows />
    </Layout>
  );
}

export default Index;
