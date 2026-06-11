import { Layout, Page } from "features/Layout";
import ExternalTools from "features/exttools/components/ExternalTools";

function Index(): JSX.Element {
  return (
    <Layout page={Page.ExternalTools} title="External Tools">
      <ExternalTools />
    </Layout>
  );
}

export default Index;
