import { Layout, Page } from "features/Layout";
import Templates from "features/template/components/Templates";

function Index(): JSX.Element {
  return (
    <Layout page={Page.Templates} title="Templates">
      <Templates />
    </Layout>
  );
}

export default Index;
