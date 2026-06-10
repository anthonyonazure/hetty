import { Layout, Page } from "features/Layout";
import Rules from "features/rules/components/Rules";

function Index(): JSX.Element {
  return (
    <Layout page={Page.Rules} title="Match & Replace">
      <Rules />
    </Layout>
  );
}

export default Index;
