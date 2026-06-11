import { Layout, Page } from "features/Layout";
import PoC from "features/poc/components/PoC";

function Index(): JSX.Element {
  return (
    <Layout page={Page.PoC} title="PoC Generators">
      <PoC />
    </Layout>
  );
}

export default Index;
