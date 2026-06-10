import { Layout, Page } from "features/Layout";
import Discovery from "features/discovery/components/Discovery";

function Index(): JSX.Element {
  return (
    <Layout page={Page.Discovery} title="Discovery">
      <Discovery />
    </Layout>
  );
}

export default Index;
