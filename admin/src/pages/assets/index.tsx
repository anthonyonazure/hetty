import { Layout, Page } from "features/Layout";
import Assets from "features/assets/components/Assets";

function Index(): JSX.Element {
  return (
    <Layout page={Page.Assets} title="Assets">
      <Assets />
    </Layout>
  );
}

export default Index;
