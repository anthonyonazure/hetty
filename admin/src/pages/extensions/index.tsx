import { Layout, Page } from "features/Layout";
import Extensions from "features/extensions/components/Extensions";

function Index(): JSX.Element {
  return (
    <Layout page={Page.Extensions} title="Extensions">
      <Extensions />
    </Layout>
  );
}

export default Index;
