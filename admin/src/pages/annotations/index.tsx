import { Layout, Page } from "features/Layout";
import Annotations from "features/annotations/components/Annotations";

function Index(): JSX.Element {
  return (
    <Layout page={Page.Annotations} title="Annotations">
      <Annotations />
    </Layout>
  );
}

export default Index;
