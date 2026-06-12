import { Layout, Page } from "features/Layout";
import Guide from "features/guide/components/Guide";

function Index(): JSX.Element {
  return (
    <Layout page={Page.Guide} title="Guide">
      <Guide />
    </Layout>
  );
}

export default Index;
