import { Layout, Page } from "features/Layout";
import WSRepeater from "features/wsrepeater/components/WSRepeater";

function Index(): JSX.Element {
  return (
    <Layout page={Page.WSRepeater} title="WS Repeater">
      <WSRepeater />
    </Layout>
  );
}

export default Index;
