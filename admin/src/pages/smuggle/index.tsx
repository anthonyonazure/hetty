import { Layout, Page } from "features/Layout";
import Smuggle from "features/smuggle/components/Smuggle";

function Index(): JSX.Element {
  return (
    <Layout page={Page.Smuggle} title="Smuggle">
      <Smuggle />
    </Layout>
  );
}

export default Index;
