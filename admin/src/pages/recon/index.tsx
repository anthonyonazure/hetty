import { Layout, Page } from "features/Layout";
import Recon from "features/recon/components/Recon";

function Index(): JSX.Element {
  return (
    <Layout page={Page.Recon} title="Recon">
      <Recon />
    </Layout>
  );
}

export default Index;
