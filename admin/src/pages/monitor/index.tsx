import { Layout, Page } from "features/Layout";
import Monitoring from "features/monitor/components/Monitoring";

function Index(): JSX.Element {
  return (
    <Layout page={Page.Monitor} title="Monitoring">
      <Monitoring />
    </Layout>
  );
}

export default Index;
