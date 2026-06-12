import { Layout, Page } from "features/Layout";
import Distributed from "features/cluster/components/Distributed";

function Index(): JSX.Element {
  return (
    <Layout page={Page.Cluster} title="Distributed">
      <Distributed />
    </Layout>
  );
}

export default Index;
