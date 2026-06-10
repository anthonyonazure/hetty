import { Layout, Page } from "features/Layout";
import ParamMiner from "features/paramminer/components/ParamMiner";

function Index(): JSX.Element {
  return (
    <Layout page={Page.ParamMiner} title="Param Miner">
      <ParamMiner />
    </Layout>
  );
}

export default Index;
