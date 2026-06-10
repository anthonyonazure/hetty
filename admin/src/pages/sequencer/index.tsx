import { Layout, Page } from "features/Layout";
import Sequencer from "features/sequencer/components/Sequencer";

function Index(): JSX.Element {
  return (
    <Layout page={Page.Sequencer} title="Sequencer">
      <Sequencer />
    </Layout>
  );
}

export default Index;
