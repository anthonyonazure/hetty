import { Layout, Page } from "features/Layout";
import Intruder from "features/intruder/components/Intruder";

function Index(): JSX.Element {
  return (
    <Layout page={Page.Intruder} title="Intruder">
      <Intruder />
    </Layout>
  );
}

export default Index;
