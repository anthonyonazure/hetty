import { Layout, Page } from "features/Layout";
import Comparer from "features/comparer/components/Comparer";

function Index(): JSX.Element {
  return (
    <Layout page={Page.Comparer} title="Comparer">
      <Comparer />
    </Layout>
  );
}

export default Index;
