import { Layout, Page } from "features/Layout";
import Macros from "features/macros/components/Macros";

function Index(): JSX.Element {
  return (
    <Layout page={Page.Macros} title="Macros">
      <Macros />
    </Layout>
  );
}

export default Index;
