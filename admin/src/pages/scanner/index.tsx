import { Layout, Page } from "features/Layout";
import Scanner from "features/scanner/components/Scanner";

function Index(): JSX.Element {
  return (
    <Layout page={Page.Scanner} title="Scanner">
      <Scanner />
    </Layout>
  );
}

export default Index;
