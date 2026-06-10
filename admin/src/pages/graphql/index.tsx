import { Layout, Page } from "features/Layout";
import GraphQL from "features/gql/components/GraphQL";

function Index(): JSX.Element {
  return (
    <Layout page={Page.GraphQL} title="GraphQL">
      <GraphQL />
    </Layout>
  );
}

export default Index;
