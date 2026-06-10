import { Layout, Page } from "features/Layout";
import Jwt from "features/jwt/components/Jwt";

function Index(): JSX.Element {
  return (
    <Layout page={Page.Jwt} title="JWT">
      <Jwt />
    </Layout>
  );
}

export default Index;
