import { Layout, Page } from "features/Layout";
import Sitemap from "features/sitemap/components/Sitemap";

function Index(): JSX.Element {
  return (
    <Layout page={Page.Sitemap} title="Site Map">
      <Sitemap />
    </Layout>
  );
}

export default Index;
