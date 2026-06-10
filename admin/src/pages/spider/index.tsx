import { Layout, Page } from "features/Layout";
import Spider from "features/spider/components/Spider";

function Index(): JSX.Element {
  return (
    <Layout page={Page.Spider} title="Spider">
      <Spider />
    </Layout>
  );
}

export default Index;
