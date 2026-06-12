import { Layout, Page } from "features/Layout";
import Storage from "features/storage/components/Storage";

function Index(): JSX.Element {
  return (
    <Layout page={Page.Storage} title="Save / Storage">
      <Storage />
    </Layout>
  );
}

export default Index;
