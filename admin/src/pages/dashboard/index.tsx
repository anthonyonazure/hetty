import { Layout, Page } from "features/Layout";
import Dashboard from "features/dashboard/components/Dashboard";

function Index(): JSX.Element {
  return (
    <Layout page={Page.Dashboard} title="Dashboard">
      <Dashboard />
    </Layout>
  );
}

export default Index;
