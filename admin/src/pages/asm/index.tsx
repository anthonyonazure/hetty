import { Layout, Page } from "features/Layout";
import AttackSurface from "features/asm/components/AttackSurface";

function Index(): JSX.Element {
  return (
    <Layout page={Page.AttackSurface} title="Attack Surface">
      <AttackSurface />
    </Layout>
  );
}

export default Index;
