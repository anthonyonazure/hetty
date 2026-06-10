import { Layout, Page } from "features/Layout";
import AIAnalyst from "features/ai/components/AIAnalyst";

function Index(): JSX.Element {
  return (
    <Layout page={Page.AIAnalyst} title="AI Analyst">
      <AIAnalyst />
    </Layout>
  );
}

export default Index;
