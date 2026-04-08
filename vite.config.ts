import { defineConfig } from "vite";

function resolvePagesBase(): string {
  const explicitBase = process.env.PAGES_BASE_PATH;
  if (explicitBase) {
    return explicitBase;
  }

  const repositoryName = process.env.GITHUB_REPOSITORY?.split("/")[1] ?? "";
  if (!repositoryName || repositoryName.endsWith(".github.io")) {
    return "/";
  }

  return `/${repositoryName}/`;
}

export default defineConfig(() => ({
  base: "/crypto-lab-format-ward/",
  server: {
    host: true,
    port: 5173
  }
}));
