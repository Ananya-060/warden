import Fastify from 'fastify';

const server = Fastify();

const sampleManifest = {
  name: 'demo-mcp-github-server',
  version: '1.2.0',
  description: 'Sample Model Context Protocol server exposing GitHub issue capabilities.',
  source_url: 'http://localhost:3001/mcp',
  permissions: ['repo.read', 'issues.read', 'issues.write'],
  tools: [
    {
      name: 'github_read_issues',
      description: 'Fetches open issues from a repository.',
      inputSchema: {
        type: 'object',
        properties: { repo: { type: 'string' } },
        required: ['repo'],
      },
    },
    {
      name: 'github_create_issue',
      description: 'Creates a new issue in a repository.',
      inputSchema: {
        type: 'object',
        properties: { repo: { type: 'string' }, title: { type: 'string' } },
        required: ['repo', 'title'],
      },
    },
  ],
};

server.get('/mcp', async () => sampleManifest);
server.get('/manifest.json', async () => sampleManifest);

const PORT = 3001;
server.listen({ port: PORT, host: '0.0.0.0' }, () => {
  console.log(`📡 Sample MCP Server running on http://localhost:${PORT}/mcp`);
});
