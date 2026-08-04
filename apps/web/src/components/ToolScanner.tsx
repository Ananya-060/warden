import React, { useState } from 'react';
import { Search, ShieldAlert, CheckCircle2, Play, FileJson, ArrowRight, GitCommit } from 'lucide-react';

interface ToolScannerProps {
  onScanComplete: () => void;
  onNavigateToCertificates: () => void;
}

const SAMPLE_PRESETS = [
  {
    name: '@mcp/server-github',
    manifest: {
      name: '@modelcontextprotocol/server-github',
      version: '0.6.2',
      description: 'Official Model Context Protocol server for GitHub integration. Enables LLM agents to interact with repositories, issues, pull requests, commits, and branches.',
      source_url: 'https://github.com/modelcontextprotocol/servers/tree/main/src/github',
      permissions: ['repo.read', 'repo.write', 'issues.read', 'issues.write', 'pull_requests.read', 'pull_requests.write'],
      tools: [
        { name: 'create_or_update_file', description: 'Create or update a single file in a GitHub repository.' },
        { name: 'search_repositories', description: 'Search for GitHub repositories using query parameters.' },
        { name: 'create_issue', description: 'Create a new issue in a GitHub repository.' },
        { name: 'get_file_contents', description: 'Get the contents of a file or directory in a GitHub repository.' },
        { name: 'create_pull_request', description: 'Create a new pull request in a GitHub repository.' },
      ],
    },
  },
  {
    name: '@mcp/server-slack',
    manifest: {
      name: '@modelcontextprotocol/server-slack',
      version: '0.4.1',
      description: 'Official Model Context Protocol server for Slack workspace integration. Allows AI assistants to inspect channels, post messages, add reactions, and fetch thread context.',
      source_url: 'https://github.com/modelcontextprotocol/servers/tree/main/src/slack',
      permissions: ['channels.read', 'chat.write', 'reactions.write', 'history.read'],
      tools: [
        { name: 'slack_list_channels', description: 'List public or private channels in the connected Slack workspace.' },
        { name: 'slack_post_message', description: 'Post a message to a specified Slack channel.' },
        { name: 'slack_get_channel_history', description: 'Fetch historical messages from a Slack channel.' },
        { name: 'slack_add_reaction', description: 'Add an emoji reaction to a message.' },
      ],
    },
  },
  {
    name: '@mcp/server-sqlite',
    manifest: {
      name: '@modelcontextprotocol/server-sqlite',
      version: '0.5.0',
      description: 'Official Model Context Protocol server for SQLite databases. Exposes schema inspection, SQL queries, and table operations.',
      source_url: 'https://github.com/modelcontextprotocol/servers/tree/main/src/sqlite',
      permissions: ['db.read', 'db.write'],
      tools: [
        { name: 'sqlite_read_query', description: 'Execute a SELECT query on the SQLite database.' },
        { name: 'sqlite_list_tables', description: 'List all tables in the SQLite database.' },
        { name: 'sqlite_describe_table', description: 'Get column definitions and schema information for a specific table.' },
        { name: 'sqlite_create_table', description: 'Create a new table in the database schema.' },
      ],
    },
  },
  {
    name: '@mcp/server-filesystem',
    manifest: {
      name: '@modelcontextprotocol/server-filesystem',
      version: '0.5.2',
      description: 'Official Model Context Protocol server for local filesystem access. Enables AI agents to read, list, and modify files within designated allowed paths.',
      source_url: 'https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem',
      permissions: ['fs.read', 'fs.write'],
      tools: [
        { name: 'read_file', description: 'Read complete UTF-8 contents of a file from an allowed path.' },
        { name: 'write_file', description: 'Write content to a file at an allowed path.' },
        { name: 'list_directory', description: 'List files and directories contained within a given path.' },
        { name: 'get_file_info', description: 'Retrieve metadata for a file or directory.' },
      ],
    },
  },
  {
    name: '@mcp/server-puppeteer',
    manifest: {
      name: '@modelcontextprotocol/server-puppeteer',
      version: '0.4.0',
      description: 'Official Model Context Protocol server for Puppeteer browser automation. Enables headless page navigation, screenshot capture, and element clicking.',
      source_url: 'https://github.com/modelcontextprotocol/servers/tree/main/src/puppeteer',
      permissions: ['browser.navigate', 'browser.interact'],
      tools: [
        { name: 'puppeteer_navigate', description: 'Navigate the automated browser to a specified URL.' },
        { name: 'puppeteer_screenshot', description: 'Capture a screenshot of the currently loaded browser page.' },
        { name: 'puppeteer_click', description: 'Click an element on the active web page using CSS selector.' },
      ],
    },
  },
];

export const ToolScanner: React.FC<ToolScannerProps> = ({ onScanComplete, onNavigateToCertificates }) => {
  const [toolName, setToolName] = useState(SAMPLE_PRESETS[0].manifest.name);
  const [manifestJson, setManifestJson] = useState(JSON.stringify(SAMPLE_PRESETS[0].manifest, null, 2));
  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [approving, setApproving] = useState(false);

  const loadPreset = (preset: typeof SAMPLE_PRESETS[0]) => {
    setToolName(preset.manifest.name);
    setManifestJson(JSON.stringify(preset.manifest, null, 2));
    setScanResult(null);
    setError(null);
  };

  const handleRunScan = async () => {
    setLoading(true);
    setError(null);
    setScanResult(null);

    try {
      let parsedManifest;
      try {
        parsedManifest = JSON.parse(manifestJson);
      } catch (e) {
        throw new Error('Invalid JSON format in manifest editor.');
      }

      const res = await fetch('/v1/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tool_name: toolName || parsedManifest.name || 'mcp-tool',
          manifest: parsedManifest,
          actor: 'dashboard:user',
        }),
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || 'Scan failed.');
      }

      const data = await res.json();
      setScanResult(data);
      onScanComplete();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const handleApproveAndIssueCert = async () => {
    if (!scanResult) return;
    setApproving(true);
    setError(null);

    try {
      const decRes = await fetch('/v1/decisions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_id: scanResult.scan.id, actor: 'dashboard:user' }),
      });

      if (!decRes.ok) {
        const errData = await decRes.json();
        throw new Error(errData.error || 'Policy evaluation failed.');
      }

      const decision = await decRes.json();

      if (decision.outcome === 'block') {
        throw new Error(`Cannot issue certificate! Policy Outcome: BLOCKED. Reason: ${decision.reason}`);
      }

      const certRes = await fetch('/v1/certificates', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision_id: decision.id, actor: 'dashboard:user' }),
      });

      if (!certRes.ok) {
        const errData = await certRes.json();
        throw new Error(errData.error || 'Certificate issuance failed.');
      }

      onScanComplete();
      onNavigateToCertificates();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setApproving(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-cyan-500/20 pb-4">
        <div>
          <h2 className="text-xl font-extrabold text-white flex items-center space-x-2">
            <Search size={20} className="text-cyan-400" />
            <span>MCP Tool Risk Scanner</span>
          </h2>
          <p className="text-slate-400 text-xs mt-0.5 font-mono">
            Inspect tool manifest, compute RFC 8785 canonical hash, and run static risk checkers.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-xs text-slate-400 font-mono">Presets:</span>
          {SAMPLE_PRESETS.map((p, idx) => (
            <button
              key={idx}
              onClick={() => loadPreset(p)}
              className="px-3 py-1 rounded-lg bg-slate-900/80 hover:bg-slate-800 text-slate-300 border border-slate-700/80 text-xs font-mono transition-all cursor-pointer shadow-sm"
            >
              {p.name}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Editor Column */}
        <div className="glass-panel p-5 space-y-4">
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-cyan-300 uppercase tracking-wider font-mono">Tool Identifier</label>
            <input
              type="text"
              value={toolName}
              onChange={(e) => setToolName(e.target.value)}
              className="w-full px-3.5 py-2 rounded-xl bg-slate-950/80 border border-slate-800 text-cyan-300 font-mono text-xs focus:outline-none focus:border-cyan-500 transition-colors shadow-inner"
              placeholder="github-mcp-server"
            />
          </div>

          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-cyan-300 uppercase tracking-wider font-mono flex items-center space-x-1.5">
                <FileJson size={14} className="text-cyan-400" />
                <span>Manifest JSON</span>
              </label>
              <span className="text-[10px] text-slate-400 font-mono">RFC 8785 Canonical Compatible</span>
            </div>
            <textarea
              rows={14}
              value={manifestJson}
              onChange={(e) => setManifestJson(e.target.value)}
              className="w-full p-3.5 rounded-xl code-container text-cyan-300 font-mono text-xs focus:outline-none focus:border-cyan-500 leading-relaxed shadow-inner"
            />
          </div>

          <button
            onClick={handleRunScan}
            disabled={loading}
            className="w-full py-2.5 rounded-xl btn-shiny-cyan text-xs flex items-center justify-center space-x-2 cursor-pointer"
          >
            {loading ? (
              <span>Running Risk Checkers...</span>
            ) : (
              <>
                <Play size={14} fill="currentColor" />
                <span>Run Risk Inspection</span>
              </>
            )}
          </button>

          {error && (
            <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono">
              <div className="font-semibold flex items-center space-x-1.5 mb-1">
                <ShieldAlert size={15} className="text-rose-400" />
                <span>Inspection Error</span>
              </div>
              <p className="text-[11px]">{error}</p>
            </div>
          )}
        </div>

        {/* Results Column */}
        <div className="glass-panel p-5 space-y-5">
          <div className="flex items-center justify-between border-b border-cyan-500/20 pb-3">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              Inspection Report
            </h3>
          </div>

          {!scanResult ? (
            <div className="h-64 flex flex-col items-center justify-center text-slate-500 space-y-2 border border-dashed border-slate-800 rounded-xl">
              <Search size={24} className="opacity-40" />
              <p className="text-xs font-mono">Click "Run Risk Inspection" to analyze manifest.</p>
            </div>
          ) : (
            <div className="space-y-5">
              {/* Tool Hash */}
              <div className="p-3.5 rounded-xl code-container space-y-1">
                <span className="text-[10px] font-mono text-cyan-400 uppercase font-semibold">Canonical SHA-256 Hash</span>
                <div className="font-mono text-xs text-slate-200 break-all select-all font-semibold">
                  {scanResult.scan.tool_hash}
                </div>
              </div>

              {/* Findings */}
              <div className="space-y-2.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono uppercase text-slate-300 font-semibold">
                    Risk Findings ({scanResult.findings.length})
                  </span>
                  <span className={`text-[10px] px-2.5 py-0.5 rounded-md font-mono font-bold uppercase ${
                    scanResult.findings.some((f: any) => f.severity === 'critical')
                      ? 'badge-block'
                      : scanResult.findings.some((f: any) => f.severity === 'high')
                      ? 'badge-sandbox'
                      : 'badge-allow'
                  }`}>
                    {scanResult.findings.length === 0 ? 'Passed' : `${scanResult.findings.length} Flagged`}
                  </span>
                </div>

                {scanResult.findings.length === 0 ? (
                  <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs font-mono flex items-center space-x-2.5">
                    <CheckCircle2 size={16} className="text-emerald-400 shrink-0" />
                    <span>No security risks detected. Tool manifest is clean and compliant.</span>
                  </div>
                ) : (
                  <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
                    {scanResult.findings.map((f: any) => (
                      <div key={f.id} className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="text-[11px] font-mono text-cyan-400">{f.checker}</span>
                          <span className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded ${
                            f.severity === 'critical' ? 'badge-block' : 'badge-sandbox'
                          }`}>
                            {f.severity}
                          </span>
                        </div>
                        <p className="text-xs text-slate-200">{f.description}</p>
                        {f.evidence && (
                          <div className="text-[11px] font-mono text-slate-400 bg-slate-900 p-2 rounded border border-slate-800 break-all">
                            Evidence: {f.evidence}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Manifest Diff */}
              {scanResult.diff && (
                <div className="space-y-1.5">
                  <span className="text-xs font-mono uppercase text-slate-300 flex items-center space-x-1">
                    <GitCommit size={14} className="text-cyan-400" />
                    <span>Manifest Diff</span>
                  </span>
                  <pre className="p-3 rounded-xl code-container text-xs font-mono text-slate-300">
                    {scanResult.diff}
                  </pre>
                </div>
              )}

              {/* Issue Certificate Button */}
              <button
                onClick={handleApproveAndIssueCert}
                disabled={approving}
                className="w-full py-2.5 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-semibold text-xs font-mono flex items-center justify-center space-x-2 shadow-md shadow-emerald-600/20 transition-all cursor-pointer"
              >
                {approving ? (
                  <span>Evaluating Policy & Issuing Certificate...</span>
                ) : (
                  <>
                    <span>Apply Policy & Issue Trust Certificate</span>
                    <ArrowRight size={14} />
                  </>
                )}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
