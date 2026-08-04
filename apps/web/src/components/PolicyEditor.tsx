import React, { useState } from 'react';
import { FileCode2, Play, CheckCircle2, AlertTriangle, ShieldX, Sparkles } from 'lucide-react';

const DEFAULT_POLICY_YAML = `- id: rule-injection
  condition: "finding.type == 'prompt_injection'"
  finding_type: prompt_injection
  outcome: block
  reason: "Detected prompt injection pattern in tool description."

- id: rule-permission-mismatch
  condition: "finding.type == 'permission_mismatch' and finding.severity == 'high'"
  finding_type: permission_mismatch
  min_severity: high
  outcome: sandbox
  reason: "Tool capability exceeds stated description; requires sandbox monitoring."

- id: rule-excessive-scope
  condition: "finding.type == 'excessive_permission' and finding.severity == 'high'"
  finding_type: excessive_permission
  min_severity: high
  outcome: sandbox
  reason: "Wildcard or root filesystem access requested."

- id: default
  condition: default
  outcome: allow
  reason: "Matches default organizational trust policy."
`;

export const PolicyEditor: React.FC = () => {
  const [policyYaml, setPolicyYaml] = useState(DEFAULT_POLICY_YAML);
  const [simulating, setSimulating] = useState(false);
  const [simResult, setSimResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const handleRunSimulation = async () => {
    setSimulating(true);
    setError(null);
    setSimResult(null);

    try {
      const res = await fetch('/v1/policies/default/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rules: policyYaml, limit: 50 }),
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || 'Simulation failed.');
      }

      const data = await res.json();
      setSimResult(data);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSimulating(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="border-b border-purple-500/20 pb-4">
        <h2 className="text-xl font-extrabold text-white flex items-center space-x-2">
          <FileCode2 size={22} className="text-purple-400" />
          <span>Policy Engine & Simulator</span>
        </h2>
        <p className="text-slate-400 text-xs mt-0.5 font-mono">
          Define declarative trust policies in YAML and dry-run candidate rules against past scan history.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Editor Column */}
        <div className="glass-panel p-5 space-y-4">
          <div className="flex items-center justify-between font-mono">
            <span className="text-xs font-semibold text-purple-300 uppercase tracking-wider">Policy Rules (YAML)</span>
            <span className="text-xs text-purple-400 font-bold">DSL v1.0 Standard</span>
          </div>

          <textarea
            rows={16}
            value={policyYaml}
            onChange={(e) => setPolicyYaml(e.target.value)}
            className="w-full p-3.5 rounded-xl code-container text-xs text-purple-300 focus:outline-none focus:border-purple-500 leading-relaxed shadow-inner"
          />

          <button
            onClick={handleRunSimulation}
            disabled={simulating}
            className="w-full py-2.5 rounded-xl btn-shiny-purple text-xs font-mono flex items-center justify-center space-x-2 cursor-pointer"
          >
            {simulating ? (
              <span>Evaluating Dry-Run Simulator...</span>
            ) : (
              <>
                <Play size={14} fill="currentColor" />
                <span>Simulate Candidate Policy Impact</span>
              </>
            )}
          </button>

          {error && (
            <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono">
              {error}
            </div>
          )}
        </div>

        {/* Simulation Output Column */}
        <div className="glass-panel p-5 space-y-5">
          <div className="flex items-center justify-between border-b border-purple-500/20 pb-3">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center space-x-2">
              <Sparkles size={16} className="text-purple-400" />
              <span>Dry-Run Impact Analysis</span>
            </h3>
          </div>

          {!simResult ? (
            <div className="h-64 flex flex-col items-center justify-center text-slate-500 space-y-2 border border-dashed border-slate-800 rounded-xl">
              <FileCode2 size={24} className="opacity-40" />
              <p className="text-xs font-mono">Click "Simulate Candidate Policy Impact" to run rules against past scans.</p>
            </div>
          ) : (
            <div className="space-y-5">
              {/* Summary Outcome Cards */}
              <div className="grid grid-cols-3 gap-3 font-mono">
                <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-center space-y-1 shadow-sm shadow-emerald-500/10">
                  <span className="text-xs font-semibold text-emerald-400 flex items-center justify-center space-x-1">
                    <CheckCircle2 size={13} />
                    <span>ALLOW</span>
                  </span>
                  <div className="text-2xl font-extrabold text-emerald-300">{simResult.outcomes.allow}</div>
                </div>

                <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 text-center space-y-1 shadow-sm shadow-amber-500/10">
                  <span className="text-xs font-semibold text-amber-400 flex items-center justify-center space-x-1">
                    <AlertTriangle size={13} />
                    <span>SANDBOX</span>
                  </span>
                  <div className="text-2xl font-extrabold text-amber-300">{simResult.outcomes.sandbox}</div>
                </div>

                <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-center space-y-1 shadow-sm shadow-rose-500/10">
                  <span className="text-xs font-semibold text-rose-400 flex items-center justify-center space-x-1">
                    <ShieldX size={13} />
                    <span>BLOCK</span>
                  </span>
                  <div className="text-2xl font-extrabold text-rose-300">{simResult.outcomes.block}</div>
                </div>
              </div>

              {/* Scans Impact List */}
              <div className="space-y-2 font-mono">
                <span className="text-xs font-semibold text-purple-300 uppercase">
                  Evaluated Tool Scans ({simResult.changes.length})
                </span>
                <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                  {simResult.changes.map((item: any, i: number) => (
                    <div key={i} className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1">
                      <div className="flex items-center justify-between text-xs font-semibold">
                        <span className="text-white">{item.tool_name}</span>
                        <span className={`uppercase font-bold text-xs ${
                          item.simulated_outcome === 'allow'
                            ? 'text-emerald-400'
                            : item.simulated_outcome === 'sandbox'
                            ? 'text-amber-400'
                            : 'text-rose-400'
                        }`}>
                          {item.simulated_outcome}
                        </span>
                      </div>
                      <p className="text-xs text-slate-300">{item.reason}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
