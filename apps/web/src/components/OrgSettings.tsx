import React, { useState, useEffect } from 'react';
import { Building2, Key, RefreshCw, Save, ShieldCheck, Copy, Check, AlertTriangle, ExternalLink, Info } from 'lucide-react';

interface OrgSettingsProps {
  onRefresh: () => void;
}

export const OrgSettings: React.FC<OrgSettingsProps> = ({ onRefresh }) => {
  const [org, setOrg] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [orgName, setOrgName] = useState('');
  const [saving, setSaving] = useState(false);
  const [saveStatus, setSaveStatus] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [policy, setPolicy] = useState<any>(null);

  const fetchOrgData = async () => {
    setLoading(true);
    try {
      const [orgRes, policyRes] = await Promise.all([
        fetch('/v1/organization'),
        fetch('/v1/policies'),
      ]);
      if (orgRes.ok) {
        const orgData = await orgRes.json();
        setOrg(orgData);
        setOrgName(orgData.name || '');
      }
      if (policyRes.ok) {
        const policies = await policyRes.json();
        if (Array.isArray(policies) && policies.length > 0) {
          setPolicy(policies.find((p: any) => p.active) || policies[0]);
        }
      }
    } catch (e) {
      console.error('Failed to fetch org data', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchOrgData();
  }, []);

  const handleSaveName = async () => {
    setSaving(true);
    setSaveStatus(null);
    try {
      const res = await fetch('/v1/organization', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: orgName, actor: 'dashboard:admin' }),
      });
      if (res.ok) {
        setSaveStatus('Organization name updated successfully.');
        onRefresh();
        await fetchOrgData();
      } else {
        setSaveStatus('Failed to update organization name.');
      }
    } catch (e) {
      setSaveStatus(`Error: ${(e as Error).message}`);
    } finally {
      setSaving(false);
    }
  };

  const handleCopyKey = () => {
    if (org?.ca_public_key) {
      navigator.clipboard.writeText(org.ca_public_key).then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      });
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400 text-sm font-mono">
        Loading organization settings...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-700/50 pb-4">
        <div>
          <h2 className="text-xl font-extrabold text-white flex items-center space-x-2">
            <Building2 size={22} className="text-indigo-400" />
            <span>Organization Settings</span>
          </h2>
          <p className="text-slate-400 text-xs mt-0.5 font-mono">
            Manage trust authority identity, CA public key, and active security policy.
          </p>
        </div>
        <button
          onClick={fetchOrgData}
          className="flex items-center space-x-2 px-4 py-2 rounded-xl btn-shiny-glass text-xs font-mono font-semibold shrink-0 cursor-pointer"
        >
          <RefreshCw size={14} className="text-indigo-400" />
          <span>Refresh</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Organization Identity */}
        <div className="glass-panel p-6 space-y-5">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
            <Building2 size={15} className="text-indigo-400" />
            Organization Identity
          </h3>

          {/* Org ID */}
          <div className="space-y-1.5">
            <label className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider font-mono">Organization ID</label>
            <div className="p-3 rounded-xl code-container text-xs text-slate-400 font-mono break-all select-all">
              {org?.id || '—'}
            </div>
          </div>

          {/* Org Name */}
          <div className="space-y-1.5">
            <label className="text-[10px] font-semibold text-indigo-300 uppercase tracking-wider font-mono">Organization Name</label>
            <input
              type="text"
              value={orgName}
              onChange={(e) => setOrgName(e.target.value)}
              className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950/80 border border-slate-800 text-white font-mono text-sm focus:outline-none focus:border-indigo-500 transition-colors"
              placeholder="Enter organization name..."
            />
            <div className="flex items-center justify-between">
              {saveStatus && (
                <p className={`text-xs font-mono ${saveStatus.includes('Error') || saveStatus.includes('Failed') ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {saveStatus}
                </p>
              )}
              <button
                onClick={handleSaveName}
                disabled={saving || orgName === org?.name}
                className="ml-auto flex items-center gap-2 px-4 py-2 rounded-xl btn-shiny-cyan text-xs font-mono cursor-pointer disabled:opacity-40"
              >
                <Save size={13} />
                <span>{saving ? 'Saving...' : 'Save Name'}</span>
              </button>
            </div>
          </div>

          {/* Created At */}
          <div className="space-y-1.5">
            <label className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider font-mono">Created At</label>
            <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 text-xs text-slate-300 font-mono">
              {org?.created_at ? new Date(org.created_at).toLocaleString() : '—'}
            </div>
          </div>
        </div>

        {/* CA Public Key & Crypto */}
        <div className="glass-panel p-6 space-y-5">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
            <Key size={15} className="text-amber-400" />
            Certificate Authority
          </h3>

          {/* Key Status Banner */}
          <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center gap-3">
            <ShieldCheck size={18} className="text-emerald-400 shrink-0" />
            <div>
              <div className="text-xs font-bold text-emerald-300">Ed25519 CA Key — Active</div>
              <p className="text-[11px] text-slate-400 mt-0.5">
                {org?.ca_key_managed_externally ? 'Key managed externally (HSM/KMS).' : 'Key managed by Warden in-process (development mode).'}
              </p>
            </div>
          </div>

          {/* Public Key */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label className="text-[10px] font-semibold text-amber-300 uppercase tracking-wider font-mono">CA Public Key (Ed25519)</label>
              <button
                onClick={handleCopyKey}
                className="flex items-center gap-1 text-[10px] font-mono text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
              >
                {copied ? <Check size={11} className="text-emerald-400" /> : <Copy size={11} />}
                <span>{copied ? 'Copied!' : 'Copy'}</span>
              </button>
            </div>
            <div className="p-3 rounded-xl code-container text-[11px] text-amber-300 font-mono break-all select-all leading-relaxed">
              {org?.ca_public_key || '—'}
            </div>
          </div>

          {/* Algorithm Info */}
          <div className="grid grid-cols-2 gap-3 font-mono">
            <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 space-y-0.5">
              <span className="text-[10px] text-slate-500 uppercase font-semibold">Algorithm</span>
              <div className="text-xs font-bold text-white">Ed25519</div>
            </div>
            <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 space-y-0.5">
              <span className="text-[10px] text-slate-500 uppercase font-semibold">Cert Validity</span>
              <div className="text-xs font-bold text-white">12 Months</div>
            </div>
            <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 space-y-0.5">
              <span className="text-[10px] text-slate-500 uppercase font-semibold">Hash Function</span>
              <div className="text-xs font-bold text-white">SHA-256</div>
            </div>
            <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 space-y-0.5">
              <span className="text-[10px] text-slate-500 uppercase font-semibold">Canonical JSON</span>
              <div className="text-xs font-bold text-white">RFC 8785</div>
            </div>
          </div>
        </div>
      </div>

      {/* Active Policy Summary */}
      {policy && (
        <div className="glass-panel p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
              <ShieldCheck size={15} className="text-purple-400" />
              Active Security Policy
            </h3>
            <span className="text-[10px] font-mono px-2.5 py-1 rounded-full bg-purple-500/10 text-purple-300 border border-purple-500/20 font-bold">
              v{policy.version}
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono">
            <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 space-y-0.5">
              <span className="text-[10px] text-slate-500 uppercase font-semibold">Policy Name</span>
              <div className="text-xs font-bold text-white">{policy.name}</div>
            </div>
            <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 space-y-0.5">
              <span className="text-[10px] text-slate-500 uppercase font-semibold">Status</span>
              <div className={`text-xs font-bold ${policy.active ? 'text-emerald-400' : 'text-slate-400'}`}>
                {policy.active ? 'ACTIVE' : 'INACTIVE'}
              </div>
            </div>
          </div>

          <div className="space-y-2">
            <span className="text-xs font-semibold text-purple-300 uppercase font-mono">Policy Rules ({policy.rules?.length || 0})</span>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
              {(policy.rules || []).map((rule: any, idx: number) => (
                <div key={idx} className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1.5 font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] text-purple-300 font-bold uppercase">{rule.id || `rule-${idx + 1}`}</span>
                    <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-md ${
                      rule.outcome === 'allow' ? 'badge-allow' :
                      rule.outcome === 'block' ? 'badge-block' : 'badge-sandbox'
                    }`}>
                      {rule.outcome}
                    </span>
                  </div>
                  {rule.condition && (
                    <div className="text-[10px] text-slate-500 truncate">{rule.condition}</div>
                  )}
                  <p className="text-[11px] text-slate-300 leading-relaxed line-clamp-2">{rule.reason}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="p-3.5 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-start gap-3 text-xs font-mono">
            <Info size={15} className="text-indigo-400 shrink-0 mt-0.5" />
            <p className="text-slate-400 leading-relaxed">
              To modify policy rules, navigate to the <strong className="text-indigo-300">Policy Engine</strong> tab and use the YAML editor with the dry-run simulator before deploying rule changes.
            </p>
          </div>
        </div>
      )}

      {/* Security Notes */}
      <div className="p-4 rounded-2xl bg-amber-500/5 border border-amber-500/20 space-y-2">
        <div className="flex items-center gap-2 text-amber-300 font-mono font-bold text-xs">
          <AlertTriangle size={14} />
          <span>Production Deployment Notes</span>
        </div>
        <ul className="space-y-1.5 text-xs text-slate-400 font-mono list-disc list-inside">
          <li>The CA private key is stored in-process (suitable for dev/staging). For production, use an HSM or KMS.</li>
          <li>Set <code className="text-amber-300">ca_key_managed_externally: true</code> when delegating signing to an external vault.</li>
          <li>Certificates are valid for 12 months. Implement rotation reminders for long-lived registries.</li>
          <li>All certificate operations are immutably recorded in the tamper-evident audit chain.</li>
        </ul>
      </div>
    </div>
  );
};
