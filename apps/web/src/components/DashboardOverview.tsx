import React, { useState, useEffect } from 'react';
import { Shield, Award, CheckCircle2, ArrowRight, Terminal, Activity, Link2, Search, Zap, AlertTriangle, ShieldCheck, TrendingUp, BarChart2 } from 'lucide-react';
import { WardenCertificate } from '@warden/shared';

interface DashboardOverviewProps {
  stats: {
    totalTools: number;
    activeCertificates: number;
    totalScans: number;
    auditIntegrityValid: boolean;
    recentLogsCount: number;
    riskDistribution: { none: number; low: number; medium: number; high: number; critical: number };
    certStats: { active: number; revoked: number; invalidated: number; expired: number; total: number };
    recentActivity: Array<{ id: number; event_type: string; actor: string; entity_id: string; created_at: string }>;
    eventCounts: Record<string, number>;
  };
  onNavigate: (tab: string) => void;
}

const EVENT_TYPE_LABELS: Record<string, { label: string; color: string }> = {
  scan_created: { label: 'Scan', color: 'text-cyan-400' },
  decision_made: { label: 'Decision', color: 'text-purple-400' },
  cert_issued: { label: 'Cert Issued', color: 'text-emerald-400' },
  cert_imported: { label: 'Cert Imported', color: 'text-blue-400' },
  cert_revoked: { label: 'Cert Revoked', color: 'text-rose-400' },
  cert_invalidated: { label: 'Invalidated', color: 'text-amber-400' },
  org_updated: { label: 'Org Updated', color: 'text-indigo-400' },
};

// SVG Risk Donut Chart (no external libs)
const RiskDonutChart: React.FC<{ distribution: { none: number; low: number; medium: number; high: number; critical: number } }> = ({ distribution }) => {
  const total = Object.values(distribution).reduce((a, b) => a + b, 0);
  if (total === 0) {
    return (
      <div className="flex items-center justify-center h-36 text-slate-500 text-xs font-mono">
        No scans yet
      </div>
    );
  }

  const segments = [
    { key: 'none', value: distribution.none, color: '#22d3ee', label: 'Clean' },
    { key: 'low', value: distribution.low, color: '#a3e635', label: 'Low' },
    { key: 'medium', value: distribution.medium, color: '#fbbf24', label: 'Medium' },
    { key: 'high', value: distribution.high, color: '#f97316', label: 'High' },
    { key: 'critical', value: distribution.critical, color: '#f87171', label: 'Critical' },
  ];

  const cx = 60, cy = 60, r = 48, innerR = 32;
  let cumulativeAngle = -90;

  const polarToXY = (angle: number, radius: number) => {
    const rad = (angle * Math.PI) / 180;
    return { x: cx + radius * Math.cos(rad), y: cy + radius * Math.sin(rad) };
  };

  const createArcPath = (startAngle: number, endAngle: number) => {
    const start = polarToXY(startAngle, r);
    const end = polarToXY(endAngle, r);
    const innerStart = polarToXY(endAngle, innerR);
    const innerEnd = polarToXY(startAngle, innerR);
    const largeArc = endAngle - startAngle > 180 ? 1 : 0;
    return [
      `M ${start.x} ${start.y}`,
      `A ${r} ${r} 0 ${largeArc} 1 ${end.x} ${end.y}`,
      `L ${innerStart.x} ${innerStart.y}`,
      `A ${innerR} ${innerR} 0 ${largeArc} 0 ${innerEnd.x} ${innerEnd.y}`,
      'Z',
    ].join(' ');
  };

  return (
    <div className="flex items-center gap-5">
      <svg width="120" height="120" viewBox="0 0 120 120" className="shrink-0">
        {segments.map((seg) => {
          if (seg.value === 0) return null;
          const angle = (seg.value / total) * 360;
          const startAngle = cumulativeAngle;
          cumulativeAngle += angle;
          const endAngle = cumulativeAngle;
          return (
            <path
              key={seg.key}
              d={createArcPath(startAngle, endAngle - 0.5)}
              fill={seg.color}
              opacity={0.85}
              className="transition-opacity duration-200 hover:opacity-100"
            />
          );
        })}
        <text x={cx} y={cy - 5} textAnchor="middle" className="font-mono font-bold" fill="#f1f5f9" fontSize="14">{total}</text>
        <text x={cx} y={cy + 9} textAnchor="middle" fill="#94a3b8" fontSize="7" fontFamily="monospace">scans</text>
      </svg>
      <div className="space-y-1.5 flex-1 min-w-0">
        {segments.map((seg) => (
          seg.value > 0 && (
            <div key={seg.key} className="flex items-center justify-between gap-2 font-mono text-[11px]">
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: seg.color }} />
                <span className="text-slate-300">{seg.label}</span>
              </div>
              <div className="flex items-center gap-1.5">
                <div className="h-1 bg-slate-800 rounded-full w-14 overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{ width: `${(seg.value / total) * 100}%`, backgroundColor: seg.color }}
                  />
                </div>
                <span className="text-slate-200 font-semibold w-4 text-right">{seg.value}</span>
              </div>
            </div>
          )
        ))}
      </div>
    </div>
  );
};

// Animated Activity Feed
const ActivityFeed: React.FC<{ events: Array<{ id: number; event_type: string; actor: string; created_at: string }> }> = ({ events }) => {
  if (events.length === 0) {
    return (
      <div className="py-6 text-center text-slate-500 text-xs font-mono">No recent activity.</div>
    );
  }
  return (
    <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
      {events.map((event, idx) => {
        const meta = EVENT_TYPE_LABELS[event.event_type] || { label: event.event_type, color: 'text-slate-400' };
        return (
          <div
            key={event.id}
            className="flex items-center gap-3 p-2.5 rounded-xl bg-slate-950/60 border border-slate-800/60 group hover:border-slate-700/80 transition-all"
            style={{ animationDelay: `${idx * 50}ms` }}
          >
            <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${meta.color.replace('text-', 'bg-')}`} />
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 font-mono text-[11px]">
                <span className={`font-bold uppercase ${meta.color}`}>{meta.label}</span>
                <span className="text-slate-500">•</span>
                <span className="text-slate-400 truncate">{event.actor}</span>
              </div>
            </div>
            <span className="text-[10px] text-slate-500 font-mono shrink-0">
              {new Date(event.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
            </span>
          </div>
        );
      })}
    </div>
  );
};

// Mini bar chart for event types
const EventCountBar: React.FC<{ counts: Record<string, number> }> = ({ counts }) => {
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5);
  const maxVal = entries[0]?.[1] || 1;
  if (entries.length === 0) return <div className="text-xs text-slate-500 font-mono py-4 text-center">No events yet</div>;

  const colors: Record<string, string> = {
    scan_created: '#22d3ee',
    decision_made: '#a78bfa',
    cert_issued: '#34d399',
    cert_revoked: '#f87171',
    cert_imported: '#60a5fa',
    cert_invalidated: '#fbbf24',
    org_updated: '#818cf8',
  };

  return (
    <div className="space-y-2">
      {entries.map(([type, count]) => (
        <div key={type} className="flex items-center gap-2 font-mono text-[11px]">
          <span className="text-slate-400 w-24 truncate shrink-0">{EVENT_TYPE_LABELS[type]?.label || type.replace(/_/g, ' ')}</span>
          <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
            <div
              className="h-full rounded-full transition-all duration-700"
              style={{
                width: `${(count / maxVal) * 100}%`,
                backgroundColor: colors[type] || '#64748b'
              }}
            />
          </div>
          <span className="text-slate-200 font-bold w-5 text-right">{count}</span>
        </div>
      ))}
    </div>
  );
};

export const DashboardOverview: React.FC<DashboardOverviewProps> = ({ stats, onNavigate }) => {
  const [recentCerts, setRecentCerts] = useState<WardenCertificate[]>([]);

  useEffect(() => {
    fetch('/v1/registry/search?q=')
      .then((res) => res.json())
      .then((data) => {
        if (Array.isArray(data)) setRecentCerts(data.slice(0, 5));
      })
      .catch(() => {});
  }, [stats]);

  return (
    <div className="space-y-6">
      {/* Top Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">
            Security Overview
          </h1>
          <p className="text-slate-400 text-xs mt-0.5 font-mono">
            Model Context Protocol trust registry, active certificates, and audit status.
          </p>
        </div>

        <div className="flex items-center space-x-2 shrink-0">
          <button
            onClick={() => onNavigate('scanner')}
            className="px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center space-x-1.5 transition-all cursor-pointer shadow-sm shadow-cyan-600/30"
          >
            <Terminal size={14} />
            <span>Inspect Tool</span>
          </button>
          <button
            onClick={() => onNavigate('certificates')}
            className="px-3.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 text-xs font-medium flex items-center space-x-1.5 transition-all cursor-pointer"
          >
            <Award size={14} className="text-cyan-400" />
            <span>Certificates</span>
          </button>
        </div>
      </div>

      {/* Unified Metrics Strip */}
      <div className="rounded-xl border border-slate-800 bg-slate-950/80 divide-y md:divide-y-0 md:divide-x divide-slate-800/80 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 shadow-lg">
        <div className="p-4 space-y-1">
          <div className="text-slate-400 text-[11px] font-mono uppercase tracking-wider font-semibold">Tracked Tools</div>
          <div className="text-2xl font-bold font-mono text-white">{stats.totalTools}</div>
          <div className="text-[11px] text-slate-500">Registered MCP servers</div>
        </div>

        <div className="p-4 space-y-1">
          <div className="text-slate-400 text-[11px] font-mono uppercase tracking-wider font-semibold">Active Certificates</div>
          <div className="text-2xl font-bold font-mono text-white">{stats.activeCertificates}</div>
          <div className="text-[11px] text-emerald-400 font-mono flex items-center space-x-1 font-semibold">
            <CheckCircle2 size={12} />
            <span>Ed25519 Signed</span>
          </div>
        </div>

        <div className="p-4 space-y-1">
          <div className="text-slate-400 text-[11px] font-mono uppercase tracking-wider font-semibold">Evaluated Scans</div>
          <div className="text-2xl font-bold font-mono text-white">{stats.totalScans}</div>
          <div className="text-[11px] text-slate-500">Static risk analyses</div>
        </div>

        <div className="p-4 space-y-1">
          <div className="text-slate-400 text-[11px] font-mono uppercase tracking-wider font-semibold">Audit Chain</div>
          <div className="text-xl font-bold font-mono text-white flex items-center space-x-2">
            <span className={stats.auditIntegrityValid ? 'text-emerald-400' : 'text-rose-400'}>
              {stats.auditIntegrityValid ? 'CHAIN VALID' : 'COMPROMISED'}
            </span>
          </div>
          <div className="text-[11px] text-slate-500 font-mono">{stats.recentLogsCount} row hashes</div>
        </div>
      </div>

      {/* Middle row: Risk Chart + Event Activity + Cert Status */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Risk Distribution Donut */}
        <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-5 shadow-lg space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
              <BarChart2 size={14} className="text-cyan-400" />
              Risk Distribution
            </h3>
            <button
              onClick={() => onNavigate('scanner')}
              className="text-[10px] font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer"
            >
              Scan <ArrowRight size={10} />
            </button>
          </div>
          <RiskDonutChart distribution={stats.riskDistribution} />
        </div>

        {/* Certificate Status Breakdown */}
        <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-5 shadow-lg space-y-3">
          <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
            <Award size={14} className="text-emerald-400" />
            Certificate Health
          </h3>
          <div className="space-y-2.5 font-mono">
            {[
              { label: 'Active', value: stats.certStats.active, color: '#34d399' },
              { label: 'Revoked', value: stats.certStats.revoked, color: '#f87171' },
              { label: 'Invalidated', value: stats.certStats.invalidated, color: '#fbbf24' },
              { label: 'Expired', value: stats.certStats.expired, color: '#94a3b8' },
            ].map(({ label, value, color }) => {
              const total = stats.certStats.total || 1;
              return (
                <div key={label} className="flex items-center gap-2 text-[11px]">
                  <span className="text-slate-400 w-20 shrink-0">{label}</span>
                  <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all duration-700"
                      style={{ width: `${(value / total) * 100}%`, backgroundColor: color }}
                    />
                  </div>
                  <span className="text-slate-200 font-bold w-5 text-right">{value}</span>
                </div>
              );
            })}
            <div className="border-t border-slate-800 pt-2 mt-1">
              <div className="flex justify-between text-[10px] text-slate-500 font-mono">
                <span>Total Certificates</span>
                <span className="font-bold text-slate-300">{stats.certStats.total}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Event Counts */}
        <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-5 shadow-lg space-y-3">
          <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
            <TrendingUp size={14} className="text-purple-400" />
            Event Breakdown
          </h3>
          <EventCountBar counts={stats.eventCounts} />
        </div>
      </div>

      {/* Bottom row: Active Registry Table + Activity Feed + Security Modules */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Active Registry Table */}
        <div className="lg:col-span-1 rounded-xl border border-slate-800 bg-slate-950/80 p-5 space-y-4 shadow-lg">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                Recent Certified Tools
              </h3>
              <p className="text-slate-400 text-xs">Active Ed25519 trust certificates</p>
            </div>
            <button
              onClick={() => onNavigate('certificates')}
              className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center space-x-1 cursor-pointer"
            >
              <span>All ({stats.activeCertificates})</span>
              <ArrowRight size={12} />
            </button>
          </div>

          <div className="space-y-2">
            {recentCerts.length === 0 ? (
              <div className="p-6 text-center text-slate-500 text-xs font-mono">
                No active trust certificates issued yet.
              </div>
            ) : (
              recentCerts.map((cert) => (
                <div
                  key={cert.certificate_id}
                  onClick={() => onNavigate('certificates')}
                  className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition-all cursor-pointer flex items-center justify-between"
                >
                  <div className="space-y-0.5 min-w-0">
                    <div className="flex items-center space-x-2">
                      <span className="font-mono text-xs font-bold text-white truncate">{cert.tool.name}</span>
                      <span className="text-[10px] font-mono text-slate-400 bg-slate-800 px-1.5 rounded shrink-0">
                        v{cert.tool.version}
                      </span>
                    </div>
                    <div className="text-[11px] font-mono text-slate-500">
                      {cert.tool.hash.substring(0, 20)}...
                    </div>
                  </div>

                  <div className="flex items-center space-x-3 text-right shrink-0 ml-2">
                    <span className="text-[10px] font-mono uppercase font-bold px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      {cert.decision.outcome}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Live Activity Feed */}
        <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-5 space-y-4 shadow-lg">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
                <Zap size={14} className="text-amber-400" />
                Live Activity Feed
              </h3>
              <p className="text-slate-400 text-xs">Real-time audit events (5s polling)</p>
            </div>
            <button
              onClick={() => onNavigate('audit')}
              className="text-xs font-mono text-emerald-400 hover:text-emerald-300 flex items-center space-x-1 cursor-pointer"
            >
              <span>Full Log</span>
              <ArrowRight size={12} />
            </button>
          </div>
          <ActivityFeed events={stats.recentActivity} />
        </div>

        {/* Security Module Quick Launch */}
        <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-5 space-y-4 shadow-lg">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono border-b border-slate-800/80 pb-3">
            Security Modules
          </h3>

          <div className="space-y-3">
            <div
              onClick={() => onNavigate('scanner')}
              className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-cyan-500/40 transition-all cursor-pointer group"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2.5">
                  <Shield size={16} className="text-cyan-400" />
                  <span className="text-xs font-bold text-white group-hover:text-cyan-300 transition-colors">Risk Scanner</span>
                </div>
                <ArrowRight size={14} className="text-slate-500 group-hover:text-cyan-400 transition-colors" />
              </div>
              <p className="text-[11px] text-slate-400 mt-1.5 leading-relaxed">
                Inspect MCP manifests for prompt injection, read-only mismatches, and wildcard scope.
              </p>
            </div>

            <div
              onClick={() => onNavigate('policy')}
              className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-purple-500/40 transition-all cursor-pointer group"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2.5">
                  <Activity size={16} className="text-purple-400" />
                  <span className="text-xs font-bold text-white group-hover:text-purple-300 transition-colors">Policy Engine</span>
                </div>
                <ArrowRight size={14} className="text-slate-500 group-hover:text-purple-400 transition-colors" />
              </div>
              <p className="text-[11px] text-slate-400 mt-1.5 leading-relaxed">
                Dry-run YAML organizational policy rules against historical tool scan results.
              </p>
            </div>

            <div
              onClick={() => onNavigate('audit')}
              className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-emerald-500/40 transition-all cursor-pointer group"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2.5">
                  <Link2 size={16} className="text-emerald-400" />
                  <span className="text-xs font-bold text-white group-hover:text-emerald-300 transition-colors">Audit Trail</span>
                </div>
                <ArrowRight size={14} className="text-slate-500 group-hover:text-emerald-400 transition-colors" />
              </div>
              <p className="text-[11px] text-slate-400 mt-1.5 leading-relaxed">
                Verify cryptographic tamper-evident SHA-256 row hash integrity across all events.
              </p>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
};
