import React, { useState, useEffect } from 'react';
import { History, ShieldCheck, AlertOctagon, Link2, RefreshCw, ChevronRight, FileText } from 'lucide-react';
import { AuditLogEntry } from '@warden/shared';

export const AuditLogExplorer: React.FC = () => {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [integrity, setIntegrity] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [selectedLog, setSelectedLog] = useState<AuditLogEntry | null>(null);

  const fetchAuditLogs = async () => {
    setLoading(true);
    try {
      const res = await fetch('/v1/audit-log');
      const data = await res.json();
      setLogs(data.logs);
      setIntegrity(data.integrity);
      if (data.logs.length > 0 && !selectedLog) {
        setSelectedLog(data.logs[0]);
      }
    } catch (e) {
      console.error('Failed to fetch audit log:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAuditLogs();
  }, []);

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-emerald-500/20 pb-4">
        <div>
          <h2 className="text-xl font-extrabold text-white flex items-center space-x-2">
            <History size={22} className="text-emerald-400" />
            <span>Tamper-Evident Audit Chain</span>
          </h2>
          <p className="text-slate-400 text-xs mt-0.5 font-mono">
            Immutable SHA-256 hash-chained event log recording all scans, decisions, and certificates.
          </p>
        </div>

        <button
          onClick={fetchAuditLogs}
          className="flex items-center space-x-2 px-4 py-2 rounded-xl btn-shiny-glass text-xs font-mono font-semibold shrink-0 cursor-pointer"
        >
          <RefreshCw size={14} className="text-emerald-400" />
          <span>Re-verify Chain Integrity</span>
        </button>
      </div>

      {/* Status Banner */}
      {integrity && (
        <div className={`p-4 rounded-2xl border flex items-center justify-between font-mono shadow-lg ${
          integrity.valid
            ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300 shadow-emerald-500/10'
            : 'bg-rose-500/10 border-rose-500/30 text-rose-300 shadow-rose-500/10'
        }`}>
          <div className="flex items-center space-x-3">
            {integrity.valid ? <ShieldCheck size={22} className="text-emerald-400" /> : <AlertOctagon size={22} className="text-rose-400" />}
            <div>
              <span className="font-bold text-xs uppercase tracking-wider">
                {integrity.valid ? 'CRYPTO HASH CHAIN VALIDATED' : 'AUDIT CHAIN COMPROMISED!'}
              </span>
              <p className="text-xs text-slate-300 mt-0.5">
                {integrity.valid
                  ? `All ${integrity.total_rows} entries match sequential SHA-256 row hashes.`
                  : integrity.reason}
              </p>
            </div>
          </div>
          <span className="text-xs font-semibold px-3 py-1 bg-slate-950/80 rounded-lg border border-slate-800 text-slate-200">
            Chain Length: {integrity.total_rows}
          </span>
        </div>
      )}

      {/* Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Logs List */}
        <div className="lg:col-span-2 glass-panel p-4 space-y-3">
          <div className="text-xs font-mono font-semibold text-emerald-400 uppercase px-1">Sequential Event Log</div>
          <div className="space-y-2 max-h-[520px] overflow-y-auto pr-1">
            {logs.map((log) => (
              <div
                key={log.id}
                onClick={() => setSelectedLog(log)}
                className={`p-3.5 rounded-xl cursor-pointer transition-all border flex items-center justify-between ${
                  selectedLog?.id === log.id
                    ? 'bg-emerald-950/30 border-emerald-500/50 shadow-md shadow-emerald-950/30'
                    : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center space-x-3 font-mono">
                  <div className="px-2.5 py-1 bg-slate-900 rounded-lg text-emerald-400 text-xs font-bold border border-slate-800">
                    #{log.id}
                  </div>
                  <div>
                    <div className="text-xs font-bold text-white flex items-center space-x-2">
                      <span className="text-cyan-400 uppercase">{log.event_type}</span>
                      <span className="text-slate-400">• {log.actor}</span>
                    </div>
                    <div className="text-xs text-slate-400 flex items-center space-x-1.5 mt-0.5">
                      <Link2 size={12} className="text-slate-500" />
                      <span>{log.row_hash.substring(0, 22)}...</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center space-x-2 text-slate-400 text-xs font-mono">
                  <span>{new Date(log.created_at).toLocaleTimeString()}</span>
                  <ChevronRight size={15} />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Selected Log Drawer */}
        {selectedLog && (
          <div className="glass-panel p-5 space-y-4 font-mono">
            <h3 className="text-sm font-bold text-white flex items-center space-x-2 uppercase tracking-wider">
              <FileText size={16} className="text-emerald-400" />
              <span>Event Detail #{selectedLog.id}</span>
            </h3>

            <div className="space-y-3">
              <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 space-y-0.5">
                <span className="text-[10px] text-slate-400 uppercase font-semibold">Event Type</span>
                <div className="text-xs font-bold text-cyan-400 uppercase">{selectedLog.event_type}</div>
              </div>

              <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 space-y-0.5">
                <span className="text-[10px] text-slate-400 uppercase font-semibold">Actor</span>
                <div className="text-xs font-bold text-slate-200">{selectedLog.actor}</div>
              </div>

              <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 space-y-0.5">
                <span className="text-[10px] text-slate-400 uppercase font-semibold">Prev Row Hash</span>
                <div className="text-xs text-slate-400 break-all select-all">
                  {selectedLog.prev_row_hash}
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 space-y-0.5">
                <span className="text-[10px] text-slate-400 uppercase font-semibold">Row Hash</span>
                <div className="text-xs text-emerald-400 break-all select-all font-bold">
                  {selectedLog.row_hash}
                </div>
              </div>

              <div className="space-y-1.5">
                <span className="text-xs font-semibold text-emerald-300 uppercase">Payload Detail</span>
                <pre className="p-3 rounded-xl code-container text-xs text-cyan-300 leading-relaxed max-h-44 overflow-y-auto">
                  {JSON.stringify(selectedLog.detail, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
