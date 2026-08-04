import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar.tsx';
import { DashboardOverview } from './components/DashboardOverview.tsx';
import { ToolScanner } from './components/ToolScanner.tsx';
import { CertificateManager } from './components/CertificateManager.tsx';
import { PolicyEditor } from './components/PolicyEditor.tsx';
import { AuditLogExplorer } from './components/AuditLogExplorer.tsx';
import { OrgSettings } from './components/OrgSettings.tsx';

export function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [apiConnected, setApiConnected] = useState(false);
  const [stats, setStats] = useState({
    totalTools: 0,
    activeCertificates: 0,
    totalScans: 0,
    auditIntegrityValid: true,
    recentLogsCount: 0,
    riskDistribution: { none: 0, low: 0, medium: 0, high: 0, critical: 0 },
    certStats: { active: 0, revoked: 0, invalidated: 0, expired: 0, total: 0 },
    recentActivity: [] as any[],
    eventCounts: {} as Record<string, number>,
  });

  const checkHealthAndStats = async () => {
    try {
      const [healthRes, statsRes] = await Promise.all([
        fetch('/v1/health'),
        fetch('/v1/stats'),
      ]);

      if (healthRes.ok) {
        setApiConnected(true);

        if (statsRes.ok) {
          const statsData = await statsRes.json();
          setStats(statsData);
        }
      } else {
        setApiConnected(false);
      }
    } catch (e) {
      setApiConnected(false);
    }
  };

  useEffect(() => {
    checkHealthAndStats();
    const interval = setInterval(checkHealthAndStats, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen text-slate-100 flex flex-col font-sans">
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} apiConnected={apiConnected} />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'overview' && (
          <DashboardOverview stats={stats} onNavigate={(tab) => setActiveTab(tab)} />
        )}
        {activeTab === 'scanner' && (
          <ToolScanner
            onScanComplete={checkHealthAndStats}
            onNavigateToCertificates={() => setActiveTab('certificates')}
          />
        )}
        {activeTab === 'certificates' && (
          <CertificateManager onRefresh={checkHealthAndStats} />
        )}
        {activeTab === 'policy' && <PolicyEditor />}
        {activeTab === 'audit' && <AuditLogExplorer />}
        {activeTab === 'settings' && <OrgSettings onRefresh={checkHealthAndStats} />}
      </main>

      <footer className="border-t border-cyan-500/10 py-5 text-center text-xs text-slate-400 bg-[#060810]/90 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3 font-mono text-xs">
          <div className="text-slate-300">
            <span className="font-bold gradient-text-cyan">WARDEN v1.0.0</span> — Portable Trust Infrastructure for AI Tools
          </div>
          <div className="flex items-center space-x-4 text-slate-400">
            <span>Ed25519 Cryptographic Signatures</span>
            <span>•</span>
            <span>SHA-256 Audit Trail</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
