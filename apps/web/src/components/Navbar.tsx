import React from 'react';
import { ShieldCheck, Scan, Award, FileCode2, History, Settings } from 'lucide-react';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  apiConnected: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({ activeTab, setActiveTab, apiConnected }) => {
  const navItems = [
    { id: 'overview',      label: 'Overview',     icon: ShieldCheck },
    { id: 'scanner',       label: 'Scanner',      icon: Scan },
    { id: 'certificates',  label: 'Certificates', icon: Award },
    { id: 'policy',        label: 'Policy Engine',icon: FileCode2 },
    { id: 'audit',         label: 'Audit Log',    icon: History },
    { id: 'settings',      label: 'Settings',     icon: Settings },
  ];

  return (
    <header className="sticky top-0 z-50 bg-[#070914]/90 backdrop-blur-xl border-b border-cyan-500/20">
      <div className="max-w-7xl mx-auto px-4 sm:px-6">
        <div className="flex items-center justify-between h-13">

          {/* Logo & Connection Dot */}
          <button
            onClick={() => setActiveTab('overview')}
            className="flex items-center space-x-2.5 cursor-pointer focus:outline-none group"
          >
            <div className="p-1.5 rounded-lg bg-gradient-to-br from-cyan-500 to-indigo-600 text-white shadow-sm shadow-cyan-500/20">
              <ShieldCheck size={18} />
            </div>
            <span className="font-extrabold text-sm tracking-wider font-mono gradient-text-cyan">
              WARDEN
            </span>
          </button>

          {/* Clean Navigation Links */}
          <nav className="flex items-center space-x-1">
            {navItems.map(({ id, label, icon: Icon }) => {
              const isActive = activeTab === id;
              return (
                <button
                  key={id}
                  onClick={() => setActiveTab(id)}
                  className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                    isActive
                      ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-400/30'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                  }`}
                >
                  <Icon size={14} className={isActive ? 'text-cyan-400' : 'text-slate-400'} />
                  <span>{label}</span>
                </button>
              );
            })}
          </nav>

          {/* Status Indicator */}
          <div className="flex items-center space-x-2 px-2.5 py-1 rounded-md bg-slate-900/80 border border-slate-800 text-[11px] font-mono text-slate-300">
            <span className={`w-2 h-2 rounded-full ${apiConnected ? 'bg-emerald-400 pulse-emerald-dot' : 'bg-rose-500'}`} />
            <span>{apiConnected ? 'connected' : 'offline'}</span>
          </div>

        </div>
      </div>
    </header>
  );
};
