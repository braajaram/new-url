import React, { useState } from 'react';
import { 
  ShieldAlert, Activity, Globe, Network, Server, Key, 
  Terminal, Settings, Bell, Search, QrCode, LogOut, User as UserIcon,
  Cpu, FileText, CheckCircle, AlertTriangle, XCircle, ChevronRight, Menu, X, ArrowRight
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

interface NavigationProps {
  currentTab: string;
  setCurrentTab: (tab: string) => void;
  onGlobalSearch: (query: string) => void;
}

export const Navigation: React.FC<NavigationProps> = ({ currentTab, setCurrentTab, onGlobalSearch }) => {
  const { user, logout } = useAuth();
  const [searchInput, setSearchInput] = useState('');
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchInput.trim()) {
      onGlobalSearch(searchInput.trim());
      setSearchInput('');
    }
  };

  const navItems = [
    { id: 'dashboard', label: 'SOC Dashboard', icon: Activity, badge: null },
    { id: 'url-analyzer', label: 'URL Security Analyzer', icon: ShieldAlert, badge: 'CORE' },
    { id: 'domains', label: 'Domain Intelligence', icon: Globe, badge: null },
    { id: 'dns', label: 'DNS Analysis', icon: Network, badge: null },
    { id: 'ip-intelligence', label: 'IP Intelligence', icon: Server, badge: null },
    { id: 'tls', label: 'TLS / SSL Inspector', icon: Key, badge: null },
    { id: 'website-security', label: 'Website Security & Headers', icon: Terminal, badge: null },
    { id: 'qr-scanner', label: 'QR Threat Scanner', icon: QrCode, badge: 'NEW' },
    { id: 'watchlist', label: 'Target Watchlist', icon: Bell, badge: null },
    { id: 'monitoring', label: 'Continuous Monitoring', icon: Activity, badge: null },
    { id: 'alerts', label: 'Security Alerts', icon: AlertTriangle, badge: null },
    { id: 'reports', label: 'Threat Reports', icon: FileText, badge: null },
    { id: 'system-health', label: 'System Health & ML', icon: Cpu, badge: null },
    { id: 'settings', label: 'Platform Settings', icon: Settings, badge: null },
  ];

  if (user?.role === 'admin') {
    navItems.push({ id: 'admin', label: 'Admin & Audit Logs', icon: Terminal, badge: 'ADMIN' });
  }

  return (
    <>
      {/* Top Bar Header */}
      <header className="h-16 border-b border-gray-800/80 bg-[#0d121d]/90 backdrop-blur-md fixed top-0 left-0 right-0 z-40 flex items-center justify-between px-4 lg:px-6">
        <div className="flex items-center space-x-3">
          <button 
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)} 
            className="lg:hidden p-1.5 text-gray-400 hover:text-white rounded-lg bg-gray-900 border border-gray-800"
          >
            {isMobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
          
          <div 
            onClick={() => setCurrentTab('landing')}
            className="flex items-center space-x-2.5 cursor-pointer group"
          >
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-red-600 to-red-950 flex items-center justify-center border border-red-500/40 shadow-lg shadow-red-950/40 group-hover:border-red-400 transition-all">
              <ShieldAlert size={20} className="text-red-400 group-hover:scale-110 transition-transform" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-mono text-base font-bold tracking-wider text-white">THREAT ANALYZE</span>
                <span className="hidden sm:inline-block px-1.5 py-0.5 text-[10px] font-mono uppercase tracking-widest bg-red-950/80 text-red-400 border border-red-800/50 rounded">SOC v2.4</span>
              </div>
              <p className="text-[10px] text-gray-400 tracking-tight hidden sm:block">AI-Powered Threat & IOC Intelligence</p>
            </div>
          </div>
        </div>

        {/* Global Cybersecurity Search Box */}
        <div className="flex-1 max-w-xl mx-4 hidden md:block">
          <form onSubmit={handleSearchSubmit} className="relative">
            <Search size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-500" />
            <input
              type="text"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              placeholder="Investigate URL, Domain, IPv4, IPv6, or File Hash..."
              className="w-full bg-[#131b2c] border border-gray-800 text-sm text-gray-200 placeholder-gray-500 pl-10 pr-24 py-2 rounded-lg focus:outline-none focus:border-red-500/70 focus:ring-1 focus:ring-red-500/50 transition-all font-mono"
            />
            <button
              type="submit"
              className="absolute right-1.5 top-1/2 -translate-y-1/2 px-2.5 py-1 text-xs font-medium bg-red-600/20 text-red-400 border border-red-600/40 hover:bg-red-600 hover:text-white rounded transition-colors flex items-center space-x-1"
            >
              <span>Scan</span>
              <ArrowRight size={12} />
            </button>
          </form>
        </div>

        {/* User Status / Quick Actions */}
        <div className="flex items-center space-x-3">
          {user ? (
            <div className="flex items-center space-x-3">
              <div className="text-right hidden sm:block">
                <div className="text-xs font-semibold text-gray-200">{user.name}</div>
                <div className="text-[10px] text-red-400 font-mono uppercase">{user.role}</div>
              </div>
              <button
                onClick={() => setCurrentTab('settings')}
                className="w-8 h-8 rounded-full bg-gray-800 border border-gray-700 flex items-center justify-center text-gray-300 hover:border-gray-500"
                title="Account Settings"
              >
                <UserIcon size={16} />
              </button>
              <button
                onClick={logout}
                className="p-1.5 text-gray-400 hover:text-red-400 hover:bg-gray-800/80 rounded-lg transition-colors"
                title="Logout"
              >
                <LogOut size={18} />
              </button>
            </div>
          ) : (
            <div className="flex items-center space-x-2">
              <button
                onClick={() => setCurrentTab('login')}
                className="px-3 py-1.5 text-xs text-gray-300 hover:text-white rounded-lg hover:bg-gray-800 transition-colors"
              >
                Login
              </button>
              <button
                onClick={() => setCurrentTab('register')}
                className="px-3 py-1.5 text-xs bg-red-600 hover:bg-red-500 text-white font-medium rounded-lg transition-colors shadow-sm shadow-red-950"
              >
                Join SOC
              </button>
            </div>
          )}
        </div>
      </header>

      {/* Sidebar Navigation */}
      <aside className={`fixed top-16 left-0 bottom-0 w-64 bg-[#0a0e17] border-r border-gray-800/80 z-30 transition-transform duration-200 overflow-y-auto ${
        isMobileMenuOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
      }`}>
        <div className="p-3">
          {/* Mobile Search */}
          <div className="md:hidden mb-4">
            <form onSubmit={handleSearchSubmit} className="relative">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
              <input
                type="text"
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                placeholder="Scan domain, IP, URL..."
                className="w-full bg-[#131b2c] border border-gray-800 text-xs text-gray-200 pl-9 pr-3 py-2 rounded focus:outline-none focus:border-red-500 font-mono"
              />
            </form>
          </div>

          <div className="text-[11px] font-mono uppercase tracking-wider text-gray-500 px-3 py-2 font-semibold">
            Threat Navigation
          </div>

          <div className="space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => {
                    setCurrentTab(item.id);
                    setIsMobileMenuOpen(false);
                  }}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-all ${
                    isActive
                      ? 'bg-red-950/40 text-red-400 border border-red-800/50 shadow-inner'
                      : 'text-gray-400 hover:text-gray-200 hover:bg-gray-900/60'
                  }`}
                >
                  <div className="flex items-center space-x-3">
                    <Icon size={16} className={isActive ? 'text-red-400' : 'text-gray-500'} />
                    <span>{item.label}</span>
                  </div>
                  {item.badge && (
                    <span className="px-1.5 py-0.5 text-[9px] font-mono tracking-wider rounded bg-red-950 text-red-400 border border-red-900/60">
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </div>

          <div className="mt-6 pt-4 border-t border-gray-800/80 px-3">
            <div className="flex items-center justify-between text-[11px] text-gray-500 mb-2 font-mono">
              <span>ENGINE STATUS</span>
              <span className="inline-flex items-center text-emerald-400">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 mr-1.5 animate-pulse"></span>
                ACTIVE
              </span>
            </div>
            <div className="bg-[#111726] border border-gray-800/60 rounded p-2.5 text-[10px] font-mono text-gray-400">
              <div>ML Core: <span className="text-gray-200">v2.4-GBDT</span></div>
              <div className="mt-1">SSRF Guard: <span className="text-emerald-400">ENFORCED</span></div>
              <div className="mt-1">DB: <span className="text-gray-200">ACID STORE</span></div>
            </div>
          </div>
        </div>
      </aside>
    </>
  );
};
