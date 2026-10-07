import React, { useState } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Navigation } from './components/Navigation';
import { LandingPage } from './pages/LandingPage';
import { DashboardPage } from './pages/DashboardPage';
import { UrlAnalyzerPage } from './pages/UrlAnalyzerPage';
import { DomainIntelligencePage } from './pages/DomainIntelligencePage';
import { DnsAnalyzerPage } from './pages/DnsAnalyzerPage';
import { IpIntelligencePage } from './pages/IpIntelligencePage';
import { TlsAnalyzerPage } from './pages/TlsAnalyzerPage';
import { WebsiteSecurityPage } from './pages/WebsiteSecurityPage';
import { QrScannerPage } from './pages/QrScannerPage';
import { WatchlistMonitoringPage } from './pages/WatchlistMonitoringPage';
import { AlertsPage } from './pages/AlertsPage';
import { ReportsPage } from './pages/ReportsPage';
import { SystemHealthPage } from './pages/SystemHealthPage';
import { SettingsPage } from './pages/SettingsPage';
import { AdminAuditPage } from './pages/AdminAuditPage';
import { LoginPage, RegisterPage } from './pages/AuthPages';

function MainApp() {
  const [currentTab, setCurrentTab] = useState<string>('landing');
  const [activeTarget, setActiveTarget] = useState<string>('');

  const handleGlobalSearch = (query: string) => {
    setActiveTarget(query);
    // Route intelligently based on target format
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(query) || query.includes(':')) {
      setCurrentTab('ip-intelligence');
    } else if (query.includes('/') || query.startsWith('http')) {
      setCurrentTab('url-analyzer');
    } else {
      setCurrentTab('domains');
    }
  };

  const handleStartAnalysis = (target: string) => {
    setActiveTarget(target);
    setCurrentTab('url-analyzer');
  };

  return (
    <div className="min-h-screen bg-[#070a11] text-gray-100 flex flex-col font-sans">
      <Navigation
        currentTab={currentTab}
        setCurrentTab={setCurrentTab}
        onGlobalSearch={handleGlobalSearch}
      />

      <main className={`flex-1 transition-all ${currentTab !== 'landing' ? 'pt-16 lg:pl-64' : 'pt-16'}`}>
        {currentTab === 'landing' && (
          <LandingPage
            onAnalyze={handleStartAnalysis}
            onExplore={() => setCurrentTab('dashboard')}
            onLogin={() => setCurrentTab('login')}
            onRegister={() => setCurrentTab('register')}
          />
        )}

        {currentTab === 'dashboard' && (
          <DashboardPage
            onSelectScan={(scanId) => {
              setCurrentTab('reports');
            }}
            onNavigateToAnalyzer={() => setCurrentTab('url-analyzer')}
          />
        )}

        {currentTab === 'url-analyzer' && (
          <UrlAnalyzerPage initialTarget={activeTarget} />
        )}

        {currentTab === 'domains' && (
          <DomainIntelligencePage initialDomain={activeTarget} />
        )}

        {currentTab === 'dns' && <DnsAnalyzerPage />}

        {currentTab === 'ip-intelligence' && <IpIntelligencePage />}

        {currentTab === 'tls' && <TlsAnalyzerPage />}

        {currentTab === 'website-security' && <WebsiteSecurityPage />}

        {currentTab === 'qr-scanner' && (
          <QrScannerPage onInspectUrl={handleStartAnalysis} />
        )}

        {currentTab === 'watchlist' && <WatchlistMonitoringPage />}
        {currentTab === 'monitoring' && <WatchlistMonitoringPage />}

        {currentTab === 'alerts' && (
          <AlertsPage onInspectTarget={handleStartAnalysis} />
        )}

        {currentTab === 'reports' && <ReportsPage />}

        {currentTab === 'system-health' && <SystemHealthPage />}

        {currentTab === 'settings' && <SettingsPage />}

        {currentTab === 'admin' && <AdminAuditPage />}

        {currentTab === 'login' && (
          <LoginPage
            onSwitchToRegister={() => setCurrentTab('register')}
            onSuccess={() => setCurrentTab('dashboard')}
          />
        )}

        {currentTab === 'register' && (
          <RegisterPage
            onSwitchToLogin={() => setCurrentTab('login')}
            onSuccess={() => setCurrentTab('dashboard')}
          />
        )}
      </main>
    </div>
  );
}

export function App() {
  return (
    <AuthProvider>
      <MainApp />
    </AuthProvider>
  );
}

export default App;
