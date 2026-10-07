import React from 'react';
import { 
  ShieldCheck, ShieldAlert, Cpu, Network, Globe, Lock, 
  Terminal, ArrowRight, CheckCircle2, ChevronRight, Zap, Eye
} from 'lucide-react';

interface LandingProps {
  onAnalyze: (target: string) => void;
  onExplore: () => void;
  onLogin: () => void;
  onRegister: () => void;
}

export const LandingPage: React.FC<LandingProps> = ({ onAnalyze, onExplore, onLogin, onRegister }) => {
  const [targetInput, setTargetInput] = React.useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (targetInput.trim()) {
      onAnalyze(targetInput.trim());
    }
  };

  const capabilities = [
    { title: 'AI URL Analysis', desc: 'Real-time lexical, entropy, and structural neural heuristic inspection.', icon: Cpu },
    { title: 'Phishing & Lookalike Detection', desc: 'Identifies brand typosquatting, IDN homoglyphs, and credential harvesting hooks.', icon: ShieldAlert },
    { title: 'Domain & DNS Intelligence', desc: 'Deep resolution of A, AAAA, MX, NS, TXT, and authoritative nameservers.', icon: Network },
    { title: 'TLS / SSL Handshake Audit', desc: 'Examines certificate timeline, trust chain, SAN domains, and cipher strength.', icon: Lock },
    { title: 'SSRF & Private Network Guard', desc: 'Active defense blocking requests to internal RFC1918 space and cloud metadata.', icon: ShieldCheck },
    { title: 'Continuous SOC Monitoring', desc: 'Automated polling detecting rogue DNS drift, expiration, and header degradation.', icon: Eye },
  ];

  return (
    <div className="min-h-screen bg-[#070a11] text-gray-100 flex flex-col justify-between selection:bg-red-500/20">
      {/* Hero Section */}
      <div className="relative overflow-hidden pt-12 pb-20 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto w-full">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[350px] bg-red-600/10 blur-[130px] rounded-full pointer-events-none -z-10" />

        <div className="text-center max-w-4xl mx-auto">
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-red-950/60 border border-red-800/40 text-red-400 text-xs font-mono mb-6">
            <span className="w-2 h-2 rounded-full bg-red-500 animate-ping" />
            <span>ENTERPRISE SOC THREAT INTELLIGENCE ENGINE v2.4</span>
          </div>

          <h1 className="text-4xl sm:text-6xl font-extrabold tracking-tight text-white font-sans leading-tight">
            AI-Powered <span className="text-transparent bg-clip-text bg-gradient-to-r from-red-400 via-red-500 to-amber-500">Cyber Threat Intelligence</span>
          </h1>

          <p className="mt-6 text-lg sm:text-xl text-gray-400 max-w-2xl mx-auto leading-relaxed">
            Analyze URLs, domains, IPs, and digital indicators before they materialize into security incidents.
          </p>

          {/* Quick Target Analyzer Bar */}
          <div className="mt-10 max-w-2xl mx-auto">
            <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-2 p-1.5 rounded-xl bg-[#0f1624] border border-gray-800 focus-within:border-red-500/80 shadow-2xl shadow-black/80 transition-all">
              <input
                type="text"
                value={targetInput}
                onChange={(e) => setTargetInput(e.target.value)}
                placeholder="Enter suspicious URL or domain (e.g. login-secure-account.xyz)..."
                className="flex-1 bg-transparent px-4 py-3 text-sm text-gray-200 placeholder-gray-500 focus:outline-none font-mono"
              />
              <button
                type="submit"
                className="px-6 py-3 rounded-lg bg-red-600 hover:bg-red-500 text-white text-sm font-semibold flex items-center justify-center space-x-2 transition-all shadow-lg shadow-red-950"
              >
                <span>Deep Scan</span>
                <ArrowRight size={16} />
              </button>
            </form>
            <div className="mt-3 flex items-center justify-center space-x-4 text-xs text-gray-500 font-mono">
              <span>Try sample:</span>
              <button onClick={() => setTargetInput('https://google.com')} className="hover:text-red-400 underline">google.com</button>
              <button onClick={() => setTargetInput('paypa1-security-login.top')} className="hover:text-red-400 underline">paypa1-security.top</button>
              <button onClick={() => setTargetInput('8.8.8.8')} className="hover:text-red-400 underline">8.8.8.8</button>
            </div>
          </div>

          <div className="mt-8 flex items-center justify-center space-x-4">
            <button
              onClick={onExplore}
              className="px-5 py-2.5 rounded-lg bg-gray-900 border border-gray-700 hover:border-gray-500 text-sm font-medium text-gray-300 hover:text-white transition-all"
            >
              Explore SOC Dashboard
            </button>
            <button
              onClick={onRegister}
              className="px-5 py-2.5 rounded-lg bg-red-950/40 border border-red-800/60 hover:bg-red-900/60 text-sm font-medium text-red-300 transition-all"
            >
              Sign Up For Analysts
            </button>
          </div>
        </div>
      </div>

      {/* Capabilities Grid */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16 border-t border-gray-900 w-full">
        <div className="text-center mb-12">
          <h2 className="text-xs font-mono uppercase tracking-widest text-red-400">Core Systems</h2>
          <p className="mt-2 text-2xl font-bold text-white">Full-Spectrum Cybersecurity Inspection</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {capabilities.map((cap, i) => {
            const Icon = cap.icon;
            return (
              <div 
                key={i} 
                className="p-6 rounded-xl bg-[#0d131f] border border-gray-800/80 hover:border-red-900/60 transition-all group"
              >
                <div className="w-10 h-10 rounded-lg bg-red-950/40 border border-red-800/40 flex items-center justify-center text-red-400 mb-4 group-hover:scale-105 transition-transform">
                  <Icon size={20} />
                </div>
                <h3 className="text-base font-semibold text-white mb-2">{cap.title}</h3>
                <p className="text-sm text-gray-400 leading-relaxed">{cap.desc}</p>
              </div>
            );
          })}
        </div>
      </div>

      {/* Footer */}
      <footer className="border-t border-gray-900 py-8 px-6 text-center text-xs text-gray-600 font-mono">
        <div>THREAT ANALYZE PLATFORM &bull; PRODUCTION-READY CYBERSECURITY DEFENSE SYSTEM</div>
        <div className="mt-1">Built with strict SSRF defenses, zero simulated statistics, and real native network inspection.</div>
      </footer>
    </div>
  );
};
