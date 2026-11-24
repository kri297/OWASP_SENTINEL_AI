import { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  ShieldAlert,
  Globe,
  Sliders,
  CheckSquare,
  Square,
  AlertOctagon,
  ArrowRight,
  Loader2,
  Database,
  FileCode,
  Lock,
  Layers,
  Search,
  Zap,
  Server,
  Sparkles,
  ChevronDown,
  ChevronUp,
  Cpu,
  CheckCircle2,
} from 'lucide-react';
import { startScan, getScan } from '../services/api';

const PRESETS = [
  {
    id: 'quick',
    title: '⚡ Quick Health Audit',
    desc: 'Lightweight checks for headers, SSL certificates & transport security (~5-10s).',
    type: 'quick',
    checks: ['security_headers', 'insecure_config', 'ssl_analysis'],
  },
  {
    id: 'standard',
    title: '🛡️ Standard OWASP Audit',
    desc: 'Recommended: Full headers, configs, exposed secrets, CSRF & technology detection.',
    type: 'full',
    checks: ['security_headers', 'insecure_config', 'sensitive_info', 'csrf', 'tech_fingerprint', 'ssl_analysis', 'dns_recon'],
  },
  {
    id: 'deep',
    title: '🔍 Deep Vulnerability Assessment',
    desc: 'Complete crawl with SQL Injection, XSS probes, and full attack-path correlation.',
    type: 'full',
    checks: ['sql_injection', 'xss', 'security_headers', 'sensitive_info', 'insecure_config', 'csrf', 'tech_fingerprint', 'ssl_analysis', 'dns_recon'],
  },
];

const VULN_CHECKS = [
  { id: 'sql_injection', name: 'SQL Injection Indicators', category: 'A03:2021', icon: Database, desc: 'Tests parameters and forms for unescaped DB syntax errors.' },
  { id: 'xss', name: 'Cross-Site Scripting (XSS)', category: 'A03:2021', icon: FileCode, desc: 'Diagnoses reflection points and unsafe DOM script execution.' },
  { id: 'security_headers', name: 'Defensive Security Headers', category: 'A05:2021', icon: ShieldAlert, desc: 'Audits missing defense-in-depth headers: CSP, HSTS, XFO.' },
  { id: 'sensitive_info', name: 'Sensitive Information Disclosure', category: 'A01:2021', icon: Search, desc: 'Discovers exposed API tokens, debug stack traces & robots.txt.' },
  { id: 'insecure_config', name: 'Insecure Configurations & CORS', category: 'A05:2021', icon: Lock, desc: 'Checks HTTPS enforcement, cookie flags, and wildcard CORS.' },
  { id: 'csrf', name: 'CSRF Form Protection', category: 'A01:2021', icon: Layers, desc: 'Verifies state-changing HTML forms for anti-CSRF synchronizer tokens.' },
  { id: 'tech_fingerprint', name: 'Technology Fingerprinting', category: 'A06:2021', icon: Server, desc: 'Identifies web servers, frameworks, CMS, and frontend libraries.' },
  { id: 'ssl_analysis', name: 'SSL/TLS Cryptographic Health', category: 'A02:2021', icon: Lock, desc: 'Inspects certificate validity, expiry, and cipher suites.' },
  { id: 'dns_recon', name: 'DNS Reconnaissance', category: 'Asset Discovery', icon: Globe, desc: 'Resolves host IPs, subdomains, and canonical names.' },
];

export default function Scanner() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const [url, setUrl] = useState('');
  const [activePreset, setActivePreset] = useState('standard');
  const [selectedChecks, setSelectedChecks] = useState(PRESETS[1].checks);
  const [scanType, setScanType] = useState('full');
  const [authorized, setAuthorized] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);

  // Scan execution state
  const [scanning, setScanning] = useState(false);
  const [activeScanId, setActiveScanId] = useState(null);
  const [scanStatus, setScanStatus] = useState('Initializing scan engine...');
  const [errorMsg, setErrorMsg] = useState('');

  const applyPreset = (preset) => {
    setActivePreset(preset.id);
    setScanType(preset.type);
    setSelectedChecks(preset.checks);
  };

  useEffect(() => {
    const targetParam = searchParams.get('target');
    if (targetParam) {
      setUrl(targetParam);
      setAuthorized(true);
      applyPreset(PRESETS[1]);
    }
  }, [searchParams]);

  const toggleCheck = (id) => {
    setActivePreset('custom');
    setSelectedChecks((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  const handleQuickDemoTarget = (targetUrl, presetId = 'standard') => {
    setUrl(targetUrl);
    setAuthorized(true);
    const p = PRESETS.find(item => item.id === presetId) || PRESETS[1];
    applyPreset(p);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMsg('');

    let targetUrl = url.trim();
    if (!targetUrl) {
      setErrorMsg('Please enter a target web URL to assess.');
      return;
    }

    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      targetUrl = 'https://' + targetUrl;
      setUrl(targetUrl);
    }

    if (!authorized) {
      setErrorMsg('You must certify that you have authorization to test this target application.');
      return;
    }

    if (selectedChecks.length === 0) {
      setErrorMsg('Please select at least one security check module.');
      return;
    }

    try {
      setScanning(true);
      setScanStatus('Launching scan engine...');
      const response = await startScan(targetUrl, scanType, selectedChecks);
      const scanId = response.id || response.scan_id;
      setActiveScanId(scanId);
      setScanStatus('Crawling target and executing diagnostic security modules...');
    } catch (err) {
      console.error('Scan launch failed:', err);
      setErrorMsg(err.response?.data?.error || 'Failed to start vulnerability scan. Verify backend server is running.');
      setScanning(false);
    }
  };

  // Poll scan progress
  useEffect(() => {
    let interval;
    if (scanning && activeScanId) {
      interval = setInterval(async () => {
        try {
          const scan = await getScan(activeScanId);
          if (scan.status === 'completed') {
            clearInterval(interval);
            setScanStatus('Scan complete! Generating AI explanations and report...');
            setTimeout(() => {
              navigate(`/results/${activeScanId}`);
            }, 800);
          } else if (scan.status === 'failed') {
            clearInterval(interval);
            setScanning(false);
            setErrorMsg('Scan execution encountered an issue. Please verify target availability.');
          } else {
            setScanStatus('Analyzing vulnerabilities & correlating attack paths...');
          }
        } catch (err) {
          console.error('Polling error:', err);
        }
      }, 1500);
    }
    return () => clearInterval(interval);
  }, [scanning, activeScanId, navigate]);

  return (
    <div className="max-w-4xl mx-auto space-y-8 animate-fadeIn">
      {/* Header with AI indicator */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-indigo-50 text-indigo-700 border border-indigo-100 mb-2">
            <Globe className="w-3.5 h-3.5" />
            Automated Web Application Vulnerability Scanner
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight">
            New Security Assessment
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            Perform OWASP Top 10 security checks, inspect cryptographic postures, and discover correlated attack paths.
          </p>
        </div>

        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-xl bg-emerald-50 border border-emerald-200 text-xs font-semibold text-emerald-800 shadow-2xs self-start sm:self-auto">
          <Sparkles className="w-3.5 h-3.5 text-emerald-600 animate-pulse" />
          <span>Gemini AI Intelligence Active</span>
        </div>
      </div>

      {/* 🎯 1-Click Live Presentation Demo Target Strip */}
      <div className="bg-gradient-to-r from-indigo-50 via-sky-50 to-indigo-50 rounded-2xl p-4 sm:p-5 border border-indigo-100 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-0.5">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-indigo-600" />
            <h3 className="text-xs font-bold text-indigo-950 uppercase tracking-wider">
              Live Presentation 1-Click Setup
            </h3>
          </div>
          <p className="text-xs text-indigo-900 leading-relaxed">
            One-click autofill for live stage demonstrations — pre-configures target, authorization, and scan modules.
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <button
            type="button"
            onClick={() => handleQuickDemoTarget('https://acmw-new.vercel.app', 'standard')}
            className="px-3 py-1.5 rounded-xl bg-white text-indigo-700 hover:bg-indigo-50 font-semibold text-xs border border-indigo-200 shadow-2xs transition-all active:scale-98"
          >
            🎯 Live Web App (acmw-new)
          </button>
          <button
            type="button"
            onClick={() => handleQuickDemoTarget('http://testphp.vulnweb.com', 'standard')}
            className="px-3 py-1.5 rounded-xl bg-white text-slate-700 hover:bg-slate-100 font-semibold text-xs border border-slate-200 shadow-2xs transition-all active:scale-98"
          >
            🧪 Vulnerable Lab (testphp)
          </button>
          <button
            type="button"
            onClick={() => handleQuickDemoTarget('https://example.com', 'quick')}
            className="px-3 py-1.5 rounded-xl bg-white text-slate-700 hover:bg-slate-100 font-semibold text-xs border border-slate-200 shadow-2xs transition-all active:scale-98"
          >
            🛡️ Clean Baseline (example.com)
          </button>
        </div>
      </div>

      {errorMsg && (
        <div className="p-4 rounded-xl bg-red-50 border border-red-200 text-red-700 text-sm flex items-start gap-3">
          <AlertOctagon className="w-5 h-5 shrink-0 mt-0.5" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Main Scanner Form */}
      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Target URL Input */}
        <div className="bg-white rounded-2xl p-6 border border-slate-200 shadow-xs space-y-3">
          <label className="block text-sm font-bold text-slate-900">
            Target Web Application URL
          </label>
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
              <Globe className="w-5 h-5" />
            </div>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              disabled={scanning}
              placeholder="e.g. http://testphp.vulnweb.com or https://example.com"
              className="w-full pl-11 pr-4 py-3 rounded-xl bg-slate-50 border border-slate-200 text-slate-900 text-sm focus:bg-white focus:border-indigo-600 focus:ring-2 focus:ring-indigo-100 outline-none transition-all font-mono"
            />
          </div>
          <p className="text-xs text-slate-500">
            Internal crawl explores same-host links and discovered forms safely without exceeding depth limits.
          </p>
        </div>

        {/* 1-Click Scan Presets */}
        <div className="space-y-3">
          <label className="block text-sm font-bold text-slate-900">
            Select Scan Profile
          </label>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {PRESETS.map((p) => (
              <div
                key={p.id}
                onClick={() => !scanning && applyPreset(p)}
                className={`cursor-pointer rounded-2xl p-5 border transition-all duration-150 select-none ${
                  activePreset === p.id
                    ? 'bg-indigo-50/70 border-indigo-500 shadow-xs ring-2 ring-indigo-500/20'
                    : 'bg-white border-slate-200 hover:border-slate-300'
                }`}
              >
                <div className="font-bold text-sm text-slate-900 mb-1">{p.title}</div>
                <p className="text-xs text-slate-500 leading-relaxed">{p.desc}</p>
                <span className="inline-block mt-3 text-[10px] font-semibold text-indigo-700 bg-white px-2 py-0.5 rounded border border-indigo-200">
                  {p.checks.length} Security Checks Active
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Advanced Module Customization (Collapsible) */}
        <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-xs">
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="w-full px-6 py-4 flex items-center justify-between text-xs font-bold text-slate-700 uppercase tracking-wider hover:bg-slate-50 transition-colors"
          >
            <span className="flex items-center gap-2">
              <Sliders className="w-4 h-4 text-indigo-600" />
              Customize Security Modules ({selectedChecks.length} Active)
            </span>
            {showAdvanced ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>

          {showAdvanced && (
            <div className="p-6 pt-2 border-t border-slate-100 grid grid-cols-1 md:grid-cols-2 gap-3">
              {VULN_CHECKS.map((check) => {
                const isSelected = selectedChecks.includes(check.id);
                return (
                  <div
                    key={check.id}
                    onClick={() => !scanning && toggleCheck(check.id)}
                    className={`cursor-pointer p-3.5 rounded-xl border flex items-start gap-3 transition-colors ${
                      isSelected
                        ? 'bg-indigo-50/50 border-indigo-200'
                        : 'bg-white border-slate-200 opacity-60 hover:opacity-100'
                    }`}
                  >
                    <div className="pt-0.5 text-indigo-600">
                      {isSelected ? <CheckSquare className="w-4 h-4" /> : <Square className="w-4 h-4 text-slate-400" />}
                    </div>
                    <div className="space-y-0.5 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-slate-900">{check.name}</span>
                        <span className="text-[10px] text-indigo-600 font-mono bg-indigo-50 px-1 rounded">{check.category}</span>
                      </div>
                      <p className="text-[11px] text-slate-500 leading-snug">{check.desc}</p>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Legal Certification Checkbox */}
        <div className="p-4 rounded-xl bg-amber-50/70 border border-amber-200 flex items-start gap-3">
          <input
            id="auth-check"
            type="checkbox"
            checked={authorized}
            onChange={(e) => setAuthorized(e.target.checked)}
            disabled={scanning}
            className="mt-0.5 h-4 w-4 rounded border-amber-300 text-indigo-600 focus:ring-indigo-500 cursor-pointer"
          />
          <label htmlFor="auth-check" className="text-xs text-amber-950 leading-relaxed cursor-pointer select-none">
            <strong className="font-semibold block mb-0.5">Authorization & Ethical Use Certification:</strong>
            I certify that I am the owner of this target endpoint or have explicit, authorized permission to perform automated security testing. Unauthorized testing against third-party systems is prohibited by law.
          </label>
        </div>

        {/* Submit or Progress Indicator */}
        {scanning ? (
          <div className="bg-white rounded-2xl p-6 border border-indigo-200 shadow-sm text-center space-y-4 animate-pulse">
            <div className="flex items-center justify-center gap-2 text-indigo-700 font-bold text-sm">
              <Loader2 className="w-5 h-5 animate-spin text-indigo-600" />
              <span>{scanStatus}</span>
            </div>
            <div className="w-full bg-slate-100 rounded-full h-2 max-w-md mx-auto overflow-hidden">
              <div className="bg-indigo-600 h-full w-3/4 animate-pulse rounded-full" />
            </div>
            <p className="text-xs text-slate-500 font-mono">
              Scan #{activeScanId} running in background &bull; Deterministic engine active.
            </p>
          </div>
        ) : (
          <button
            type="submit"
            className="w-full py-4 rounded-2xl font-bold text-sm bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-500 hover:to-indigo-600 active:scale-99 text-white shadow-md shadow-indigo-600/20 transition-all flex items-center justify-center gap-2 cursor-pointer"
          >
            <Sparkles className="w-4 h-4" />
            <span>Launch Security Assessment</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        )}
      </form>
    </div>
  );
}
