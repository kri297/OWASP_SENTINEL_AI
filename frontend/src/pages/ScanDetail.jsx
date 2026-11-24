import { useState, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ArrowLeft,
  FileDown,
  Trash2,
  ExternalLink,
  Clock,
  Activity,
  Zap,
  Server,
  Layers,
  Search,
  Loader2,
  RotateCcw,
  GitCompare,
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { saveAs } from 'file-saver';

import SeverityBadge from '../components/SeverityBadge';
import VulnerabilityCard from '../components/VulnerabilityCard';
import AttackPathVisualizer from '../components/AttackPathVisualizer';
import TechFingerprint from '../components/TechFingerprint';
import SSLInfo from '../components/SSLInfo';
import LoadingSkeleton from '../components/LoadingSkeleton';
import {
  getScan,
  getScanVulnerabilities,
  getAttackPaths,
  deleteScan,
  downloadPdfReport,
  downloadJsonReport,
} from '../services/api';

const SEVERITY_COLORS = {
  Critical: '#dc2626',
  High: '#ea580c',
  Medium: '#d97706',
  Low: '#0284c7',
  Info: '#64748b',
};

export default function ScanDetail() {
  const { id } = useParams();
  const navigate = useNavigate();

  const [scan, setScan] = useState(null);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [attackPaths, setAttackPaths] = useState([]);
  const [loading, setLoading] = useState(true);

  const [activeTab, setActiveTab] = useState('overview'); // overview | vulns | paths | recon
  const [selectedSeverity, setSelectedSeverity] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [downloading, setDownloading] = useState(false);

  useEffect(() => {
    async function loadData() {
      try {
        setLoading(true);
        const [scanData, vulnsData, pathsData] = await Promise.all([
          getScan(id),
          getScanVulnerabilities(id),
          getAttackPaths(id),
        ]);

        setScan(scanData);
        setVulnerabilities(vulnsData.vulnerabilities || []);
        setAttackPaths(pathsData.attack_paths || []);
      } catch (err) {
        console.error('Failed to load scan details:', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, [id]);

  const handleDownloadPdf = async () => {
    try {
      setDownloading(true);
      const blob = await downloadPdfReport(id);
      saveAs(blob, `sentinel_report_scan_${id}.pdf`);
    } catch (err) {
      console.error('PDF error:', err);
      alert('Failed to generate PDF report.');
    } finally {
      setDownloading(false);
    }
  };

  const handleDownloadJson = async () => {
    try {
      const blob = await downloadJsonReport(id);
      saveAs(blob, `sentinel_report_scan_${id}.json`);
    } catch (err) {
      console.error('JSON export error:', err);
      alert('Failed to export JSON report.');
    }
  };

  const handleDelete = async () => {
    if (!window.confirm(`Permanently delete scan #${id}?`)) return;
    try {
      await deleteScan(id);
      navigate('/results');
    } catch (err) {
      alert('Failed to delete scan.');
    }
  };

  if (loading) {
    return (
      <div className="space-y-6 animate-fadeIn">
        <LoadingSkeleton type="card" count={4} />
        <LoadingSkeleton type="vulnerability" count={4} />
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="text-center py-16 bg-white rounded-2xl border border-slate-200 space-y-4">
        <ShieldAlert className="w-12 h-12 text-slate-400 mx-auto" />
        <h2 className="text-lg font-bold text-slate-900">Scan Record Not Located</h2>
        <Link to="/results" className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold bg-indigo-600 text-white">
          <ArrowLeft className="w-4 h-4" /> Back to All Scans
        </Link>
      </div>
    );
  }

  // Filter vulnerabilities
  const filteredVulns = vulnerabilities.filter((v) => {
    const sev = (v.severity || 'info').toLowerCase();
    const matchesSev = selectedSeverity === 'all' ? true : sev === selectedSeverity.toLowerCase();
    const type = (v.vuln_type || v.type || '').toLowerCase();
    const desc = (v.description || '').toLowerCase();
    const matchesSearch = type.includes(searchTerm.toLowerCase()) || desc.includes(searchTerm.toLowerCase());
    return matchesSev && matchesSearch;
  });

  // Severity counts
  const sevCounts = {
    Critical: scan.critical_count || 0,
    High: scan.high_count || 0,
    Medium: scan.medium_count || 0,
    Low: scan.low_count || 0,
    Info: scan.info_count || 0,
  };

  const pieData = Object.entries(sevCounts)
    .filter(([_, val]) => val > 0)
    .map(([name, value]) => ({ name, value, color: SEVERITY_COLORS[name] }));

  const overallRating =
    scan.critical_count > 0 ? 'Critical' : scan.high_count > 0 ? 'High' : scan.medium_count > 0 ? 'Medium' : scan.low_count > 0 ? 'Low' : 'Secure';

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Top Nav & Action Strip */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <Link
          to="/results"
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-500 hover:text-slate-900 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" /> Back to Scans
        </Link>

        <div className="flex items-center gap-2 flex-wrap">
          <Link
            to={`/compare?scan1=${scan.id}`}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold bg-white border border-slate-200 text-slate-700 hover:bg-slate-50 shadow-2xs transition-colors"
          >
            <GitCompare className="w-3.5 h-3.5 text-indigo-600" />
            Compare
          </Link>
          <button
            onClick={handleDownloadPdf}
            disabled={downloading}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold bg-indigo-600 hover:bg-indigo-700 text-white shadow-xs transition-colors"
          >
            {downloading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <FileDown className="w-3.5 h-3.5" />}
            Download PDF Report
          </button>
          <button
            onClick={handleDownloadJson}
            className="inline-flex items-center gap-1 px-3 py-2 rounded-xl text-xs font-semibold bg-slate-100 hover:bg-slate-200 text-slate-700 transition-colors"
          >
            JSON
          </button>
          <button
            onClick={handleDelete}
            title="Delete this scan"
            className="p-2 rounded-xl bg-slate-100 text-red-600 hover:bg-red-50 transition-colors"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Target Application Header Card */}
      <div className="bg-white rounded-2xl p-6 sm:p-7 border border-slate-200 shadow-xs space-y-3">
        <div className="flex flex-wrap items-center gap-2.5">
          <span className="text-xs font-mono font-bold text-indigo-600 bg-indigo-50 px-2 py-0.5 rounded border border-indigo-100">
            Scan #{scan.id}
          </span>
          <span className="text-xs capitalize text-slate-600 bg-slate-100 px-2 py-0.5 rounded">
            {scan.scan_type || 'full'} Audit
          </span>
          <SeverityBadge severity={overallRating} />
        </div>

        <h1 className="text-xl sm:text-2xl font-extrabold text-slate-900 tracking-tight flex items-center gap-2 break-all">
          <ExternalLink className="w-5 h-5 text-slate-400 shrink-0" />
          <span>{scan.target_url}</span>
        </h1>

        <div className="flex flex-wrap items-center gap-4 text-xs text-slate-500 pt-1 border-t border-slate-100">
          <span className="flex items-center gap-1">
            <Clock className="w-3.5 h-3.5 text-slate-400" />
            Executed: {scan.created_at ? new Date(scan.created_at).toLocaleString() : 'N/A'}
          </span>
          <span>&bull;</span>
          <span>Findings: <strong className="text-slate-900">{scan.total_vulnerabilities}</strong></span>
          <span>&bull;</span>
          <span>Attack Chains: <strong className="text-indigo-600 font-bold">{attackPaths.length}</strong></span>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-200 overflow-x-auto">
        <button
          onClick={() => setActiveTab('overview')}
          className={`flex items-center gap-2 px-4 py-3 text-xs sm:text-sm font-bold border-b-2 transition-all whitespace-nowrap ${
            activeTab === 'overview' ? 'border-indigo-600 text-indigo-600' : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <Activity className="w-4 h-4" />
          Overview & Metrics
        </button>
        <button
          onClick={() => setActiveTab('vulns')}
          className={`flex items-center gap-2 px-4 py-3 text-xs sm:text-sm font-bold border-b-2 transition-all whitespace-nowrap ${
            activeTab === 'vulns' ? 'border-indigo-600 text-indigo-600' : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <ShieldAlert className="w-4 h-4" />
          Vulnerabilities ({vulnerabilities.length})
        </button>
        <button
          onClick={() => setActiveTab('paths')}
          className={`flex items-center gap-2 px-4 py-3 text-xs sm:text-sm font-bold border-b-2 transition-all whitespace-nowrap ${
            activeTab === 'paths' ? 'border-indigo-600 text-indigo-600' : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <Zap className="w-4 h-4" />
          Attack Paths ({attackPaths.length})
        </button>
        <button
          onClick={() => setActiveTab('recon')}
          className={`flex items-center gap-2 px-4 py-3 text-xs sm:text-sm font-bold border-b-2 transition-all whitespace-nowrap ${
            activeTab === 'recon' ? 'border-indigo-600 text-indigo-600' : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <Server className="w-4 h-4" />
          Technology & SSL Recon
        </button>
      </div>

      {/* TAB 1: EXECUTIVE OVERVIEW */}
      {activeTab === 'overview' && (
        <div className="space-y-6 animate-fadeIn">
          {/* Executive Summary Card */}
          <div className="bg-indigo-50/70 rounded-2xl p-5 sm:p-6 border border-indigo-100 space-y-2">
            <h3 className="text-xs font-bold text-indigo-900 uppercase tracking-wider flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4 text-indigo-600" />
              Automated Executive Risk Evaluation
            </h3>
            <p className="text-sm text-indigo-950 leading-relaxed">
              Assessment of <strong>{scan.target_url}</strong> identified a total of{' '}
              <strong>{scan.total_vulnerabilities} findings</strong>. Risk classification is{' '}
              <strong className="uppercase">{overallRating}</strong>. Immediate remediation is recommended for{' '}
              <strong>{scan.critical_count} Critical</strong> and <strong>{scan.high_count} High</strong> severity items.
            </p>
          </div>

          {/* Severity Metric Pill Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            <div className="bg-white rounded-xl p-4 border border-red-200 text-center">
              <span className="text-[11px] font-bold text-red-600 uppercase">Critical</span>
              <p className="text-2xl font-extrabold text-red-700 mt-0.5">{scan.critical_count}</p>
            </div>
            <div className="bg-white rounded-xl p-4 border border-orange-200 text-center">
              <span className="text-[11px] font-bold text-orange-600 uppercase">High</span>
              <p className="text-2xl font-extrabold text-orange-700 mt-0.5">{scan.high_count}</p>
            </div>
            <div className="bg-white rounded-xl p-4 border border-amber-200 text-center">
              <span className="text-[11px] font-bold text-amber-700 uppercase">Medium</span>
              <p className="text-2xl font-extrabold text-amber-800 mt-0.5">{scan.medium_count}</p>
            </div>
            <div className="bg-white rounded-xl p-4 border border-sky-200 text-center">
              <span className="text-[11px] font-bold text-sky-700 uppercase">Low</span>
              <p className="text-2xl font-extrabold text-sky-800 mt-0.5">{scan.low_count}</p>
            </div>
            <div className="bg-white rounded-xl p-4 border border-slate-200 text-center col-span-2 sm:col-span-1">
              <span className="text-[11px] font-bold text-slate-500 uppercase">Info</span>
              <p className="text-2xl font-extrabold text-slate-700 mt-0.5">{scan.info_count}</p>
            </div>
          </div>

          {/* Severity Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-white rounded-2xl p-6 border border-slate-200 shadow-xs">
              <h3 className="text-sm font-bold text-slate-900 mb-4">Severity Distribution</h3>
              <div className="h-60 w-full">
                {pieData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={pieData}
                        cx="50%"
                        cy="50%"
                        innerRadius={50}
                        outerRadius={75}
                        paddingAngle={3}
                        dataKey="value"
                      >
                        {pieData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={{ backgroundColor: '#ffffff', borderRadius: '8px' }} />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="h-full flex items-center justify-center text-slate-400 text-xs">
                    No findings to chart
                  </div>
                )}
              </div>
            </div>

            <div className="bg-white rounded-2xl p-6 border border-slate-200 shadow-xs space-y-3">
              <h3 className="text-sm font-bold text-slate-900">Scan Assessment Details</h3>
              <div className="divide-y divide-slate-100 text-xs space-y-2">
                <div className="flex justify-between py-2">
                  <span className="text-slate-500">Scan Profile:</span>
                  <span className="font-semibold text-slate-900 capitalize">{scan.scan_type}</span>
                </div>
                <div className="flex justify-between py-2">
                  <span className="text-slate-500">Execution Status:</span>
                  <span className="font-semibold text-emerald-700 capitalize">{scan.status}</span>
                </div>
                <div className="flex justify-between py-2">
                  <span className="text-slate-500">Completed At:</span>
                  <span className="font-semibold text-slate-900">
                    {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : 'N/A'}
                  </span>
                </div>
                <div className="flex justify-between py-2">
                  <span className="text-slate-500">Total Vulnerabilities Discovered:</span>
                  <span className="font-bold text-slate-900">{scan.total_vulnerabilities}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: DETAILED VULNERABILITIES */}
      {activeTab === 'vulns' && (
        <div className="space-y-4 animate-fadeIn">
          {/* Filter Bar */}
          <div className="bg-white p-3.5 rounded-2xl border border-slate-200 shadow-xs flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
            <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-xl overflow-x-auto">
              {['all', 'critical', 'high', 'medium', 'low', 'info'].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSelectedSeverity(sev)}
                  className={`px-3 py-1 rounded-lg text-xs font-bold uppercase tracking-wider transition-all ${
                    selectedSeverity === sev ? 'bg-white text-indigo-600 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>

            <div className="relative flex-1 max-w-xs">
              <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search findings..."
                className="w-full pl-8 pr-3 py-1.5 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-900 outline-none focus:border-indigo-600 transition-colors"
              />
            </div>
          </div>

          {/* Vulnerability Cards */}
          {filteredVulns.length > 0 ? (
            <div className="space-y-3">
              {filteredVulns.map((vuln) => (
                <VulnerabilityCard key={vuln.id} vuln={vuln} />
              ))}
            </div>
          ) : (
            <div className="bg-white rounded-2xl p-12 border border-slate-200 text-center space-y-2">
              <ShieldCheck className="w-10 h-10 text-emerald-500 mx-auto" />
              <h3 className="text-sm font-bold text-slate-900">No Findings Match Active Filter</h3>
              <p className="text-xs text-slate-500">Switch to &quot;All&quot; severity or clear search query.</p>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: ATTACK PATHS */}
      {activeTab === 'paths' && (
        <div className="space-y-4 animate-fadeIn">
          {attackPaths.length > 0 ? (
            attackPaths.map((path, idx) => (
              <AttackPathVisualizer key={idx} attackPath={path} />
            ))
          ) : (
            <div className="bg-white rounded-2xl p-12 border border-slate-200 text-center space-y-2">
              <ShieldCheck className="w-10 h-10 text-emerald-500 mx-auto" />
              <h3 className="text-sm font-bold text-slate-900">No Multi-Vector Attack Chains Synthesized</h3>
              <p className="text-xs text-slate-500 max-w-sm mx-auto">
                No complex chained exploits were detected between individual findings.
              </p>
            </div>
          )}
        </div>
      )}

      {/* TAB 4: RECON & INFRASTRUCTURE */}
      {activeTab === 'recon' && (
        <div className="space-y-6 animate-fadeIn">
          {/* SSL/TLS Health */}
          <SSLInfo data={scan.ssl_info} />

          {/* Tech Fingerprinting */}
          <div className="space-y-2">
            <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider">
              Identified Frameworks & Technologies
            </h3>
            <TechFingerprint data={scan.tech_fingerprint} />
          </div>

          {/* DNS Reconnaissance */}
          {scan.dns_info && (
            <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs space-y-3">
              <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <Server className="w-4 h-4 text-indigo-600" />
                DNS Host Endpoints & IP Mapping
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
                  <span className="text-[11px] text-slate-500 uppercase font-semibold">Resolved IP Addresses</span>
                  <div className="font-mono text-slate-800">
                    {(scan.dns_info.ip_addresses || []).join(', ') || '127.0.0.1'}
                  </div>
                </div>
                <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
                  <span className="text-[11px] text-slate-500 uppercase font-semibold">Subdomains Discovered</span>
                  <div className="font-mono text-slate-800">
                    {scan.dns_info.subdomains?.length > 0
                      ? scan.dns_info.subdomains.map(s => s.subdomain).join(', ')
                      : 'None identified'}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
