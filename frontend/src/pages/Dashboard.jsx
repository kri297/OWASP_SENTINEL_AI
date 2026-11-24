import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Activity,
  Plus,
  ArrowRight,
  ExternalLink,
  Clock,
  CheckCircle2,
  XCircle,
  Loader2,
  Zap,
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

import StatsCard from '../components/StatsCard';
import SeverityBadge from '../components/SeverityBadge';
import LoadingSkeleton from '../components/LoadingSkeleton';
import { getDashboardStats, getSeverityDistribution } from '../services/api';

const SEVERITY_COLORS = {
  Critical: '#dc2626',
  High: '#ea580c',
  Medium: '#d97706',
  Low: '#0284c7',
  Info: '#64748b',
};

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [distribution, setDistribution] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      try {
        const [statsData, distData] = await Promise.all([
          getDashboardStats().catch(() => null),
          getSeverityDistribution().catch(() => null),
        ]);

        if (statsData) setStats(statsData);

        if (distData?.distribution) {
          const chartData = Object.entries(distData.distribution).map(([name, value]) => ({
            name,
            value,
            color: SEVERITY_COLORS[name] || '#64748b',
          }));
          setDistribution(chartData);
        }
      } catch (err) {
        console.error('Failed to load dashboard data:', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  if (loading) {
    return (
      <div className="space-y-6 animate-fadeIn">
        <LoadingSkeleton type="card" count={4} />
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <LoadingSkeleton type="chart" />
          <LoadingSkeleton type="chart" />
        </div>
        <LoadingSkeleton type="table" count={4} />
      </div>
    );
  }

  const criticalCount = stats?.vulns_by_severity?.Critical || 0;
  const highCount = stats?.vulns_by_severity?.High || 0;
  const mediumCount = stats?.vulns_by_severity?.Medium || 0;
  const totalVulns = stats?.total_vulnerabilities || 0;
  const totalScans = stats?.total_scans || 0;

  // Calculate high-level risk score
  const riskScore = totalVulns > 0
    ? Math.min(100, Math.round((criticalCount * 25 + highCount * 15 + mediumCount * 5) / Math.max(1, totalScans)))
    : 0;

  // Format type breakdown data for bar chart
  const typeData = stats?.vulns_by_type
    ? Object.entries(stats.vulns_by_type)
        .slice(0, 6)
        .map(([name, count]) => ({
          name: name.length > 20 ? name.substring(0, 18) + '…' : name,
          count,
        }))
    : [];

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* Hero Welcome Banner */}
      <div className="bg-gradient-to-r from-indigo-900 to-slate-900 rounded-3xl p-6 sm:p-8 text-white shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div className="space-y-2 max-w-2xl">
          <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-white/10 text-indigo-200 border border-white/15">
            <ShieldCheck className="w-3.5 h-3.5" />
            OWASP Top 10 Web Vulnerability Assessment Platform
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight">
            Security Intelligence Dashboard
          </h1>
          <p className="text-sm text-slate-300 leading-relaxed">
            Monitor target web assets, identify multi-step attack vectors, and generate professional audit-ready remediation reports.
          </p>
        </div>

        <div className="flex items-center gap-3 shrink-0 flex-wrap">
          <Link
            to="/scan?target=https%3A%2F%2Facmw-new.vercel.app"
            className="inline-flex items-center gap-2 px-4 py-3 rounded-xl font-bold text-xs sm:text-sm bg-indigo-500/30 text-white hover:bg-indigo-500/50 border border-indigo-400/40 backdrop-blur-xs shadow-md transition-all active:scale-98"
          >
            <span>🎯 Live Stage Demo (acmw-new)</span>
          </Link>
          <Link
            to="/scan"
            className="inline-flex items-center gap-2 px-5 py-3 rounded-xl font-bold text-xs sm:text-sm bg-white text-indigo-900 hover:bg-slate-100 shadow-md transition-all active:scale-98"
          >
            <Plus className="w-4 h-4 text-indigo-600" />
            <span>Launch New Scan</span>
          </Link>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6">
        <StatsCard
          icon={Activity}
          label="Total Scans Executed"
          value={totalScans}
          trend={totalScans > 0 ? 'Active' : undefined}
          trendUp={true}
        />
        <StatsCard
          icon={ShieldAlert}
          label="Total Vulnerabilities"
          value={totalVulns}
          trend={totalVulns > 0 ? `${totalVulns} Findings` : 'Clean'}
          trendUp={totalVulns === 0}
        />
        <StatsCard
          icon={AlertTriangle}
          label="Critical Severity Items"
          value={criticalCount}
          trend={criticalCount > 0 ? 'Urgent Action' : 'Zero Critical'}
          trendUp={criticalCount === 0}
        />
        <StatsCard
          icon={Zap}
          label="Average Risk Index"
          value={`${riskScore}/100`}
          trend={riskScore > 50 ? 'High Risk' : riskScore > 20 ? 'Moderate' : 'Low Risk'}
          trendUp={riskScore <= 20}
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution Donut */}
        <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs flex flex-col justify-between">
          <div>
            <h3 className="text-base font-bold text-slate-900">Severity Breakdown</h3>
            <p className="text-xs text-slate-500 mb-4">Distribution across OWASP risk tiers</p>
          </div>

          <div className="h-56 w-full flex items-center justify-center">
            {distribution.some((d) => d.value > 0) ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={distribution.filter((d) => d.value > 0)}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {distribution.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e2e8f0', borderRadius: '12px', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="text-center text-slate-400 text-xs py-8">
                <ShieldCheck className="w-10 h-10 mx-auto text-emerald-500/80 mb-2" />
                No vulnerabilities detected yet
              </div>
            )}
          </div>

          <div className="flex flex-wrap items-center justify-center gap-3 pt-4 border-t border-slate-100">
            {distribution.map((d) => (
              <div key={d.name} className="flex items-center gap-1.5 text-xs text-slate-600">
                <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: d.color }} />
                <span>{d.name}:</span>
                <span className="font-bold text-slate-900">{d.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Top Vulnerability Categories Bar Chart */}
        <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs lg:col-span-2">
          <div className="mb-4">
            <h3 className="text-base font-bold text-slate-900">Top Vulnerability Categories</h3>
            <p className="text-xs text-slate-500">Most frequent weaknesses identified</p>
          </div>

          <div className="h-64 w-full">
            {typeData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={typeData} layout="vertical" margin={{ left: 10, right: 30, top: 10, bottom: 10 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                  <XAxis type="number" stroke="#94a3b8" tick={{ fill: '#64748b', fontSize: 11 }} />
                  <YAxis type="category" dataKey="name" width={140} stroke="#94a3b8" tick={{ fill: '#475569', fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#ffffff', borderColor: '#e2e8f0', borderRadius: '12px' }}
                  />
                  <Bar dataKey="count" fill="#4f46e5" radius={[0, 6, 6, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-slate-400 text-xs">
                <Activity className="w-8 h-8 text-slate-300 mb-2" />
                Run a security scan to populate category analytics
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="bg-white rounded-2xl border border-slate-200 shadow-xs overflow-hidden">
        <div className="p-5 sm:p-6 border-b border-slate-100 flex items-center justify-between">
          <div>
            <h3 className="text-base font-bold text-slate-900">Recent Security Assessments</h3>
            <p className="text-xs text-slate-500">Latest scan targets and status overview</p>
          </div>
          <Link
            to="/results"
            className="text-xs font-semibold text-indigo-600 hover:text-indigo-700 flex items-center gap-1"
          >
            View All Scans <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        {stats?.recent_scans && stats.recent_scans.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-50/75 border-b border-slate-100 text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
                  <th className="py-3 px-5">Target Application</th>
                  <th className="py-3 px-4">Profile</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Vulnerabilities</th>
                  <th className="py-3 px-4">Executed</th>
                  <th className="py-3 px-5 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-sm">
                {stats.recent_scans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-slate-50/80 transition-colors">
                    <td className="py-3.5 px-5 font-semibold text-slate-900 max-w-xs truncate">
                      <div className="flex items-center gap-2">
                        <ExternalLink className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                        <span className="truncate">{scan.target_url}</span>
                      </div>
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="text-xs px-2 py-0.5 rounded-md bg-slate-100 text-slate-700 font-medium capitalize">
                        {scan.scan_type || 'full'}
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      {scan.status === 'completed' ? (
                        <span className="inline-flex items-center gap-1.5 text-xs text-emerald-700 font-semibold">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                          Completed
                        </span>
                      ) : scan.status === 'running' ? (
                        <span className="inline-flex items-center gap-1.5 text-xs text-indigo-600 font-semibold">
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                          Auditing...
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-xs text-red-600 font-semibold">
                          <XCircle className="w-3.5 h-3.5" />
                          Failed
                        </span>
                      )}
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-1.5">
                        <span className="font-bold text-slate-900 mr-1">{scan.total_vulnerabilities}</span>
                        {scan.critical_count > 0 && <SeverityBadge severity="Critical" className="!px-1.5 !py-0 !text-[10px]" />}
                        {scan.high_count > 0 && <SeverityBadge severity="High" className="!px-1.5 !py-0 !text-[10px]" />}
                      </div>
                    </td>
                    <td className="py-3.5 px-4 text-xs text-slate-500">
                      {scan.created_at ? new Date(scan.created_at).toLocaleDateString() : 'N/A'}
                    </td>
                    <td className="py-3.5 px-5 text-right">
                      <Link
                        to={`/results/${scan.id}`}
                        className="inline-flex items-center gap-1 text-xs font-semibold px-3 py-1.5 rounded-lg bg-indigo-50 text-indigo-700 hover:bg-indigo-100 transition-colors"
                      >
                        Inspect <ArrowRight className="w-3 h-3" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-12 text-center text-slate-500 space-y-3">
            <ShieldCheck className="w-12 h-12 text-slate-300 mx-auto" />
            <p className="text-sm font-medium">No security scans executed yet</p>
            <Link
              to="/scan"
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold bg-indigo-600 text-white hover:bg-indigo-700 transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              Start First Scan
            </Link>
          </div>
        )}
      </div>
    </div>
  );
}
