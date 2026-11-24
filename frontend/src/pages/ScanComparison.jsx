import { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { GitCompare, ArrowRight, ShieldCheck, ShieldAlert, CheckCircle2, AlertTriangle } from 'lucide-react';
import SeverityBadge from '../components/SeverityBadge';
import { getScans, compareScans } from '../services/api';

export default function ScanComparison() {
  const [searchParams] = useSearchParams();
  const [scans, setScans] = useState([]);
  const [scan1Id, setScan1Id] = useState(searchParams.get('scan1') || '');
  const [scan2Id, setScan2Id] = useState(searchParams.get('scan2') || '');
  const [comparison, setComparison] = useState(null);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  useEffect(() => {
    async function loadScansList() {
      try {
        const data = await getScans(1, 100);
        const list = data.scans || [];
        setScans(list);

        if (!scan1Id && list.length > 0) setScan1Id(list[0].id);
        if (!scan2Id && list.length > 1) setScan2Id(list[1].id);
      } catch (err) {
        console.error('Failed to load scans:', err);
      }
    }
    loadScansList();
  }, []);

  const handleCompare = async () => {
    if (!scan1Id || !scan2Id) {
      setErrorMsg('Please select two scans to compare.');
      return;
    }
    if (scan1Id === scan2Id) {
      setErrorMsg('Please select two distinct scans.');
      return;
    }

    try {
      setLoading(true);
      setErrorMsg('');
      const data = await compareScans(scan1Id, scan2Id);
      setComparison(data);
    } catch (err) {
      console.error('Comparison error:', err);
      setErrorMsg('Failed to compare scans. Please verify selection.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6 animate-fadeIn">
      {/* Header */}
      <div>
        <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-indigo-50 text-indigo-700 border border-indigo-100 mb-2">
          <GitCompare className="w-3.5 h-3.5" />
          Security Regression & Remediation Diff
        </div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight">
          Scan Comparison
        </h1>
        <p className="text-sm text-slate-500 mt-1">
          Compare two security scans to discover newly introduced risks, resolved vulnerabilities, and posture progress.
        </p>
      </div>

      {/* Selectors Bar */}
      <div className="bg-white rounded-2xl p-6 border border-slate-200 shadow-xs space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <label className="text-xs font-bold text-slate-700 uppercase">Baseline Scan (Before)</label>
            <select
              value={scan1Id}
              onChange={(e) => setScan1Id(e.target.value)}
              className="w-full p-2.5 rounded-xl bg-slate-50 border border-slate-200 text-xs font-semibold text-slate-800 focus:bg-white focus:border-indigo-600 outline-none"
            >
              <option value="">Select Scan 1...</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  #{s.id} - {s.target_url} ({s.total_vulnerabilities} findings)
                </option>
              ))}
            </select>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-bold text-slate-700 uppercase">Target Scan (After)</label>
            <select
              value={scan2Id}
              onChange={(e) => setScan2Id(e.target.value)}
              className="w-full p-2.5 rounded-xl bg-slate-50 border border-slate-200 text-xs font-semibold text-slate-800 focus:bg-white focus:border-indigo-600 outline-none"
            >
              <option value="">Select Scan 2...</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  #{s.id} - {s.target_url} ({s.total_vulnerabilities} findings)
                </option>
              ))}
            </select>
          </div>
        </div>

        {errorMsg && <p className="text-xs text-red-600">{errorMsg}</p>}

        <button
          onClick={handleCompare}
          disabled={loading}
          className="w-full py-3 rounded-xl font-bold text-xs bg-indigo-600 hover:bg-indigo-700 text-white transition-colors"
        >
          {loading ? 'Comparing Scans...' : 'Execute Side-by-Side Comparison'}
        </button>
      </div>

      {/* Comparison Results */}
      {comparison && (
        <div className="space-y-6 animate-fadeIn">
          {/* Summary Metric Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="bg-white rounded-xl p-4 border border-slate-200 text-center">
              <span className="text-[11px] font-semibold text-slate-500 uppercase">Baseline Total</span>
              <p className="text-2xl font-bold text-slate-900 mt-1">{comparison.summary.total_before}</p>
            </div>
            <div className="bg-white rounded-xl p-4 border border-slate-200 text-center">
              <span className="text-[11px] font-semibold text-slate-500 uppercase">Target Total</span>
              <p className="text-2xl font-bold text-slate-900 mt-1">{comparison.summary.total_after}</p>
            </div>
            <div className="bg-white rounded-xl p-4 border border-emerald-200 text-center bg-emerald-50/40">
              <span className="text-[11px] font-bold text-emerald-700 uppercase">Resolved Issues</span>
              <p className="text-2xl font-extrabold text-emerald-700 mt-1">+{comparison.summary.fixed_count}</p>
            </div>
            <div className="bg-white rounded-xl p-4 border border-red-200 text-center bg-red-50/40">
              <span className="text-[11px] font-bold text-red-700 uppercase">New Regressions</span>
              <p className="text-2xl font-extrabold text-red-700 mt-1">{comparison.summary.new_count}</p>
            </div>
          </div>

          {/* Resolved Vulnerabilities */}
          <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs space-y-3">
            <h3 className="text-sm font-bold text-emerald-800 flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-600" />
              Resolved Weaknesses ({comparison.fixed.length})
            </h3>
            {comparison.fixed.length > 0 ? (
              <div className="space-y-2">
                {comparison.fixed.map((f, i) => (
                  <div key={i} className="p-3 rounded-xl bg-emerald-50/60 border border-emerald-200 flex items-center justify-between text-xs">
                    <span className="font-semibold text-emerald-950">{f.vuln_type}</span>
                    <SeverityBadge severity={f.severity} />
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-400 italic">No vulnerabilities were resolved between these scans.</p>
            )}
          </div>

          {/* Newly Introduced Regressions */}
          <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs space-y-3">
            <h3 className="text-sm font-bold text-red-800 flex items-center gap-1.5">
              <AlertTriangle className="w-4 h-4 text-red-600" />
              Newly Introduced Weaknesses ({comparison.new.length})
            </h3>
            {comparison.new.length > 0 ? (
              <div className="space-y-2">
                {comparison.new.map((f, i) => (
                  <div key={i} className="p-3 rounded-xl bg-red-50/60 border border-red-200 flex items-center justify-between text-xs">
                    <span className="font-semibold text-red-950">{f.vuln_type}</span>
                    <SeverityBadge severity={f.severity} />
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-emerald-700 font-medium">No new security weaknesses were introduced!</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
