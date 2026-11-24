import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  Search,
  ExternalLink,
  Clock,
  CheckCircle2,
  XCircle,
  Loader2,
  Trash2,
  FileDown,
  ArrowRight,
  ShieldCheck,
  Plus,
  GitCompare,
} from 'lucide-react';
import { saveAs } from 'file-saver';

import SeverityBadge from '../components/SeverityBadge';
import LoadingSkeleton from '../components/LoadingSkeleton';
import { getScans, deleteScan, clearAllScans, downloadPdfReport } from '../services/api';

export default function Results() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filterStatus, setFilterStatus] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [deletingId, setDeletingId] = useState(null);

  const fetchScans = async () => {
    try {
      const data = await getScans(1, 100);
      setScans(data.scans || []);
    } catch (err) {
      console.error('Failed to load scans:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  const handleDelete = async (scanId) => {
    if (!window.confirm(`Are you sure you want to delete scan #${scanId}?`)) return;
    try {
      setDeletingId(scanId);
      await deleteScan(scanId);
      setScans((prev) => prev.filter((s) => s.id !== scanId));
    } catch (err) {
      console.error('Delete failed:', err);
      alert('Failed to delete scan.');
    } finally {
      setDeletingId(null);
    }
  };

  const handleClearAll = async () => {
    if (!window.confirm('Permanently wipe all scan history and vulnerabilities for a fresh start?')) return;
    try {
      await clearAllScans();
      setScans([]);
    } catch (err) {
      console.error('Clear all failed:', err);
      alert('Failed to clear scan records.');
    }
  };

  const handleDownloadPdf = async (e, scanId) => {
    e.stopPropagation();
    try {
      const blob = await downloadPdfReport(scanId);
      saveAs(blob, `sentinel_report_scan_${scanId}.pdf`);
    } catch (err) {
      console.error('PDF download error:', err);
      alert('Unable to generate PDF report.');
    }
  };

  const filteredScans = scans.filter((scan) => {
    const matchesStatus = filterStatus === 'all' ? true : scan.status === filterStatus;
    const matchesSearch = scan.target_url?.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesStatus && matchesSearch;
  });

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight">
            Security Audit History
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            Review past scan assessments, export executive PDF summaries, and track remediations.
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {scans.length > 0 && (
            <button
              onClick={handleClearAll}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold bg-white border border-red-200 text-red-600 hover:bg-red-50 transition-colors shadow-2xs cursor-pointer"
              title="Clear all scans for a fresh start"
            >
              <Trash2 className="w-3.5 h-3.5 text-red-600" />
              <span>Clear History</span>
            </button>
          )}
          <Link
            to="/compare"
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold bg-white border border-slate-200 text-slate-700 hover:bg-slate-50 transition-colors shadow-2xs"
          >
            <GitCompare className="w-3.5 h-3.5 text-indigo-600" />
            <span>Compare Scans</span>
          </Link>
          <Link
            to="/scan"
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold bg-indigo-600 hover:bg-indigo-700 text-white shadow-xs transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>New Scan</span>
          </Link>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="bg-white rounded-2xl p-4 border border-slate-200 shadow-xs flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4">
        <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-xl">
          {['all', 'completed', 'running', 'failed'].map((st) => (
            <button
              key={st}
              onClick={() => setFilterStatus(st)}
              className={`px-3 py-1 rounded-lg text-xs font-semibold capitalize transition-all ${
                filterStatus === st ? 'bg-white text-indigo-600 shadow-xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              {st}
            </button>
          ))}
        </div>

        <div className="relative flex-1 max-w-sm">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by target URL..."
            className="w-full pl-9 pr-3 py-2 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-900 focus:bg-white focus:border-indigo-600 outline-none transition-all"
          />
        </div>
      </div>

      {/* Scans Grid */}
      {loading ? (
        <LoadingSkeleton type="vulnerability" count={4} />
      ) : filteredScans.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredScans.map((scan) => (
            <div
              key={scan.id}
              className="bg-white rounded-2xl p-5 sm:p-6 border border-slate-200 shadow-xs hover:border-slate-300 transition-all flex flex-col justify-between space-y-4"
            >
              <div className="space-y-2">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <span className="text-[11px] font-mono text-indigo-600 font-semibold bg-indigo-50 px-2 py-0.5 rounded">
                      Scan #{scan.id}
                    </span>
                    <h3 className="text-base font-bold text-slate-900 truncate mt-1 flex items-center gap-1.5">
                      <ExternalLink className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                      <span className="truncate">{scan.target_url}</span>
                    </h3>
                  </div>

                  {scan.status === 'completed' ? (
                    <span className="inline-flex items-center gap-1 text-xs text-emerald-700 bg-emerald-50 px-2.5 py-0.5 rounded-full font-semibold border border-emerald-200">
                      <CheckCircle2 className="w-3 h-3 text-emerald-600" />
                      Done
                    </span>
                  ) : scan.status === 'running' ? (
                    <span className="inline-flex items-center gap-1 text-xs text-indigo-600 bg-indigo-50 px-2.5 py-0.5 rounded-full font-semibold border border-indigo-200">
                      <Loader2 className="w-3 h-3 animate-spin" />
                      Running
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-xs text-red-600 bg-red-50 px-2.5 py-0.5 rounded-full font-semibold border border-red-200">
                      <XCircle className="w-3 h-3" />
                      Failed
                    </span>
                  )}
                </div>

                <div className="flex items-center gap-3 text-xs text-slate-500">
                  <span className="capitalize bg-slate-100 px-2 py-0.5 rounded text-slate-700 font-medium">
                    {scan.scan_type || 'full'}
                  </span>
                  <span className="flex items-center gap-1">
                    <Clock className="w-3.5 h-3.5 text-slate-400" />
                    {scan.created_at ? new Date(scan.created_at).toLocaleString() : 'N/A'}
                  </span>
                </div>
              </div>

              {/* Findings Summary Strip */}
              <div className="bg-slate-50 p-3 rounded-xl border border-slate-100 flex items-center justify-between">
                <span className="text-xs font-medium text-slate-600">Vulnerabilities:</span>
                <div className="flex items-center gap-1.5">
                  <span className="text-xs font-bold text-slate-900 mr-1">{scan.total_vulnerabilities}</span>
                  {scan.critical_count > 0 && <SeverityBadge severity="Critical" className="!px-1.5 !py-0 !text-[10px]" />}
                  {scan.high_count > 0 && <SeverityBadge severity="High" className="!px-1.5 !py-0 !text-[10px]" />}
                  {scan.medium_count > 0 && <SeverityBadge severity="Medium" className="!px-1.5 !py-0 !text-[10px]" />}
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center justify-between pt-2 border-t border-slate-100">
                <div className="flex items-center gap-2">
                  <button
                    onClick={(e) => handleDownloadPdf(e, scan.id)}
                    title="Export PDF Report"
                    className="p-2 rounded-xl bg-slate-100 text-slate-700 hover:bg-slate-200 transition-colors"
                  >
                    <FileDown className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => handleDelete(scan.id)}
                    disabled={deletingId === scan.id}
                    title="Delete Scan"
                    className="p-2 rounded-xl bg-slate-100 text-red-600 hover:bg-red-50 hover:text-red-700 transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>

                <Link
                  to={`/results/${scan.id}`}
                  className="inline-flex items-center gap-1 px-4 py-2 rounded-xl text-xs font-semibold bg-indigo-50 text-indigo-700 hover:bg-indigo-100 transition-colors"
                >
                  View Details <ArrowRight className="w-3.5 h-3.5" />
                </Link>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="bg-white rounded-2xl p-12 border border-slate-200 text-center space-y-3">
          <ShieldCheck className="w-12 h-12 text-slate-300 mx-auto" />
          <h3 className="text-base font-bold text-slate-900">No Historical Scans Found</h3>
          <p className="text-xs text-slate-500 max-w-sm mx-auto">
            Execute your first security assessment to populate this repository.
          </p>
          <Link
            to="/scan"
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold bg-indigo-600 text-white"
          >
            <Plus className="w-3.5 h-3.5" /> Start New Scan
          </Link>
        </div>
      )}
    </div>
  );
}
