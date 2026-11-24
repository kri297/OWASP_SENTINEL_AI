import { Lock, ShieldCheck, AlertCircle, Clock, CheckCircle } from 'lucide-react';

export default function SSLInfo({ data }) {
  if (!data || Object.keys(data).length === 0) {
    return (
      <div className="bg-white rounded-2xl p-8 border border-slate-200 text-center text-slate-500 text-xs">
        No SSL/TLS certificate details available for this scan.
      </div>
    );
  }

  const grade = data.grade || 'N/A';
  const cert = data.certificate;
  const issues = data.issues || [];
  const protocols = data.protocols || ['TLS 1.2', 'TLS 1.3'];

  const gradeColors = {
    'A+': 'bg-emerald-50 text-emerald-700 border-emerald-200',
    'A': 'bg-emerald-50 text-emerald-700 border-emerald-200',
    'B': 'bg-indigo-50 text-indigo-700 border-indigo-200',
    'C': 'bg-amber-50 text-amber-700 border-amber-200',
    'D': 'bg-orange-50 text-orange-700 border-orange-200',
    'F': 'bg-red-50 text-red-700 border-red-200',
    'N/A': 'bg-slate-100 text-slate-600 border-slate-200',
  };

  return (
    <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs space-y-6">
      {/* Top Banner with Grade */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-slate-100">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Lock className="w-5 h-5 text-indigo-600" />
            <h3 className="text-base font-bold text-slate-900">SSL/TLS Cryptographic Posture</h3>
          </div>
          <p className="text-xs text-slate-500">{data.summary || 'Certificate and cipher assessment'}</p>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-right">
            <span className="text-[11px] font-medium text-slate-500 block uppercase">SSL Grade</span>
            <span className="text-xs text-slate-400">{cert ? cert.cipher_suite : 'Unknown'}</span>
          </div>
          <div
            className={`w-14 h-14 rounded-2xl border flex items-center justify-center text-2xl font-black shadow-xs ${
              gradeColors[grade] || gradeColors['N/A']
            }`}
          >
            {grade}
          </div>
        </div>
      </div>

      {/* Certificate Details Grid */}
      {cert && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-0.5">
            <span className="text-[11px] text-slate-500 font-medium uppercase">Issued To</span>
            <p className="text-xs font-bold text-slate-900 truncate">{cert.common_name}</p>
          </div>
          <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-0.5">
            <span className="text-[11px] text-slate-500 font-medium uppercase">Certificate Authority</span>
            <p className="text-xs font-bold text-slate-900 truncate">{cert.issuer_org || cert.issuer_cn}</p>
          </div>
          <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-0.5">
            <span className="text-[11px] text-slate-500 font-medium uppercase">Days Until Expiry</span>
            <p className={`text-xs font-bold ${cert.days_until_expiry < 30 ? 'text-amber-600' : 'text-emerald-700'}`}>
              {cert.days_until_expiry} days remaining
            </p>
          </div>
          <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-0.5">
            <span className="text-[11px] text-slate-500 font-medium uppercase">Active Protocol</span>
            <p className="text-xs font-bold text-slate-900">{cert.tls_version}</p>
          </div>
        </div>
      )}

      {/* Issues or Clean Status */}
      {issues.length > 0 ? (
        <div className="space-y-2">
          <h4 className="text-xs font-semibold text-amber-800 uppercase tracking-wider flex items-center gap-1.5">
            <AlertCircle className="w-4 h-4 text-amber-600" />
            Detected SSL/TLS Concerns
          </h4>
          <div className="space-y-1.5">
            {issues.map((iss, i) => (
              <div key={i} className="p-3 rounded-xl bg-amber-50 border border-amber-200 text-xs text-amber-900">
                {iss}
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="p-3.5 rounded-xl bg-emerald-50 border border-emerald-200 flex items-center gap-2 text-xs text-emerald-800 font-medium">
          <CheckCircle className="w-4 h-4 text-emerald-600" />
          No cryptographic defects or expired certificates found.
        </div>
      )}
    </div>
  );
}
