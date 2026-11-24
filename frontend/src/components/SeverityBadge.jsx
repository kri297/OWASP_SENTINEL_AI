export default function SeverityBadge({ severity, className = '' }) {
  const sev = (severity || 'info').toLowerCase();

  const styles = {
    critical: 'bg-red-50 text-red-700 border-red-200',
    high: 'bg-orange-50 text-orange-700 border-orange-200',
    medium: 'bg-amber-50 text-amber-800 border-amber-200',
    low: 'bg-sky-50 text-sky-700 border-sky-200',
    info: 'bg-slate-100 text-slate-700 border-slate-200',
    secure: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  };

  const currentStyle = styles[sev] || styles.info;

  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border capitalize tracking-wide shadow-2xs ${currentStyle} ${className}`}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current mr-1.5 opacity-80" />
      {severity || 'Info'}
    </span>
  );
}
