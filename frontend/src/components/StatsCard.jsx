export default function StatsCard({ icon: Icon, label, value, trend, trendUp, className = '' }) {
  return (
    <div className={`bg-white rounded-2xl p-5 border border-slate-200 shadow-xs hover:shadow-sm transition-all duration-200 flex items-start justify-between gap-4 ${className}`}>
      <div className="space-y-1">
        <p className="text-xs font-medium text-slate-500 uppercase tracking-wider">{label}</p>
        <p className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight">{value}</p>
        {trend && (
          <div className="flex items-center gap-1.5 pt-1">
            <span
              className={`inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium ${
                trendUp
                  ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                  : 'bg-red-50 text-red-700 border border-red-200'
              }`}
            >
              {trend}
            </span>
          </div>
        )}
      </div>
      {Icon && (
        <div className="p-3 rounded-xl bg-indigo-50 border border-indigo-100 text-indigo-600 shrink-0">
          <Icon className="w-5 h-5" />
        </div>
      )}
    </div>
  );
}
