import { Zap, ArrowDown, ShieldAlert, CheckCircle2, AlertOctagon } from 'lucide-react';
import SeverityBadge from './SeverityBadge';

export default function AttackPathVisualizer({ attackPath }) {
  const name = attackPath.name || 'Coordinated Exploit Chain';
  const description = attackPath.description || '';
  const risk = attackPath.risk_level || 'Medium';

  let steps = attackPath.attack_steps || attackPath.steps || [];
  if (typeof steps === 'string') {
    try {
      steps = JSON.parse(steps);
    } catch (_) {
      steps = [steps];
    }
  }

  return (
    <div className="bg-white rounded-2xl border border-slate-200 p-5 sm:p-6 shadow-xs space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-100">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-amber-50 text-amber-600 border border-amber-200">
              <Zap className="w-4 h-4" />
            </div>
            <h3 className="text-base font-bold text-slate-900">{name}</h3>
          </div>
          <p className="text-xs text-slate-500 leading-relaxed max-w-2xl">{description}</p>
        </div>
        <div>
          <SeverityBadge severity={risk} />
        </div>
      </div>

      {/* Step-by-Step Chain Flow */}
      <div className="space-y-3">
        <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wider">
          Exploitation Progression Flow
        </h4>

        <div className="space-y-2">
          {steps.map((step, idx) => {
            const stepText = typeof step === 'object' ? (step.description || step.text || JSON.stringify(step)) : String(step);
            const stepVuln = typeof step === 'object' ? step.vulnerability_type : null;
            const stepImpact = typeof step === 'object' ? step.impact : null;

            return (
              <div key={idx} className="relative">
                <div className="flex items-start gap-3 bg-slate-50 p-4 rounded-xl border border-slate-200 hover:border-slate-300 transition-colors">
                  <div className="w-7 h-7 rounded-full bg-indigo-600 text-white text-xs font-bold flex items-center justify-center shrink-0 mt-0.5 shadow-2xs">
                    {idx + 1}
                  </div>
                  <div className="space-y-1 flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-2 flex-wrap">
                      <p className="text-xs font-semibold text-slate-900 leading-relaxed">{stepText}</p>
                      {stepVuln && (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 border border-indigo-100 font-medium">
                          {stepVuln}
                        </span>
                      )}
                    </div>
                    {stepImpact && (
                      <p className="text-[11px] text-slate-500 leading-normal">
                        <strong className="text-slate-600">Impact:</strong> {stepImpact}
                      </p>
                    )}
                  </div>
                </div>

                {idx < steps.length - 1 && (
                  <div className="flex justify-center py-1">
                    <ArrowDown className="w-3.5 h-3.5 text-slate-400" />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Impact & Mitigation Footer */}
      <div className="p-3.5 rounded-xl bg-indigo-50/60 border border-indigo-100 flex items-start gap-2.5 text-xs text-indigo-900 leading-relaxed">
        <CheckCircle2 className="w-4 h-4 text-indigo-600 shrink-0 mt-0.5" />
        <div>
          <strong className="font-semibold text-indigo-950 block">Breach Prevention:</strong>
          Resolving any individual vulnerability in this chain breaks the sequential exploit path and eliminates the cumulative compromise risk.
        </div>
      </div>
    </div>
  );
}
