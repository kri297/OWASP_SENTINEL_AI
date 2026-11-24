import { Server, Cpu, Layers, Globe, Shield } from 'lucide-react';

export default function TechFingerprint({ data }) {
  if (!data || Object.keys(data).length === 0) {
    return (
      <div className="bg-white rounded-2xl p-8 border border-slate-200 text-center text-slate-500 text-xs">
        No technological fingerprint signatures identified for this endpoint.
      </div>
    );
  }

  const technologies = data.technologies || [];

  const categories = [
    { title: 'Web Server', icon: Server, items: technologies.filter(t => t.category === 'Web Server' || t.category === 'Generic Web Server') },
    { title: 'Backend & Frameworks', icon: Cpu, items: technologies.filter(t => t.category.includes('Framework') || t.category.includes('Language') || t.category.includes('Runtime')) },
    { title: 'Content Management System', icon: Layers, items: technologies.filter(t => t.category.includes('CMS') || t.category.includes('Commerce') || t.category.includes('Platform')) },
    { title: 'CDN & WAF Layer', icon: Globe, items: technologies.filter(t => t.category.includes('CDN') || t.category.includes('WAF') || t.category.includes('DDoS')) },
    { title: 'Client-side Libraries', icon: Shield, items: technologies.filter(t => t.category.includes('Library') || t.category.includes('CSS') || t.category.includes('Font')) },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {categories.map((cat, idx) => (
        <div key={idx} className="bg-white rounded-2xl border border-slate-200 p-5 shadow-xs space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-slate-100">
            <div className="p-1.5 rounded-lg bg-indigo-50 text-indigo-600">
              <cat.icon className="w-4 h-4" />
            </div>
            <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider">{cat.title}</h4>
          </div>

          {cat.items.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {cat.items.map((item, i) => (
                <div
                  key={i}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-50 border border-slate-200 text-xs font-medium text-slate-800"
                  title={item.evidence || item.category}
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-indigo-600" />
                  <span className="font-semibold">{item.name}</span>
                  {item.version && item.version !== 'Detected' && (
                    <span className="text-[10px] text-slate-500 font-mono bg-white px-1.5 py-0.5 rounded border border-slate-200">
                      {item.version}
                    </span>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-slate-400 italic">No specific signature detected</p>
          )}
        </div>
      ))}
    </div>
  );
}
