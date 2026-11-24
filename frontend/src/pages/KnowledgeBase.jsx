import { useState, useEffect } from 'react';
import {
  BookOpen,
  Search,
  ExternalLink,
  ShieldCheck,
  Code2,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import SeverityBadge from '../components/SeverityBadge';
import { getOWASPKnowledge } from '../services/api';

export default function KnowledgeBase() {
  const [categories, setCategories] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedId, setExpandedId] = useState(null);

  useEffect(() => {
    async function load() {
      try {
        const data = await getOWASPKnowledge();
        setCategories(data.categories || []);
      } catch (err) {
        console.error('Failed to load OWASP knowledge base:', err);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const filtered = categories.filter((cat) => {
    const q = searchTerm.toLowerCase();
    const blob = `${cat.id} ${cat.title} ${cat.description} ${(cat.related_cwes || []).join(' ')}`.toLowerCase();
    return blob.includes(q);
  });

  return (
    <div className="max-w-5xl mx-auto space-y-6 animate-fadeIn">
      {/* Header */}
      <div>
        <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-indigo-50 text-indigo-700 border border-indigo-100 mb-2">
          <BookOpen className="w-3.5 h-3.5" />
          Educational Security Reference
        </div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight">
          OWASP Top 10 Knowledge Center
        </h1>
        <p className="text-sm text-slate-500 mt-1">
          Explore vulnerability classifications, exploitation mechanisms, and developer remediation guidelines.
        </p>
      </div>

      {/* Search Input */}
      <div className="relative">
        <Search className="w-4 h-4 absolute left-3.5 top-3.5 text-slate-400" />
        <input
          type="text"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          placeholder="Search by category, CWE (e.g. CWE-89), injection, access control..."
          className="w-full pl-10 pr-4 py-3 rounded-2xl bg-white border border-slate-200 text-sm text-slate-900 shadow-2xs focus:border-indigo-600 focus:ring-2 focus:ring-indigo-100 outline-none transition-all"
        />
      </div>

      {/* Categories List */}
      <div className="space-y-4">
        {filtered.map((cat) => {
          const isExpanded = expandedId === cat.id;
          return (
            <div
              key={cat.id}
              className="bg-white rounded-2xl border border-slate-200 shadow-xs hover:border-slate-300 transition-all overflow-hidden"
            >
              <div
                onClick={() => setExpandedId(isExpanded ? null : cat.id)}
                className="p-5 flex items-start justify-between gap-4 cursor-pointer select-none hover:bg-slate-50/60 transition-colors"
              >
                <div className="space-y-1.5 flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-mono font-bold text-indigo-700 bg-indigo-50 px-2 py-0.5 rounded border border-indigo-100">
                      {cat.id}
                    </span>
                    <SeverityBadge severity={cat.risk_level} />
                    {cat.related_cwes?.slice(0, 3).map((cwe) => (
                      <span key={cwe} className="text-[11px] font-mono bg-slate-100 text-slate-600 px-1.5 py-0.5 rounded">
                        {cwe}
                      </span>
                    ))}
                  </div>

                  <h3 className="text-base font-bold text-slate-900">{cat.title}</h3>
                  <p className="text-xs text-slate-500 line-clamp-2 leading-relaxed">{cat.description}</p>
                </div>

                <div className="pt-1 text-slate-400 shrink-0">
                  {isExpanded ? <ChevronUp className="w-5 h-5 text-slate-600" /> : <ChevronDown className="w-5 h-5" />}
                </div>
              </div>

              {isExpanded && (
                <div className="p-5 pt-0 border-t border-slate-100 bg-slate-50/50 space-y-4">
                  {/* Full Description */}
                  <div className="space-y-1">
                    <h4 className="text-xs font-bold text-slate-700 uppercase tracking-wider">Description</h4>
                    <p className="text-sm text-slate-600 leading-relaxed bg-white p-3.5 rounded-xl border border-slate-200">
                      {cat.description}
                    </p>
                  </div>

                  {/* Common Flaws */}
                  {cat.common_flaws?.length > 0 && (
                    <div className="space-y-1">
                      <h4 className="text-xs font-bold text-slate-700 uppercase tracking-wider">Common Vulnerability Patterns</h4>
                      <ul className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                        {cat.common_flaws.map((flaw, idx) => (
                          <li key={idx} className="flex items-start gap-2 bg-white p-2.5 rounded-xl border border-slate-200 text-xs text-slate-700">
                            <span className="w-1.5 h-1.5 rounded-full bg-red-500 shrink-0 mt-1.5" />
                            <span>{flaw}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Code Example / Remediation */}
                  {cat.example_code && (
                    <div className="space-y-1">
                      <h4 className="text-xs font-bold text-emerald-800 uppercase tracking-wider flex items-center gap-1.5">
                        <Code2 className="w-4 h-4 text-emerald-600" /> Secure Code Implementation Example
                      </h4>
                      <pre className="bg-slate-900 text-slate-100 text-xs p-3.5 rounded-xl overflow-x-auto font-mono leading-relaxed">
                        {cat.example_code.replace(/```python|```html|```nginx|```bash|```/g, '')}
                      </pre>
                    </div>
                  )}

                  {/* Remediation Checkpoints */}
                  {cat.remediation?.length > 0 && (
                    <div className="space-y-1">
                      <h4 className="text-xs font-bold text-indigo-900 uppercase tracking-wider">Prevention Checklist</h4>
                      <div className="space-y-1.5">
                        {cat.remediation.map((rem, idx) => (
                          <div key={idx} className="flex items-start gap-2 p-2.5 rounded-xl bg-white border border-slate-200 text-xs text-slate-700">
                            <ShieldCheck className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                            <span>{rem}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* External Link */}
                  {cat.owasp_url && (
                    <div className="pt-2 flex justify-end">
                      <a
                        href={cat.owasp_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-xs font-semibold text-indigo-600 hover:text-indigo-700"
                      >
                        Official OWASP Documentation <ExternalLink className="w-3.5 h-3.5" />
                      </a>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
