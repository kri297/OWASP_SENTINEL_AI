import { ShieldCheck, Heart, ExternalLink } from 'lucide-react';
import { Link } from 'react-router-dom';

export default function Footer() {
  return (
    <footer className="mt-16 border-t border-slate-200 bg-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 sm:py-12">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          <div className="md:col-span-2 space-y-3">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-indigo-600 flex items-center justify-center text-white">
                <ShieldCheck className="w-4 h-4" />
              </div>
              <span className="text-sm font-bold text-slate-900">OWASP Sentinel AI</span>
            </div>
            <p className="text-xs text-slate-500 max-w-sm leading-relaxed">
              An automated web application vulnerability scanner and multi-vector attack-path analyzer built for developers, security researchers, and students.
            </p>
            <p className="text-[11px] text-slate-400">
              Strictly for authorized security audits and educational defensive research.
            </p>
          </div>

          <div className="space-y-2">
            <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider">Navigation</h4>
            <ul className="space-y-1.5 text-xs text-slate-600">
              <li><Link to="/" className="hover:text-indigo-600 transition-colors">Dashboard</Link></li>
              <li><Link to="/scan" className="hover:text-indigo-600 transition-colors">New Security Scan</Link></li>
              <li><Link to="/results" className="hover:text-indigo-600 transition-colors">Audit History</Link></li>
              <li><Link to="/knowledge" className="hover:text-indigo-600 transition-colors">OWASP Top 10 Guide</Link></li>
              <li><Link to="/compare" className="hover:text-indigo-600 transition-colors">Scan Comparison</Link></li>
            </ul>
          </div>

          <div className="space-y-2">
            <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider">Resources</h4>
            <ul className="space-y-1.5 text-xs text-slate-600">
              <li>
                <a
                  href="https://owasp.org/www-project-top-ten/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="hover:text-indigo-600 transition-colors inline-flex items-center gap-1"
                >
                  OWASP Official <ExternalLink className="w-3 h-3 text-slate-400" />
                </a>
              </li>
              <li>
                <a
                  href="https://cwe.mitre.org/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="hover:text-indigo-600 transition-colors inline-flex items-center gap-1"
                >
                  MITRE CWE <ExternalLink className="w-3 h-3 text-slate-400" />
                </a>
              </li>
              <li>
                <span className="text-slate-400">Version 2.0 (Light Edition)</span>
              </li>
            </ul>
          </div>
        </div>

        <div className="mt-8 pt-6 border-t border-slate-100 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-400 gap-2">
          <p>&copy; {new Date().getFullYear()} OWASP Sentinel AI. All rights reserved.</p>
          <p className="flex items-center gap-1">
            Built with modern standards for ethical application security.
          </p>
        </div>
      </div>
    </footer>
  );
}
