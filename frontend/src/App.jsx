import { Routes, Route } from 'react-router-dom';
import Navbar from './components/Navbar';
import Footer from './components/Footer';
import Dashboard from './pages/Dashboard';
import Scanner from './pages/Scanner';
import Results from './pages/Results';
import ScanDetail from './pages/ScanDetail';
import KnowledgeBase from './pages/KnowledgeBase';
import ScanComparison from './pages/ScanComparison';

export default function App() {
  return (
    <div className="min-h-screen bg-slate-50 text-slate-800 flex flex-col font-sans antialiased selection:bg-indigo-100 selection:text-indigo-900">
      <Navbar />
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scan" element={<Scanner />} />
          <Route path="/results" element={<Results />} />
          <Route path="/results/:id" element={<ScanDetail />} />
          <Route path="/knowledge" element={<KnowledgeBase />} />
          <Route path="/compare" element={<ScanComparison />} />
        </Routes>
      </main>
      <Footer />
    </div>
  );
}
