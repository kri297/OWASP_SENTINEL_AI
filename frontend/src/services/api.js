import axios from 'axios';

const client = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
});

/* ── Scans ── */
export const getScans = (page = 1, perPage = 20) =>
  client.get('/scans', { params: { page, per_page: perPage } }).then((r) => r.data);

export const getScan = (scanId) =>
  client.get(`/scans/${scanId}`).then((r) => r.data);

export const startScan = (targetUrl, scanType = 'full', checks = []) =>
  client.post('/scans', { target_url: targetUrl, scan_type: scanType, checks }).then((r) => r.data);

export const deleteScan = (scanId) =>
  client.delete(`/scans/${scanId}`).then((r) => r.data);

export const clearAllScans = () =>
  client.delete('/scans/clear-all').then((r) => r.data);

export const compareScans = (scan1Id, scan2Id) =>
  client.get('/scans/compare', { params: { scan1: scan1Id, scan2: scan2Id } }).then((r) => r.data);

export const getScanTech = (scanId) =>
  client.get(`/scans/${scanId}/tech`).then((r) => r.data);

export const getScanSSL = (scanId) =>
  client.get(`/scans/${scanId}/ssl`).then((r) => r.data);

export const getScanDNS = (scanId) =>
  client.get(`/scans/${scanId}/dns`).then((r) => r.data);

/* ── Vulnerabilities ── */
export const getScanVulnerabilities = (scanId, filters = {}) =>
  client.get(`/scans/${scanId}/vulnerabilities`, { params: filters }).then((r) => r.data);

/* ── Attack paths ── */
export const getAttackPaths = (scanId) =>
  client.get(`/scans/${scanId}/attack-paths`).then((r) => r.data);

/* ── Dashboard / analytics ── */
export const getDashboardStats = () =>
  client.get('/dashboard/stats').then((r) => r.data);

export const getSeverityDistribution = () =>
  client.get('/dashboard/severity-distribution').then((r) => r.data);

export const getVulnerabilityTrend = () =>
  client.get('/dashboard/vulnerability-trend').then((r) => r.data);

/* ── OWASP Knowledge Base ── */
export const getOWASPKnowledge = () =>
  client.get('/knowledge').then((r) => r.data);

export const getKnowledgeCategory = (categoryId) =>
  client.get(`/knowledge/${categoryId}`).then((r) => r.data);

export const searchKnowledge = (query) =>
  client.get('/knowledge/search', { params: { q: query } }).then((r) => r.data);

/* ── Reports ── */
export const downloadPdfReport = (scanId) =>
  client.get(`/scans/${scanId}/report/pdf`, { responseType: 'blob' }).then((r) => r.data);

export const downloadJsonReport = (scanId) =>
  client.get(`/scans/${scanId}/report/json`, { responseType: 'blob' }).then((r) => r.data);
