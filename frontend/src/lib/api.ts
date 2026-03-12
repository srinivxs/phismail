/** PhisMail — API Client (typed) */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || '';

export interface AnalysisJob {
  analysis_id: string;
  artifact_type: 'email' | 'url';
  status: 'pending' | 'processing' | 'complete' | 'failed';
  created_at: string;
  message?: string;
  error_message?: string;
}

export interface Indicator {
  indicator_type: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  detail?: string;
  confidence?: number;
  source_module?: string;
}

export interface UrlAnalysis {
  url: string;
  domain?: string;
  url_length?: number;
  num_subdomains?: number;
  contains_ip: boolean;
  is_shortened: boolean;
  entropy_score?: number;
  redirect_count: number;
  redirect_chain?: string[];
  final_destination?: string;
  final_domain_mismatch: boolean;
}

export interface DomainIntel {
  domain: string;
  registrar?: string;
  registration_date?: string;
  domain_age_days?: number;
  nameservers?: string[];
  tld_risk_score?: number;
  is_homograph: boolean;
  brand_impersonation: boolean;
  brand_keyword?: string;
}

export interface ThreatHit {
  source: string;
  matched_url?: string;
  confidence_score?: number;
}

export interface FeatureAttribution {
  feature_name: string;
  attribution_score: number;
  direction: 'phishing' | 'safe';
}

export interface InvestigationReport {
  analysis_id: string;
  verdict: 'SAFE' | 'MARKETING' | 'SUSPICIOUS' | 'PHISHING';
  risk_score: number;
  phishing_probability?: number;
  indicators: Indicator[];
  extracted_urls: UrlAnalysis[];
  domain_intelligence: DomainIntel[];
  threat_intel_hits: ThreatHit[];
  top_contributors: FeatureAttribution[];
  created_at?: string;
}

export interface AnalysisList {
  total: number;
  page: number;
  per_page: number;
  analyses: AnalysisJob[];
}

// --- API Functions ---

export async function submitUrl(url: string): Promise<AnalysisJob> {
  const res = await fetch(`${API_BASE}/api/v1/analyze/url`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

export async function submitEmail(file: File): Promise<AnalysisJob> {
  const formData = new FormData();
  formData.append('file', file);
  const res = await fetch(`${API_BASE}/api/v1/analyze/email`, {
    method: 'POST',
    body: formData,
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

export async function getAnalysisStatus(id: string): Promise<AnalysisJob> {
  const res = await fetch(`${API_BASE}/api/v1/analysis/${id}`);
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

export async function getReport(id: string): Promise<InvestigationReport> {
  const res = await fetch(`${API_BASE}/api/v1/report/${id}`);
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

export async function listAnalyses(page = 1, perPage = 20): Promise<AnalysisList> {
  const res = await fetch(`${API_BASE}/api/v1/analyses?page=${page}&per_page=${perPage}`);
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}
