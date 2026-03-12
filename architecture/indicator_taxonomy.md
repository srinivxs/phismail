# PhisMail — Indicator Taxonomy

## Severity Model

| Level | Score Range | Description |
|---|---|---|
| **CRITICAL** | - | Confirmed malicious via threat intel feeds |
| **HIGH** | - | Strong phishing signals (infrastructure spoofing, executables) |
| **MEDIUM** | - | Moderate signals (obfuscation, credential keywords) |
| **LOW** | - | Weak signals (urgency language, brand keywords) |

## Indicator Categories

### CRITICAL Indicators
| Indicator | Source Module | Description |
|---|---|---|
| `openphish_match` | threat_intel | URL found in OpenPhish feed |
| `phishtank_match` | threat_intel | URL confirmed in PhishTank database |
| `urlhaus_match` | threat_intel | URL listed in URLHaus |
| `domain_blacklisted` | threat_intel | Domain appears in any threat feed |

### HIGH Indicators
| Indicator | Source Module | Description |
|---|---|---|
| `domain_recent_registration` | domain_intel | Domain registered < 30 days ago |
| `reply_to_mismatch` | header_analysis | Reply-To domain ≠ From domain |
| `return_path_mismatch` | header_analysis | Return-Path domain ≠ From domain |
| `brand_homograph_detected` | homograph | Unicode confusable characters in domain |
| `has_executable_attachment` | attachment | .exe, .bat, .cmd, .scr attachment |
| `double_extension_detected` | attachment | "invoice.pdf.exe" pattern |
| `contains_ip_address` | url_analysis | URL uses IP address instead of domain |

### MEDIUM Indicators
| Indicator | Source Module | Description |
|---|---|---|
| `url_shortened` | url_analysis | bit.ly, tinyurl, t.co etc. |
| `username_in_url` | url_analysis | user@domain in URL |
| `credential_request_keywords` | nlp | "verify account", "enter password" |
| `financial_request_keywords` | nlp | "wire transfer", "payment failed" |
| `has_macro_document` | attachment | .docm, .xlsm attachment |
| `javascript_in_email` | feature_builder | `<script>` tag in HTML body |
| `final_domain_mismatch` | redirect_tracker | Redirect chain ends at different domain |
| `hidden_links_detected` | feature_builder | CSS hidden links in HTML |

### LOW Indicators
| Indicator | Source Module | Description |
|---|---|---|
| `urgency_keyword_count` | nlp | "urgent", "immediately", "act now" |
| `brand_keyword_present` | url_analysis | Brand name in URL path/domain |
| `mixed_case_domain` | url_analysis | Inconsistent casing in domain |
| `percent_encoding_count` | url_analysis | Excessive %XX encoding in URL |
