# Phishing Detection Feature Engineering Matrix

This document defines the feature set used by the phishing detection pipeline.

Features are derived from multiple analysis modules including email header analysis, URL structural analysis, domain intelligence, threat intelligence feeds, social engineering detection, and attachment inspection.

These features are aggregated into a **feature vector** used by both the ML classifier and the rule-based scoring engine.

---

## 1. Email Header Features

Derived from email header authentication and infrastructure analysis.

```
spf_pass
dkim_pass
dmarc_pass
reply_to_mismatch
return_path_mismatch
sender_domain_mismatch
originating_ip_present
num_received_headers
smtp_hops
ip_private_network
```

**Purpose:** Detect spoofed email infrastructure and relay anomalies.

---

## 2. URL Structural Features

Extracted from embedded URLs in the email or directly submitted URLs.

```
url_length
num_dots
num_subdomains
num_hyphens
num_special_chars
contains_ip_address
contains_at_symbol
num_query_parameters
url_entropy_score
num_fragments
has_https
url_shortened
```

**Purpose:** Identify suspicious URL structures commonly used in phishing campaigns.

---

## 3. URL Obfuscation Indicators

Detect obfuscation techniques used by attackers.

```
percent_encoding_count
hex_encoding_count
double_slash_redirect
encoded_characters_ratio
username_in_url
mixed_case_domain
long_query_string
```

**Purpose:** Identify attempts to disguise malicious URLs.

---

## 4. Domain Intelligence Features

Derived from WHOIS and DNS analysis.

```
domain_age_days
domain_recent_registration
domain_expiry_days
domain_registrar_known
num_nameservers
has_mx_record
has_txt_record
has_spf_record
has_dmarc_record
dns_record_count
```

**Purpose:** Identify newly registered or suspicious domains used in phishing campaigns.

---

## 5. Domain Reputation Features

Signals derived from infrastructure intelligence.

```
tld_risk_score
domain_popularity_rank
asn_reputation_score
hosting_provider_known
country_risk_score
```

**Purpose:** Detect malicious hosting environments.

---

## 6. Threat Intelligence Features

Indicators derived from external threat feeds.

```
openphish_match
phishtank_match
urlhaus_match
domain_blacklisted
ip_blacklisted
threat_confidence_score
```

**Purpose:** Identify known phishing infrastructure.

---

## 7. Redirect Behavior Features

Derived from redirect chain analysis.

```
redirect_count
redirect_to_different_domain
redirect_to_ip
final_domain_mismatch
meta_refresh_detected
```

**Purpose:** Identify phishing links that redirect through multiple domains.

---

## 8. Social Engineering NLP Features

Derived from email subject and body analysis.

```
urgency_keyword_count
credential_request_keywords
financial_request_keywords
security_alert_keywords
threat_language_score
sentiment_score
imperative_language_score
```

**Purpose:** Detect manipulation techniques used in phishing emails.

---

## 9. Brand Impersonation Features

Detect domains impersonating well-known organizations.

```
brand_keyword_present
brand_domain_similarity_score
brand_typosquat_distance
brand_homograph_detected
```

**Purpose:** Identify phishing domains mimicking trusted brands.

---

## 10. Attachment Risk Features

Derived from attachment metadata analysis.

```
attachment_count
has_executable_attachment
has_script_attachment
has_macro_document
double_extension_detected
archive_with_executable
mime_mismatch_detected
```

**Purpose:** Detect malware delivery attempts.

---

## 11. Email Structure Features

Signals derived from email formatting.

```
num_urls_in_email
num_external_domains
html_to_text_ratio
num_images
num_forms
javascript_in_email
hidden_links_detected
```

**Purpose:** Identify phishing emails designed to mimic legitimate messages.

---

## 12. Temporal Features

Derived from timing patterns.

```
domain_age_hours
email_sent_outside_business_hours
campaign_activity_frequency
```

**Purpose:** Detect rapid phishing campaigns and newly deployed domains.

---

## Feature Vector Example

Example feature vector passed to the ML classifier:

```json
{
  "spf_pass": 0,
  "reply_to_mismatch": 1,
  "domain_age_days": 2,
  "url_length": 78,
  "num_subdomains": 4,
  "entropy_score": 4.9,
  "brand_keyword_present": 1,
  "redirect_count": 2,
  "urgency_keyword_count": 3,
  "attachment_risk": 1
}
```

---

## ML Model Usage

These features feed into the ML classifier.

**Recommended models:** RandomForest, XGBoost

**Model output:** `phishing_probability`

The probability score is combined with the rule-based scoring engine to produce the final verdict.
