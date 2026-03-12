"""
PhisMail — Domain Analysis Utilities
Domain normalization, typosquatting detection, and brand impersonation checks.
"""

import tldextract

from app.core.security import BRAND_KEYWORDS, SUSPICIOUS_TLDS


def extract_base_domain(domain: str) -> str:
    """
    Return the registered domain using tldextract.

    Examples:
        'sub.evil.com' -> 'evil.com'
        'paypal-login.net' -> 'paypal-login.net'
    """
    extracted = tldextract.extract(domain)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return extracted.domain or domain


def get_domain_tld(domain: str) -> str:
    """Return the public suffix / TLD of a domain string."""
    return tldextract.extract(domain).suffix


def is_suspicious_tld(domain: str) -> bool:
    """
    Return True if the domain's TLD is in the SUSPICIOUS_TLDS list.

    SUSPICIOUS_TLDS entries include the leading dot (e.g. '.ru').
    """
    tld = get_domain_tld(domain)
    if not tld:
        return False
    # Normalise: ensure we check with a leading dot
    tld_with_dot = tld if tld.startswith(".") else f".{tld}"
    return tld_with_dot.lower() in [t.lower() for t in SUSPICIOUS_TLDS]


def calculate_levenshtein(s1: str, s2: str) -> int:
    """
    Compute the Levenshtein edit distance between two strings (iterative,
    O(len(s1) * len(s2)) time, O(len(s2)) space).
    """
    if s1 == s2:
        return 0
    if not s1:
        return len(s2)
    if not s2:
        return len(s1)

    # Use single-row DP
    previous_row = list(range(len(s2) + 1))

    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (0 if c1 == c2 else 1)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def find_brand_keyword(domain: str) -> str | None:
    """
    Check whether any brand keyword appears as a substring in *domain*,
    but the domain is NOT exactly equal to the brand.

    Returns the first matching brand keyword, or None if no match.
    """
    normalized = normalize_domain(domain)
    # Strip the TLD portion for comparison so 'paypal.com' -> 'paypal'
    extracted = tldextract.extract(normalized)
    domain_stem = extracted.domain.lower() if extracted.domain else normalized

    for brand in BRAND_KEYWORDS:
        brand_lower = brand.lower()
        if brand_lower in domain_stem and domain_stem != brand_lower:
            return brand_lower

    return None


def is_typosquatting(
    domain: str,
    threshold: float = 0.85,
) -> tuple[bool, str | None, float]:
    """
    Determine whether *domain* is likely typosquatting a known brand.

    Algorithm:
    1. Extract the domain stem (registered domain minus TLD).
    2. For each brand keyword compute a normalised Levenshtein similarity:
       similarity = 1 - (distance / max(len(a), len(b)))
    3. If any similarity >= threshold AND the stem is NOT identical to the
       brand, flag as typosquatting.

    Returns:
        (is_typosquat, matched_brand, best_similarity_score)
    """
    normalized = normalize_domain(domain)
    extracted = tldextract.extract(normalized)
    domain_stem = extracted.domain.lower() if extracted.domain else normalized

    best_brand: str | None = None
    best_score: float = 0.0

    for brand in BRAND_KEYWORDS:
        brand_lower = brand.lower()
        max_len = max(len(domain_stem), len(brand_lower))
        if max_len == 0:
            continue

        distance = calculate_levenshtein(domain_stem, brand_lower)
        similarity = 1.0 - (distance / max_len)

        if similarity > best_score:
            best_score = similarity
            best_brand = brand_lower

    is_typosquat = (
        best_score >= threshold
        and best_brand is not None
        and domain_stem != best_brand
    )

    return is_typosquat, best_brand if is_typosquat else None, best_score


def normalize_domain(domain: str) -> str:
    """
    Normalize a domain for consistent comparison:
    - Lowercase
    - Strip leading 'www.' prefix
    """
    normalized = domain.lower().strip()
    if normalized.startswith("www."):
        normalized = normalized[4:]
    return normalized
