"""
PhisMail — Redirect Chain Tracker
Traces HTTP redirect chains to detect phishing redirects.
"""

from typing import List, Optional, Dict
import httpx
from urllib.parse import urlparse

from app.core.logging import get_logger

logger = get_logger(__name__)

MAX_REDIRECTS = 10
TIMEOUT_PER_HOP = 3.0


class RedirectChainResult:
    """Result of redirect chain analysis."""

    def __init__(self):
        self.redirect_count: int = 0
        self.redirect_chain: List[str] = []
        self.final_destination: Optional[str] = None
        self.final_domain_mismatch: bool = False
        self.redirect_to_different_domain: bool = False
        self.redirect_to_ip: bool = False
        self.meta_refresh_detected: bool = False
        self.error: Optional[str] = None


async def trace_redirect_chain(url: str) -> RedirectChainResult:
    """Trace the full redirect chain of a URL."""

    result = RedirectChainResult()
    result.redirect_chain = [url]
    original_domain = urlparse(url).hostname

    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=TIMEOUT_PER_HOP,
            verify=False,
        ) as client:
            current_url = url

            for _ in range(MAX_REDIRECTS):
                try:
                    response = await client.get(current_url)
                except httpx.TimeoutException:
                    result.error = f"Timeout reaching {current_url}"
                    break
                except Exception as e:
                    result.error = str(e)
                    break

                # Check for meta refresh redirect in HTML
                if response.status_code == 200:
                    content_type = response.headers.get("content-type", "")
                    if "html" in content_type:
                        meta_url = _extract_meta_refresh(response.text)
                        if meta_url:
                            result.meta_refresh_detected = True
                            result.redirect_chain.append(meta_url)
                            result.redirect_count += 1
                            current_url = meta_url
                            continue
                    break

                # Follow HTTP redirects (301, 302, 303, 307, 308)
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get("location")
                    if not location:
                        break

                    # Handle relative redirects
                    if location.startswith("/"):
                        parsed = urlparse(current_url)
                        location = f"{parsed.scheme}://{parsed.netloc}{location}"

                    result.redirect_chain.append(location)
                    result.redirect_count += 1
                    current_url = location
                else:
                    break

    except Exception as e:
        result.error = str(e)
        logger.warning("redirect_trace_error", url=url, error=str(e))

    # Set final destination
    result.final_destination = result.redirect_chain[-1] if result.redirect_chain else url

    # Check domain mismatch
    final_domain = urlparse(result.final_destination).hostname
    result.final_domain_mismatch = (
        original_domain is not None
        and final_domain is not None
        and original_domain != final_domain
    )

    # Check if redirects to a different domain at any point
    domains_seen = set()
    for chain_url in result.redirect_chain:
        domain = urlparse(chain_url).hostname
        if domain:
            domains_seen.add(domain)
    result.redirect_to_different_domain = len(domains_seen) > 1

    # Check if final destination is an IP
    if final_domain:
        import re
        result.redirect_to_ip = bool(
            re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", final_domain)
        )

    return result


def _extract_meta_refresh(html: str) -> Optional[str]:
    """Extract URL from HTML meta refresh tag."""

    import re
    pattern = re.compile(
        r'<meta[^>]*http-equiv\s*=\s*["\']?refresh["\']?[^>]*content\s*=\s*["\']?\d+\s*;\s*url\s*=\s*(["\']?)([^"\'>\s]+)\1',
        re.IGNORECASE,
    )
    match = pattern.search(html)
    if match:
        return match.group(2)
    return None
