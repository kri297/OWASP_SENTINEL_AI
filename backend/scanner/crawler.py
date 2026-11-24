"""
OWASP Sentinel AI - Web Crawler
Crawls the target URL up to a configurable depth and page limit.
Discovers internal URLs, forms, and inputs for downstream security checks
with deterministic ordering and automatic connection retries.
"""

import logging
from urllib.parse import urljoin, urlparse, urldefrag
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class SimpleCrawler:
    """Discovers internal links, forms, and input fields from a target web app deterministically."""

    def __init__(self, target_url: str, max_pages: int = 20, max_depth: int = 2, timeout: int = 10):
        clean_target, _ = urldefrag(target_url.strip())
        self.target_url = clean_target
        parsed = urlparse(self.target_url)
        self.base_domain = parsed.netloc
        self.base_scheme = parsed.scheme
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.timeout = timeout
        self.visited = set()
        self.discovered_urls = []
        self.discovered_forms = []

        # Session with deterministic retry policy to overcome transient network drops
        self.session = requests.Session()
        retries = Retry(total=1, connect=1, backoff_factor=0.2, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.update({
            "User-Agent": "OWASP-Sentinel-AI-Auditor/2.0 (+https://owasp.org/)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })

    def _is_same_origin(self, url: str) -> bool:
        """Ensure the URL belongs to the same domain as the target."""
        try:
            parsed = urlparse(url)
            return parsed.netloc == self.base_domain or not parsed.netloc
        except Exception:
            return False

    def _normalize_url(self, base: str, link: str) -> str:
        """Resolve relative URLs and strip fragments."""
        full_url = urljoin(base, link)
        clean_url, _ = urldefrag(full_url)
        return clean_url

    def crawl(self) -> dict:
        """
        Execute crawling starting from target_url with deterministic link order.
        """
        queue = [(self.target_url, 0)]
        self.visited.add(self.target_url)
        self.discovered_urls.append(self.target_url)

        seen_form_signatures = set()

        while queue and len(self.discovered_urls) < self.max_pages:
            current_url, depth = queue.pop(0)

            if depth > self.max_depth:
                continue

            try:
                resp = self.session.get(current_url, timeout=(4, min(self.timeout, 8)), allow_redirects=True, verify=False)
                content_type = resp.headers.get("Content-Type", "").lower()
                if "text/html" not in content_type:
                    continue

                soup = BeautifulSoup(resp.text, "html.parser")

                # Extract and deduplicate forms deterministically
                forms = soup.find_all("form")
                for form in forms:
                    action = form.get("action") or current_url
                    action_url = self._normalize_url(current_url, action)
                    method = (form.get("method") or "GET").upper()
                    inputs = []

                    for inp in form.find_all(["input", "textarea", "select"]):
                        inp_name = inp.get("name")
                        if not inp_name:
                            continue
                        inp_type = inp.get("type", "text").lower()
                        inp_val = inp.get("value", "")
                        inputs.append({
                            "name": inp_name,
                            "type": inp_type,
                            "value": inp_val
                        })

                    # Form signature for deduplication
                    sorted_input_names = tuple(sorted(i["name"] for i in inputs))
                    form_sig = (action_url, method, sorted_input_names)
                    if form_sig not in seen_form_signatures:
                        seen_form_signatures.add(form_sig)
                        self.discovered_forms.append({
                            "page_url": current_url,
                            "action": action_url,
                            "method": method,
                            "inputs": inputs,
                            "raw_html": str(form)[:300]
                        })

                # Extract links for deeper crawling deterministically
                if depth < self.max_depth:
                    new_links = []
                    for a_tag in soup.find_all("a", href=True):
                        href = a_tag["href"].strip()
                        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                            continue

                        resolved = self._normalize_url(current_url, href)
                        if self._is_same_origin(resolved) and resolved not in self.visited:
                            self.visited.add(resolved)
                            new_links.append(resolved)

                    # Sort new links at this depth for deterministic evaluation order
                    for link in sorted(new_links):
                        self.discovered_urls.append(link)
                        queue.append((link, depth + 1))
                        if len(self.discovered_urls) >= self.max_pages:
                            break

            except Exception as e:
                logger.debug("Crawl error on %s: %s", current_url, e)

        # Final deterministic form ordering
        self.discovered_forms.sort(key=lambda f: (f["action"], f["method"]))

        return {
            "urls": self.discovered_urls,
            "forms": self.discovered_forms
        }
