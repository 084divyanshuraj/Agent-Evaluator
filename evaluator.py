"""
evaluator.py - Core Engine for Agent Evaluator
Multi-Agent Autonomous Benchmarking, Security Leak Scanner & Architectural Audit
"""

import os
import re
import time
import asyncio
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import httpx

# Optional Gemini API integration via google-genai
try:
    from google import genai
    from google.genai import types
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False


# ==============================================================================
# Data Structures
# ==============================================================================

@dataclass
class AgentTarget:
    name: str
    url: str
    category: str = "General Agent"


@dataclass
class SecretFinding:
    secret_type: str
    pattern_name: str
    masked_value: str
    source_location: str
    severity: str = "CRITICAL"


@dataclass
class EvaluationResult:
    rank: int = 0
    name: str = ""
    url: str = ""
    category: str = "General"
    http_status: int = 0
    status_badge: str = "Unknown"
    ttfb_ms: float = 0.0
    perf_score: float = 0.0
    ui_score: float = 0.0
    tech_score: float = 0.0
    overall_score: float = 0.0
    detected_framework: str = "Unknown"
    edge_platform: str = "Unknown"
    tech_stack: str = "Unknown"
    security_status: str = "🟢 Clean (No Leaks)"
    secret_findings: List[Dict[str, Any]] = field(default_factory=list)
    key_findings: str = ""
    ui_findings: str = ""
    scanned_scripts_count: int = 0
    bundle_size_kb: float = 0.0
    evaluated_at: str = ""
    raw_ai_feedback: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


# ==============================================================================
# Regex Patterns for Stage 2: Secret & Security Leak Scanner
# ==============================================================================

SECRET_PATTERNS = {
    "Groq API Key": {
        "regex": re.compile(r"gsk_[a-zA-Z0-9]{20,}"),
        "severity": "CRITICAL",
        "description": "Leaked Groq Cloud API Secret Key"
    },
    "OpenAI API Key": {
        "regex": re.compile(r"(?:sk-[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9_\-]{20,})"),
        "severity": "CRITICAL",
        "description": "Leaked OpenAI API Secret Key / Project Key"
    },
    "Google API Key": {
        "regex": re.compile(r"AIzaSy[a-zA-Z0-9_\-]{33}"),
        "severity": "CRITICAL",
        "description": "Leaked Google Cloud / Firebase API Key"
    },
    "MongoDB Connection String": {
        "regex": re.compile(r"mongodb(?:\+srv)?://[^\s\"'`<>]+"),
        "severity": "CRITICAL",
        "description": "Exposed MongoDB Database Connection URI with credentials"
    },
    "GitHub Personal Access Token": {
        "regex": re.compile(r"gh[pous]_[a-zA-Z0-9]{36}"),
        "severity": "CRITICAL",
        "description": "Leaked GitHub Personal Access / OAuth Token"
    },
    "Anthropic API Key": {
        "regex": re.compile(r"sk-ant-[a-zA-Z0-9_\-]{20,}"),
        "severity": "CRITICAL",
        "description": "Leaked Anthropic Claude API Secret Key"
    },
    "Hugging Face Token": {
        "regex": re.compile(r"hf_[a-zA-Z0-9]{34,}"),
        "severity": "HIGH",
        "description": "Leaked Hugging Face Access Token"
    },
    "AWS Access Key ID": {
        "regex": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "severity": "HIGH",
        "description": "Leaked AWS Access Key ID"
    }
}

LOCAL_DEV_PATTERN = re.compile(
    r"(?:http://|https://|ws://|wss://)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?",
    re.IGNORECASE
)


def mask_secret(value: str) -> str:
    """Safely mask secret strings so credentials are never exposed in UI or reports."""
    if len(value) <= 8:
        return "••••••••"
    prefix = value[:4]
    suffix = value[-4:]
    return f"{prefix}••••••••{suffix}"


# ==============================================================================
# Helper Functions: URL Normalization & Validation
# ==============================================================================

def normalize_url(url: str) -> str:
    """Ensure URL has a valid scheme."""
    url = url.strip()
    if not url:
        return ""
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url
    return url


def parse_bulk_text(text: str) -> List[AgentTarget]:
    """
    Parse pasted multi-line input. Supports:
    - Agent Name, https://...
    - Agent Name, https://..., Category
    - Just https://... (auto-derives agent name from domain)
    """
    targets = []
    lines = [line.strip() for line in text.strip().splitlines() if line.strip()]

    for idx, line in enumerate(lines, 1):
        # Ignore comments or empty lines
        if line.startswith("#"):
            continue

        parts = [p.strip() for p in line.split(",") if p.strip()]
        if len(parts) >= 3:
            name, raw_url, category = parts[0], parts[1], parts[2]
        elif len(parts) == 2:
            # Check if part 0 looks like a URL
            if parts[0].startswith("http://") or parts[0].startswith("https://") or "." in parts[0] and "/" in parts[0]:
                raw_url, name = parts[0], parts[1]
                category = "General Agent"
            else:
                name, raw_url = parts[0], parts[1]
                category = "General Agent"
        else:
            raw_url = parts[0]
            # Derive name from URL domain
            norm = normalize_url(raw_url)
            parsed = urlparse(norm)
            domain = parsed.netloc.replace("www.", "")
            name = domain.split(".")[0].capitalize() if domain else f"Agent-{idx}"
            if "agent" not in name.lower():
                name = f"{name} Agent"
            category = "General Agent"

        clean_url = normalize_url(raw_url)
        if clean_url:
            targets.append(AgentTarget(name=name, url=clean_url, category=category))

    return targets


# ==============================================================================
# Stage 1: Network & Latency Engine
# ==============================================================================

def calculate_perf_score(http_status: int, ttfb_ms: float) -> Tuple[float, str]:
    """
    Scoring per spec:
    200/307:
      - Fast edge (<800ms) = 9.0–10.0
      - Moderate (800–1500ms) = 8.0–8.9
      - 1500–2500ms = 7.2–8.0
      - High (>2500ms) = 6.0–7.2
    503 (Render idle spin-down / Cold start):
      - Assign 3.5–4.0 with "Cold-start Sleep" badge
    404 / Connection Timeout / Network Error:
      - Assign 1.0–2.0
    """
    if http_status in (200, 301, 302, 307, 308):
        badge = f"{http_status} OK" if http_status == 200 else f"{http_status} Redirect"
        if ttfb_ms < 800:
            # Linear scale 10.0 down to 9.0
            score = 10.0 - (ttfb_ms / 800.0) * 1.0
            score = max(9.0, min(10.0, score))
        elif ttfb_ms <= 1500:
            # Linear scale 8.9 down to 8.0
            score = 8.9 - ((ttfb_ms - 800.0) / 700.0) * 0.9
            score = max(8.0, min(8.9, score))
        elif ttfb_ms <= 2500:
            # Linear scale 8.0 down to 7.2
            score = 8.0 - ((ttfb_ms - 1500.0) / 1000.0) * 0.8
            score = max(7.2, min(8.0, score))
        else:
            # High latency > 2500ms
            score = 7.2 - min(1.2, ((ttfb_ms - 2500.0) / 3000.0) * 1.2)
            score = max(6.0, min(7.2, score))
        return round(score, 2), badge

    elif http_status == 503:
        badge = "503 Sleep (Render Cold-Start)"
        score = 3.8
        return score, badge

    elif http_status == 404:
        badge = "404 Not Found"
        score = 1.5
        return score, badge

    elif http_status == 403:
        badge = "403 Forbidden"
        score = 2.0
        return score, badge

    elif http_status == 500:
        badge = "500 Server Error"
        score = 2.0
        return score, badge

    elif http_status == 0:
        badge = "Connection Timeout / Offline"
        score = 1.0
        return score, badge

    else:
        badge = f"HTTP {http_status}"
        score = 2.5
        return score, badge


# ==============================================================================
# Stage 2: Secret & Security Leak Scanner
# ==============================================================================

def scan_text_for_secrets(text: str, location_label: str) -> List[SecretFinding]:
    """Scan given text (HTML or JS bundle) for leaked API secrets and credentials."""
    findings = []
    if not text:
        return findings

    for pattern_name, meta in SECRET_PATTERNS.items():
        matches = meta["regex"].findall(text)
        for match in matches:
            # Avoid duplicate finds in same location
            masked = mask_secret(match)
            if not any(f.masked_value == masked and f.pattern_name == pattern_name for f in findings):
                findings.append(SecretFinding(
                    secret_type=meta["description"],
                    pattern_name=pattern_name,
                    masked_value=masked,
                    source_location=location_label,
                    severity=meta["severity"]
                ))
    return findings


def detect_local_dev_uris(text: str) -> bool:
    """Check if client-side code contains hardcoded localhost/127.0.0.1 development URIs."""
    if not text:
        return False
    return bool(LOCAL_DEV_PATTERN.search(text))


# ==============================================================================
# Stage 3: AI Code & UI Evaluation (Gemini API with Heuristic Fallback)
# ==============================================================================

def detect_tech_stack_heuristics(
    headers: Dict[str, str],
    html: str,
    script_srcs: List[str]
) -> Tuple[str, str, str, float]:
    """
    Inspect HTTP headers, meta tags, and script bundle signatures to detect:
    - Framework (Next.js SSR/SSG, React Vite SPA, Streamlit, Vue/Nuxt, SvelteKit, etc.)
    - Hosting / Edge Platform (Vercel, Cloudflare, Render, AWS, Google Cloud Run)
    - Base tech architecture score
    """
    html_lower = html.lower()
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    scripts_str = " ".join(script_srcs).lower()

    framework = "Modern Web Application"
    edge = "Standard Cloud Host"
    tech_score = 7.5

    # Edge / Infrastructure detection
    server_header = headers_lower.get("server", "")

    if "x-vercel-id" in headers_lower or "vercel" in server_header:
        edge = "Vercel Edge Network"
    elif "cf-ray" in headers_lower or "cloudflare" in server_header:
        edge = "Cloudflare Global CDN"
    elif "x-render-origin-server" in headers_lower or "render" in server_header:
        edge = "Render Cloud Services"
    elif "x-cloud-trace-context" in headers_lower or "google" in server_header:
        edge = "Google Cloud Run"
    elif "x-amz-cf-id" in headers_lower or "awselb" in str(headers_lower) or "cloudfront" in server_header:
        edge = "AWS Edge / CloudFront"
    elif "x-nf-request-id" in headers_lower or "netlify" in server_header:
        edge = "Netlify Global Edge"

    # Framework detection
    if "__next_data__" in html or "/_next/static" in html_lower or "/_next/" in scripts_str:
        framework = "Next.js (SSR / Hybrid)"
        tech_score = 9.4
    elif "stapp" in html_lower or "stappviewcontainer" in html_lower or "_stcore" in html_lower or "streamlit" in html_lower:
        framework = "Streamlit (Python Data App)"
        tech_score = 8.6
    elif "/@vite/client" in html_lower or "vite" in scripts_str or ("react" in html_lower and "assets/index-" in scripts_str):
        framework = "React Vite (Modern SPA)"
        tech_score = 9.0
    elif "__nuxt__" in html_lower or "/_nuxt/" in scripts_str:
        framework = "Nuxt.js / Vue (SSR)"
        tech_score = 9.2
    elif "svelte" in html_lower or "svelte" in scripts_str:
        framework = "SvelteKit"
        tech_score = 9.1
    elif "angular" in html_lower or "ng-version" in html_lower:
        framework = "Angular Enterprise SPA"
        tech_score = 8.7
    elif "gradio" in html_lower or "gradio-app" in html_lower:
        framework = "Gradio AI Interface"
        tech_score = 8.4
    elif "id=\"root\"" in html_lower or "id='root'" in html_lower or "react" in scripts_str:
        framework = "React Single Page App"
        tech_score = 8.8
    elif "id=\"app\"" in html_lower or "vue" in scripts_str:
        framework = "Vue.js Single Page App"
        tech_score = 8.7
    elif "tailwind" in html_lower or "class=\"" in html_lower and ("flex" in html_lower or "grid" in html_lower):
        framework = "TailwindCSS + Responsive HTML5"
        tech_score = 8.0

    # Compression / HTTP Security header bonus
    if "content-encoding" in headers_lower and any(enc in headers_lower["content-encoding"] for enc in ("br", "gzip", "zstd")):
        tech_score = min(10.0, tech_score + 0.3)
    if "strict-transport-security" in headers_lower:
        tech_score = min(10.0, tech_score + 0.3)

    tech_stack_desc = f"{framework} on {edge}"
    return framework, edge, tech_stack_desc, round(tech_score, 2)


def heuristic_ui_evaluation(html: str) -> Tuple[float, str]:
    """
    Built-in heuristic UI evaluator that grades DOM structure, responsive tags,
    semantic hierarchy, and layout sophistication.
    """
    if not html:
        return 2.0, "Target endpoint returned no HTML content."

    soup = BeautifulSoup(html[:150000], "html.parser")
    score = 4.0
    features = []

    # Check viewport meta tag (crucial for mobile responsiveness)
    viewport = soup.find("meta", attrs={"name": "viewport"})
    if viewport:
        score += 1.5
        features.append("Mobile-responsive viewport")
    else:
        features.append("Missing viewport meta tag")

    # Semantic HTML elements
    semantic_tags = soup.find_all(["header", "nav", "main", "footer", "section", "article", "aside"])
    if len(semantic_tags) >= 3:
        score += 1.5
        features.append(f"Semantic HTML5 hierarchy ({len(semantic_tags)} landmark tags)")
    elif len(semantic_tags) >= 1:
        score += 0.8
        features.append("Partial semantic tags")

    # Interactive elements (buttons, inputs, forms)
    interactive = soup.find_all(["button", "input", "textarea", "select", "form"])
    if len(interactive) >= 5:
        score += 1.2
        features.append(f"Rich interactive controls ({len(interactive)} UI elements)")
    elif len(interactive) >= 1:
        score += 0.6
        features.append("Basic interactive controls")

    # Modern CSS framework cues (Tailwind, Bootstrap, Flex/Grid)
    html_sample = html[:50000].lower()
    if any(k in html_sample for k in ["flex", "grid", "col-", "row", "tw-", "gap-"]):
        score += 1.0
        features.append("Modern Flexbox/CSS Grid layout system")

    # Title & Metadata
    title = soup.find("title")
    if title and title.string and len(title.string.strip()) > 3:
        score += 0.8
        features.append(f"Title: '{title.string.strip()[:40]}'")

    score = min(9.8, max(3.0, score))
    summary = " | ".join(features)
    return round(score, 2), summary


def gemini_ai_evaluation(
    api_key: str,
    agent_name: str,
    url: str,
    html: str,
    http_status: int,
    ttfb_ms: float,
    detected_framework: str,
    edge_platform: str
) -> Optional[Dict[str, Any]]:
    """
    Use Google Gemini API (via google-genai) to perform deep UI & architecture grading.
    """
    if not GEMINI_AVAILABLE or not api_key:
        return None

    try:
        client = genai.Client(api_key=api_key)

        # Extract structured summary of HTML to fit token constraints
        soup = BeautifulSoup(html[:100000], "html.parser")
        title = soup.title.string.strip() if soup.title and soup.title.string else "No title"

        meta_tags = []
        for meta in soup.find_all("meta")[:10]:
            name = meta.get("name") or meta.get("property") or ""
            content = meta.get("content") or ""
            if name and content:
                meta_tags.append(f"{name}: {content[:60]}")

        # Count tags
        tag_counts = {
            "buttons": len(soup.find_all("button")),
            "inputs": len(soup.find_all("input")),
            "links": len(soup.find_all("a")),
            "images": len(soup.find_all("img")),
            "scripts": len(soup.find_all("script")),
        }

        # Text snippet
        body_text = soup.get_text(separator=" ", strip=True)[:1500]

        prompt = f"""
You are an expert AI Autonomous Agent Architect and Security Auditor evaluating a deployed Web Agent.

Agent Target Info:
- Agent Name: {agent_name}
- Deployment URL: {url}
- HTTP Status: {http_status}
- Response Latency (TTFB): {ttfb_ms:.1f} ms
- Detected Framework: {detected_framework}
- Edge Host: {edge_platform}
- Page Title: {title}
- Meta Tags: {', '.join(meta_tags)}
- DOM Elements: {tag_counts}
- Page Text Sample: {body_text}

Provide an architectural and UI audit evaluation in valid JSON format matching this exact schema:
{{
  "ui_score": <float between 1.0 and 10.0 representing UI/UX design sophistication, hierarchy, and completeness>,
  "tech_score": <float between 1.0 and 10.0 representing architecture maturity, modern stack, edge hosting, and structure>,
  "key_findings": "<1 to 2 crisp, executive sentences summarizing key architectural merits and constraints>",
  "ui_findings": "<concise summary of UI layout, component hierarchy, and design quality>"
}}

Output ONLY the JSON object, without markdown quotes or explanation.
"""

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.2,
                response_mime_type="application/json"
            )
        )

        import json
        raw_text = response.text.strip()
        # Clean json formatting if wrapped in code blocks
        if raw_text.startswith("```"):
            raw_text = re.sub(r"^```(?:json)?\n?", "", raw_text)
            raw_text = re.sub(r"\n?```$", "", raw_text)

        data = json.loads(raw_text)
        return {
            "ui_score": round(float(data.get("ui_score", 7.5)), 2),
            "tech_score": round(float(data.get("tech_score", 8.0)), 2),
            "key_findings": str(data.get("key_findings", "")),
            "ui_findings": str(data.get("ui_findings", "")),
            "raw": raw_text
        }
    except Exception as e:
        # Fallback will seamlessly take over
        return None


# ==============================================================================
# Master Single-Agent Autonomous Evaluation Pipeline
# ==============================================================================

async def evaluate_single_agent(
    target: AgentTarget,
    gemini_api_key: Optional[str] = None,
    timeout_sec: float = 12.0
) -> EvaluationResult:
    """
    Executes the 3-Stage Autonomous Evaluation for a single target agent:
    Stage 1: Real-Time Network & Latency Engine (httpx)
    Stage 2: Secret & Security Leak Scanner (regex across HTML + JS bundles)
    Stage 3: AI Code & UI Evaluation (Gemini API with heuristic fallback)
    """
    result = EvaluationResult(
        name=target.name,
        url=target.url,
        category=target.category,
        evaluated_at=time.strftime("%Y-%m-%d %H:%M:%S")
    )

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/128.0.0.0 Safari/537.36 AgentEvaluator/2.0"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
    }

    # --------------------------------------------------------------------------
    # Stage 1: Real-Time Network & Latency Engine
    # --------------------------------------------------------------------------
    html_content = ""
    response_headers: Dict[str, str] = {}
    script_sources: List[str] = []

    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=timeout_sec,
            verify=False  # Allow testing varied public/staging certificates
        ) as client:
            t0 = time.perf_counter()
            resp = await client.get(target.url, headers=headers)
            ttfb_ms = (time.perf_counter() - t0) * 1000.0

            result.http_status = resp.status_code
            result.ttfb_ms = round(ttfb_ms, 2)
            html_content = resp.text
            response_headers = dict(resp.headers)
            result.bundle_size_kb = round(len(resp.content) / 1024.0, 2)

    except httpx.TimeoutException:
        result.http_status = 0
        result.ttfb_ms = round(timeout_sec * 1000.0, 2)
        result.status_badge = "Connection Timeout"
        result.perf_score = 1.0
        result.ui_score = 1.0
        result.tech_score = 1.0
        result.overall_score = 1.0
        result.security_status = "🟢 Clean (Offline)"
        result.key_findings = f"Target unreachable within {timeout_sec:.0f}s timeout window."
        return result

    except Exception as exc:
        result.http_status = 0
        result.ttfb_ms = 0.0
        result.status_badge = "Network Failure / Unreachable"
        result.perf_score = 1.0
        result.ui_score = 1.0
        result.tech_score = 1.0
        result.overall_score = 1.0
        result.security_status = "🟢 Clean (Offline)"
        result.key_findings = f"Network connection failed: {str(exc)[:100]}"
        return result

    # Calculate Performance Score & HTTP Badge
    perf_score, status_badge = calculate_perf_score(result.http_status, result.ttfb_ms)
    result.perf_score = perf_score
    result.status_badge = status_badge

    # --------------------------------------------------------------------------
    # Stage 2: Secret & Security Leak Scanner
    # --------------------------------------------------------------------------
    all_findings: List[SecretFinding] = []
    has_local_dev = False

    # 1. Scan Main HTML Document
    html_findings = scan_text_for_secrets(html_content, "index.html (Main Document)")
    all_findings.extend(html_findings)
    if detect_local_dev_uris(html_content):
        has_local_dev = True

    # 2. Extract and inspect first-party JS scripts
    try:
        soup = BeautifulSoup(html_content[:200000], "html.parser")
        scripts = soup.find_all("script")
        script_urls_to_fetch = []

        parsed_base = urlparse(target.url)

        for s in scripts:
            src = s.get("src")
            if src:
                script_sources.append(src)
                # Resolve full url
                full_script_url = urljoin(target.url, src)
                parsed_script = urlparse(full_script_url)
                # Check if first-party or same domain
                if parsed_script.netloc == parsed_base.netloc or not parsed_script.netloc:
                    if len(script_urls_to_fetch) < 6:  # Inspect top 6 bundles
                        script_urls_to_fetch.append(full_script_url)
            else:
                # Inline script
                inline_code = s.string or s.text or ""
                if inline_code:
                    inline_finds = scan_text_for_secrets(inline_code, "Inline <script>")
                    all_findings.extend(inline_finds)
                    if detect_local_dev_uris(inline_code):
                        has_local_dev = True

        result.scanned_scripts_count = len(script_sources)

        # Asynchronously fetch first-party bundle scripts to scan for embedded keys
        if script_urls_to_fetch and result.http_status == 200:
            async with httpx.AsyncClient(timeout=6.0, verify=False) as bundle_client:
                for bundle_url in script_urls_to_fetch:
                    try:
                        b_resp = await bundle_client.get(bundle_url, headers=headers)
                        if b_resp.status_code == 200:
                            bundle_text = b_resp.text
                            bundle_finds = scan_text_for_secrets(
                                bundle_text,
                                f"Bundle: {urlparse(bundle_url).path.split('/')[-1] or 'bundle.js'}"
                            )
                            all_findings.extend(bundle_finds)
                            if detect_local_dev_uris(bundle_text):
                                has_local_dev = True
                    except Exception:
                        pass
    except Exception:
        pass

    # Record security status
    result.secret_findings = [asdict(f) for f in all_findings]
    if all_findings:
        leak_types = list({f.pattern_name for f in all_findings})
        result.security_status = f"🚨 Leak Detected: {', '.join(leak_types)}"
    elif has_local_dev:
        result.security_status = "🟡 Local Dev URI"
    else:
        result.security_status = "🟢 Clean (No Leaks)"

    # --------------------------------------------------------------------------
    # Stage 3: AI Code & UI Evaluation (Gemini API with Fallback)
    # --------------------------------------------------------------------------
    # Framework & Stack Detection
    framework, edge, tech_desc, h_tech_score = detect_tech_stack_heuristics(
        response_headers, html_content, script_sources
    )
    result.detected_framework = framework
    result.edge_platform = edge
    result.tech_stack = tech_desc

    # UI Heuristic baseline
    h_ui_score, h_ui_summary = heuristic_ui_evaluation(html_content)

    # Attempt Gemini API if key is available
    ai_evaluated = False
    if gemini_api_key and result.http_status in (200, 301, 302, 307):
        ai_data = gemini_ai_evaluation(
            api_key=gemini_api_key,
            agent_name=target.name,
            url=target.url,
            html=html_content,
            http_status=result.http_status,
            ttfb_ms=result.ttfb_ms,
            detected_framework=framework,
            edge_platform=edge
        )
        if ai_data:
            result.ui_score = ai_data["ui_score"]
            result.tech_score = ai_data["tech_score"]
            result.key_findings = ai_data["key_findings"]
            result.ui_findings = ai_data["ui_findings"]
            result.raw_ai_feedback = ai_data.get("raw")
            ai_evaluated = True

    # Fallback to intelligent heuristic grading if Gemini wasn't used or failed
    if not ai_evaluated:
        result.ui_score = h_ui_score
        result.tech_score = h_tech_score
        result.ui_findings = h_ui_summary

        # Build clean architectural finding summary
        findings_parts = []
        findings_parts.append(f"Deployed on {edge} using {framework}.")
        if result.ttfb_ms > 0:
            findings_parts.append(f"Edge latency: {result.ttfb_ms:.1f}ms ({status_badge}).")
        if all_findings:
            findings_parts.append(f"CRITICAL: {len(all_findings)} secret(s) exposed in client bundle!")
        elif has_local_dev:
            findings_parts.append("Warning: Uncompiled local dev URLs (127.0.0.1) detected.")
        else:
            findings_parts.append("Security posture clean (zero client-side credential leaks).")

        result.key_findings = " ".join(findings_parts)

    # --------------------------------------------------------------------------
    # Scoring Formula:
    # Overall Score = (UI_Score * 0.35) + (Perf_Score * 0.35) + (Tech_Score * 0.30)
    # --------------------------------------------------------------------------
    overall = (result.ui_score * 0.35) + (result.perf_score * 0.35) + (result.tech_score * 0.30)
    result.overall_score = round(max(1.0, min(10.0, overall)), 2)

    return result


# ==============================================================================
# Batch Orchestrator
# ==============================================================================

async def evaluate_agents_batch(
    targets: List[AgentTarget],
    gemini_api_key: Optional[str] = None,
    concurrency_limit: int = 5,
    callback=None
) -> List[EvaluationResult]:
    """
    Evaluates a batch of targets with bounded concurrency and optional live callback.
    """
    results: List[EvaluationResult] = []
    semaphore = asyncio.Semaphore(concurrency_limit)

    async def sem_eval(target: AgentTarget, index: int, total: int):
        async with semaphore:
            res = await evaluate_single_agent(target, gemini_api_key=gemini_api_key)
            if callback:
                callback(index, total, res)
            return res

    tasks = [sem_eval(target, i + 1, len(targets)) for i, target in enumerate(targets)]
    results = await asyncio.gather(*tasks)

    # Sort results by overall score descending to assign ranks
    results.sort(key=lambda r: r.overall_score, reverse=True)
    for idx, r in enumerate(results, start=1):
        r.rank = idx

    return results
