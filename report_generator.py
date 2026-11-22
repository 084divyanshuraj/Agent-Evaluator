"""
report_generator.py - Dossier & Report Exporter for Agent Evaluator
Generates Markdown, CSV, and PDF Audit Reports.
"""

import io
import time
from typing import List, Dict, Any
import pandas as pd
from evaluator import EvaluationResult

# ReportLab imports for executive PDF generation
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


def generate_leaderboard_dataframe(results: List[EvaluationResult]) -> pd.DataFrame:
    """Transform evaluation results into a clean, displayable DataFrame."""
    rows = []
    for r in results:
        rows.append({
            "Rank": f"#{r.rank}",
            "Agent Name": r.name,
            "URL": r.url,
            "Category": r.category,
            "Overall Score": f"{r.overall_score:.1f} / 10.0",
            "UI/UX Score": f"{r.ui_score:.1f}",
            "Perf Score": f"{r.perf_score:.1f}",
            "Tech Score": f"{r.tech_score:.1f}",
            "Latency (TTFB)": f"{r.ttfb_ms:.0f} ms" if r.ttfb_ms > 0 else "N/A",
            "HTTP Status": r.status_badge,
            "Tech Stack": r.tech_stack,
            "Security Status": r.security_status,
            "Key Architectural Findings": r.key_findings,
            "Bundle Size": f"{r.bundle_size_kb:.1f} KB" if r.bundle_size_kb > 0 else "N/A"
        })
    return pd.DataFrame(rows)


def generate_markdown_dossier(results: List[EvaluationResult]) -> str:
    """Generate an in-depth, executive-ready Markdown audit dossier."""
    total_agents = len(results)
    if total_agents == 0:
        return "# Agent Evaluator Dossier\n\nNo evaluation data available."

    avg_overall = sum(r.overall_score for r in results) / total_agents
    avg_perf = sum(r.perf_score for r in results) / total_agents
    avg_ui = sum(r.ui_score for r in results) / total_agents
    avg_tech = sum(r.tech_score for r in results) / total_agents

    valid_latencies = [r.ttfb_ms for r in results if r.ttfb_ms > 0]
    avg_latency = sum(valid_latencies) / len(valid_latencies) if valid_latencies else 0.0

    leaks_detected = sum(1 for r in results if "Leak Detected" in r.security_status)
    local_dev_count = sum(1 for r in results if "Local Dev" in r.security_status)
    clean_count = total_agents - leaks_detected - local_dev_count
    clean_percentage = (clean_count / total_agents) * 100.0

    top_agent = results[0] if results else None

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    md = f"""# 🛡️ Agent Evaluator: Autonomous Audit & Benchmarking Dossier
*Generated on {timestamp} by Agent Evaluator v2.0 AI Security Suite*

---

## Executive Summary

This audit dossier compiles network telemetry, static bundle secret inspection, and AI-driven architectural evaluations across **{total_agents} deployed autonomous agents**.

### Fleet Health KPI Overview
| Metric | Fleet Value | Benchmark Target | Status |
| :--- | :--- | :--- | :--- |
| **Total Evaluated Agents** | `{total_agents}` | - | Completed |
| **Fleet Average Score** | `{avg_overall:.2f} / 10.0` | > 8.00 | {'🟢 Strong' if avg_overall >= 8.0 else '🟡 Moderate' if avg_overall >= 6.5 else '🔴 Sub-optimal'} |
| **Average Edge TTFB Latency** | `{avg_latency:.1f} ms` | < 800 ms | {'🟢 Fast Edge' if avg_latency < 800 else '🟡 Moderate' if avg_latency < 1500 else '🔴 Slow Edge'} |
| **Security Hygiene Rate** | `{clean_percentage:.1f}% Clean` | 100.0% | {'🟢 Zero Leaks' if leaks_detected == 0 else '🚨 Leaks Found'} |
| **Credential Leaks Detected** | `{leaks_detected}` agent(s) | 0 | {'🟢 Passed' if leaks_detected == 0 else '🚨 Action Required'} |
| **Uncompiled Local Dev URIs** | `{local_dev_count}` agent(s) | 0 | {'🟢 None' if local_dev_count == 0 else '🟡 Found'} |
| **Top Performing Agent** | **{top_agent.name if top_agent else 'N/A'}** (`{top_agent.overall_score if top_agent else 0.0}/10.0`) | Rank #1 | 🏆 Leader |

---

## 🏆 Full Fleet Benchmarking Leaderboard

| Rank | Agent Name | Overall | UI/UX | Perf | Tech | Latency | HTTP Badge | Security Posture | Architecture |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :--- | :--- | :--- |
"""

    for r in results:
        md += (
            f"| **#{r.rank}** | [{r.name}]({r.url}) | **{r.overall_score:.1f}** | "
            f"{r.ui_score:.1f} | {r.perf_score:.1f} | {r.tech_score:.1f} | "
            f"{r.ttfb_ms:.0f} ms | `{r.status_badge}` | {r.security_status} | "
            f"{r.detected_framework} on {r.edge_platform} |\n"
        )

    md += """
---

## 🚨 Security & Secret Leakage Findings
"""

    if leaks_detected > 0 or local_dev_count > 0:
        md += "The following critical security anomalies were detected during client-side bundle and DOM scanning:\n\n"
        for r in results:
            if r.secret_findings or "Local Dev" in r.security_status:
                md += f"### ⚠️ Agent: {r.name} ([{r.url}]({r.url}))\n"
                md += f"- **Security Status**: {r.security_status}\n"
                if r.secret_findings:
                    md += "- **Detected Secrets**:\n"
                    for sf in r.secret_findings:
                        md += f"  - `[{sf['severity']}]` **{sf['pattern_name']}**: `{sf['masked_value']}` found in `{sf['source_location']}`\n"
                if "Local Dev" in r.security_status:
                    md += "- **Localhost Anomaly**: Bundle exposes uncompiled `127.0.0.1` / `localhost` references.\n"
                md += "\n"
    else:
        md += "✅ **No client-side API secrets, tokens, or private database URIs were discovered in public bundles.**\n\n"

    md += """---

## 🏗️ Detailed Per-Agent Architectural Breakdown

"""

    for r in results:
        md += f"""### Rank #{r.rank}: {r.name}
- **URL**: [{r.url}]({r.url})
- **Category / Domain**: `{r.category}`
- **Overall Score**: **`{r.overall_score:.2f} / 10.0`** *(Formula: UI 35% + Perf 35% + Tech 30%)*
- **Component Scores**: UI: `{r.ui_score:.1f}/10` | Performance: `{r.perf_score:.1f}/10` | Architecture: `{r.tech_score:.1f}/10`
- **Network Telemetry**: `{r.status_badge}` with `{r.ttfb_ms:.1f} ms` TTFB (Payload: `{r.bundle_size_kb:.1f} KB`)
- **Framework & Edge Host**: `{r.detected_framework}` hosted on `{r.edge_platform}`
- **Key Architectural Findings**: {r.key_findings}
- **UI Structure Assessment**: {r.ui_findings or 'Evaluated via DOM heuristic scanner.'}

"""

    md += """---

## 📋 Security Advisory & Hardening Recommendations

1. **Immediate Revocation of Client-Exposed API Keys:**
   - Any API keys identified in `<script>` tags or webpack/vite bundles must be **immediately revoked and rotated** at their respective providers (OpenAI, Groq, Google Cloud, MongoDB, GitHub).
   - Use server-side proxy routes (Next.js Route Handlers, FastAPI backend, or Edge Functions) to guard API keys. Never prefix LLM keys with `NEXT_PUBLIC_` or `VITE_`.

2. **Mitigating Render 503 "Cold-Start Sleep":**
   - Endpoints returning HTTP 503 during scans are idling on free-tier container spin-downs.
   - Configure a lightweight health-check cron or upgrade to warm instances to avoid 30–60 second agent invocation latencies.

3. **Client-Side Asset Optimization:**
   - Enable modern Brotli/Gzip compression on edge hosts to keep initial bundle sizes under 150 KB.
   - Include `<meta name="viewport" content="width=device-width, initial-scale=1.0">` to guarantee mobile responsiveness.

---
*Report automatically compiled by Agent Evaluator Suite.*
"""
    return md


def generate_pdf_report(results: List[EvaluationResult]) -> bytes:
    """
    Generate an executive-grade PDF audit report using ReportLab.
    Returns the PDF as raw bytes.
    """
    if not REPORTLAB_AVAILABLE:
        # Fallback to plain bytes if reportlab is unavailable
        return b"%PDF-1.4\n%Fallback empty PDF"

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#64748b'),
        spaceAfter=14
    )
    h2_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=12,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor('#334155')
    )
    table_cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor('#1e293b')
    )
    table_cell_bold = ParagraphStyle(
        'TableCellBold',
        parent=styles['Normal'],
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor('#0f172a'),
        fontName='Helvetica-Bold'
    )
    table_header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontSize=8,
        leading=10,
        textColor=colors.white,
        fontName='Helvetica-Bold'
    )

    elements = []

    # Title & Subtitle
    elements.append(Paragraph("🛡️ Agent Evaluator: Autonomous Audit & Benchmarking Report", title_style))
    elements.append(Paragraph(f"Autonomous Fleet Inspection | Generated {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())} | Agent Evaluator v2.0", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#3b82f6"), spaceAfter=10))

    # KPI Summary Box
    total = len(results)
    avg_score = sum(r.overall_score for r in results) / total if total else 0.0
    leaks = sum(1 for r in results if "Leak Detected" in r.security_status)
    fast_edge = sum(1 for r in results if r.ttfb_ms > 0 and r.ttfb_ms < 800)

    kpi_data = [
        [
            Paragraph("<b>Total Agents Evaluated</b>", table_cell_style),
            Paragraph("<b>Fleet Average Score</b>", table_cell_style),
            Paragraph("<b>Fast Edge Latency (<800ms)</b>", table_cell_style),
            Paragraph("<b>Security Leak Alerts</b>", table_cell_style),
        ],
        [
            Paragraph(f"<font size=12><b>{total}</b></font>", table_cell_bold),
            Paragraph(f"<font size=12 color='#2563eb'><b>{avg_score:.2f} / 10.0</b></font>", table_cell_bold),
            Paragraph(f"<font size=12 color='#16a34a'><b>{fast_edge} / {total}</b></font>", table_cell_bold),
            Paragraph(f"<font size=12 color='{'#dc2626' if leaks > 0 else '#16a34a'}'><b>{leaks}</b></font>", table_cell_bold),
        ]
    ]
    kpi_table = Table(kpi_data, colWidths=[130, 130, 140, 140])
    kpi_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
    ]))
    elements.append(kpi_table)
    elements.append(Spacer(1, 12))

    # Leaderboard Table
    elements.append(Paragraph("Fleet Benchmarking Leaderboard", h2_style))

    table_data = [[
        Paragraph("Rank", table_header_style),
        Paragraph("Agent Name", table_header_style),
        Paragraph("Score", table_header_style),
        Paragraph("UI/Perf/Tech", table_header_style),
        Paragraph("TTFB Latency", table_header_style),
        Paragraph("Framework & Host", table_header_style),
        Paragraph("Security Posture", table_header_style),
    ]]

    for r in results:
        sec_color = "#dc2626" if "Leak" in r.security_status else ("#d97706" if "Local" in r.security_status else "#16a34a")
        table_data.append([
            Paragraph(f"<b>#{r.rank}</b>", table_cell_bold),
            Paragraph(f"<b>{r.name}</b><br/><font color='#64748b'>{r.url[:32]}...</font>", table_cell_style),
            Paragraph(f"<b>{r.overall_score:.1f}</b>", table_cell_bold),
            Paragraph(f"{r.ui_score:.1f} / {r.perf_score:.1f} / {r.tech_score:.1f}", table_cell_style),
            Paragraph(f"{r.ttfb_ms:.0f} ms<br/><font color='#64748b'>{r.status_badge}</font>", table_cell_style),
            Paragraph(f"{r.detected_framework}<br/><font color='#64748b'>{r.edge_platform}</font>", table_cell_style),
            Paragraph(f"<font color='{sec_color}'><b>{r.security_status}</b></font>", table_cell_style),
        ])

    leader_table = Table(table_data, colWidths=[35, 115, 45, 75, 75, 105, 90])
    leader_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(leader_table)
    elements.append(Spacer(1, 14))

    # Security Alerts & Vulnerabilities Section
    elements.append(Paragraph("Security & Secret Leakage Inspection", h2_style))
    if leaks > 0:
        elements.append(Paragraph(
            "<font color='#dc2626'><b>CRITICAL ALERT:</b> One or more public client bundles contain hardcoded API credentials. Immediate revocation required.</font>",
            body_style
        ))
        elements.append(Spacer(1, 6))

        sec_data = [[
            Paragraph("Agent", table_header_style),
            Paragraph("Vulnerability", table_header_style),
            Paragraph("Masked Secret Preview", table_header_style),
            Paragraph("Bundle Location", table_header_style),
        ]]
        for r in results:
            for sf in r.secret_findings:
                sec_data.append([
                    Paragraph(f"<b>{r.name}</b>", table_cell_bold),
                    Paragraph(f"<font color='#dc2626'><b>{sf['pattern_name']}</b></font>", table_cell_style),
                    Paragraph(f"<code>{sf['masked_value']}</code>", table_cell_style),
                    Paragraph(f"{sf['source_location']}", table_cell_style),
                ])
        sec_table = Table(sec_data, colWidths=[100, 120, 140, 180])
        sec_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#7f1d1d')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fef2f2')]),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#fca5a5')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#fecaca')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(sec_table)
    else:
        elements.append(Paragraph(
            "<b>🟢 Clean Posture:</b> No unencrypted API keys or production database strings were found in inspected client assets.",
            body_style
        ))

    elements.append(Spacer(1, 14))

    # Architectural Highlights Section
    elements.append(Paragraph("Key Architectural Findings", h2_style))
    for r in results[:5]:  # Top 5 highlights
        elements.append(Paragraph(
            f"<b>#{r.rank} {r.name}:</b> {r.key_findings} <i>(UI Score: {r.ui_score:.1f}, Perf: {r.perf_score:.1f}, Tech: {r.tech_score:.1f})</i>",
            body_style
        ))
        elements.append(Spacer(1, 4))

    # Build Document
    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()
