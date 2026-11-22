"""
app.py - Agent Evaluator
AI-Powered Multi-Agent Autonomous Benchmarking & Security Suite
A sleek, production-ready Streamlit dashboard with real-time network,
security leak inspection, and AI-driven architecture audits.
"""

import os
import io
import time
import json
import uuid
import asyncio
from typing import List, Dict, Any, Optional
import pandas as pd
import streamlit as st

from evaluator import (
    AgentTarget,
    EvaluationResult,
    evaluate_single_agent,
    parse_bulk_text,
    normalize_url,
    SECRET_PATTERNS
)
from report_generator import (
    generate_leaderboard_dataframe,
    generate_markdown_dossier,
    generate_pdf_report
)

# ==============================================================================
# Page Configuration & Styling
# ==============================================================================

st.set_page_config(
    page_title="Agent Evaluator | Autonomous Benchmarking & Security Suite",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Sleek Cyber-Audit Aesthetic
st.markdown("""
<style>
    /* Main container styling */
    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2.5rem;
        max-width: 96%;
    }
    
    /* Header branding */
    .brand-header {
        background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
        padding: 24px 30px;
        border-radius: 14px;
        border: 1px solid rgba(99, 102, 241, 0.3);
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        margin-bottom: 24px;
    }
    .brand-title {
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(90deg, #38bdf8, #818cf8, #c084fc);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 0;
        letter-spacing: -0.5px;
    }
    .brand-subtitle {
        color: #94a3b8;
        font-size: 0.95rem;
        margin-top: 6px;
        font-weight: 400;
    }
    .badge-pill {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 9999px;
        font-size: 0.72rem;
        font-weight: 600;
        margin-right: 6px;
        margin-top: 8px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .badge-cyan { background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); }
    .badge-indigo { background: rgba(129, 140, 248, 0.15); color: #818cf8; border: 1px solid rgba(129, 140, 248, 0.3); }
    .badge-green { background: rgba(52, 211, 153, 0.15); color: #34d399; border: 1px solid rgba(52, 211, 153, 0.3); }
    
    /* Metric Cards */
    .kpi-card {
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 16px 20px;
        text-align: left;
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .kpi-card:hover {
        border-color: #6366f1;
        transform: translateY(-2px);
    }
    .kpi-value {
        font-size: 1.8rem;
        font-weight: 700;
        color: #f8fafc;
        margin: 4px 0;
    }
    .kpi-label {
        font-size: 0.8rem;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        font-weight: 600;
    }

    /* Live Scanning Card */
    .scan-card {
        background: #0f172a;
        border: 1px solid #38bdf8;
        border-radius: 10px;
        padding: 14px 18px;
        margin-bottom: 12px;
        box-shadow: 0 0 15px rgba(56, 189, 248, 0.15);
    }
    .scan-card-title {
        color: #f8fafc;
        font-weight: 700;
        font-size: 1.05rem;
    }
    .scan-card-meta {
        color: #64748b;
        font-size: 0.8rem;
        font-family: monospace;
    }
    
    /* Table Styling */
    .stDataFrame {
        border-radius: 8px;
        overflow: hidden;
    }
</style>
""", unsafe_allow_html=True)


# ==============================================================================
# Session State Initialization
# ==============================================================================

def make_box(name: str = "", url: str = "") -> dict:
    return {
        "id": str(uuid.uuid4())[:8],
        "name": name,
        "url": url
    }

if "agent_boxes" not in st.session_state:
    st.session_state.agent_boxes = [
        make_box("Agent #1", "https://research-collaboration-agent.vercel.app/"),
        make_box("Agent #2", "https://feewise-red.vercel.app")
    ]

if "evaluation_results" not in st.session_state:
    st.session_state.evaluation_results = []

if "is_evaluating" not in st.session_state:
    st.session_state.is_evaluating = False

if "parsed_targets" not in st.session_state:
    # Initialize from the default boxes
    st.session_state.parsed_targets = [
        AgentTarget(name=b["name"], url=normalize_url(b["url"]), category="General")
        for b in st.session_state.agent_boxes if b["url"].strip()
    ]

if "gemini_api_key" not in st.session_state:
    st.session_state.gemini_api_key = os.getenv("GEMINI_API_KEY", "")

if "timeout_sec" not in st.session_state:
    st.session_state.timeout_sec = 12.0


# ==============================================================================
# Helper: Sample Template Generators
# ==============================================================================

def get_sample_csv_template() -> str:
    return (
        "Agent_Name,URL,Category\n"
        "Perplexity AI,https://www.perplexity.ai,Search & Research\n"
        "Vercel AI SDK,https://sdk.vercel.ai,Developer Tools\n"
        "Streamlit AI,https://streamlit.io/generative-ai,Data & Analytics\n"
        "Hugging Face Chat,https://huggingface.co/chat,NLP & Open Models\n"
        "FastAPI LLM Edge,https://fastapi.tiangolo.com,Backend API\n"
    )

def get_sample_json_template() -> str:
    sample_data = [
        {"Agent_Name": "Perplexity AI", "URL": "https://www.perplexity.ai", "Category": "Search & Research"},
        {"Agent_Name": "Vercel AI SDK", "URL": "https://sdk.vercel.ai", "Category": "Developer Tools"},
        {"Agent_Name": "Streamlit AI", "URL": "https://streamlit.io/generative-ai", "Category": "Data & Analytics"},
    ]
    return json.dumps(sample_data, indent=2)


# ==============================================================================
# Sidebar: Settings & System Status
# ==============================================================================

with st.sidebar:
    st.markdown("### ⚡ Engine Control")
    st.caption("AI-Powered Multi-Agent Autonomous Suite")

    api_key_input = st.text_input(
        "Gemini API Key (Optional)",
        value=st.session_state.gemini_api_key,
        type="password",
        help="If provided, Gemini 2.5 Flash analyzes UI hierarchy and component structure. If omitted, built-in heuristic grading is used."
    )
    if api_key_input != st.session_state.gemini_api_key:
        st.session_state.gemini_api_key = api_key_input

    if st.session_state.gemini_api_key:
        st.success("🟢 Gemini API Enabled", icon="✅")
    else:
        st.info("ℹ️ Heuristic Fallback Active", icon="⚡")

    st.markdown("---")
    st.markdown("### ⏱️ Network Timeouts")
    timeout = st.slider("Probe Timeout (seconds)", min_value=3, max_value=25, value=12, step=1)
    st.session_state.timeout_sec = float(timeout)

    st.markdown("---")
    st.markdown("### 🔍 Active Secret Scanners")
    st.caption("Inspecting DOM & first-party JavaScript bundles:")
    for pat_name, meta in SECRET_PATTERNS.items():
        st.markdown(f"- **{pat_name}** (`{meta['severity']}`)")
    st.markdown("- **Local Dev URIs** (`127.0.0.1 / localhost`)")

    st.markdown("---")
    if st.button("🗑️ Reset All Scans & Data", use_container_width=True):
        st.session_state.evaluation_results = []
        st.session_state.parsed_targets = []
        st.rerun()


# ==============================================================================
# Header Branding
# ==============================================================================

st.markdown("""
<div class="brand-header">
    <div class="brand-title">⚡ AGENT EVALUATOR</div>
    <div class="brand-subtitle">
        AI-Powered Multi-Agent Autonomous Benchmarking & Security Suite &bull; Real-Time TTFB Edge Telemetry &bull; Client-Side Secret Leak Detection &bull; Architectural Grading
    </div>
    <div style="margin-top: 10px;">
        <span class="badge-pill badge-cyan">Zero Hardcoded URLs</span>
        <span class="badge-pill badge-indigo">Dynamic Batch Upload</span>
        <span class="badge-pill badge-green">3-Stage Evaluation Engine</span>
        <span class="badge-pill badge-cyan">Gemini 2.5 / Heuristic Auditing</span>
    </div>
</div>
""", unsafe_allow_html=True)


# ==============================================================================
# STEP 1 & STEP 2: Scope Selection & Dynamic Link Upload
# ==============================================================================

with st.expander("🛠️ Step 1 & Step 2: Configure Evaluation Scope & Upload Links", expanded=len(st.session_state.evaluation_results) == 0):
    col1, col2 = st.columns([1, 1], gap="medium")

    with col1:
        st.markdown("#### **Step 1: Scope & Range Selection**")
        st.caption("Select how many agents to evaluate from your uploaded target pool:")

        scope_option = st.radio(
            "Evaluation Scope Preset:",
            options=[
                "1 – 10 Agents (Quick Demo)",
                "1 – 20 Agents",
                "20 – 30 Agents",
                "All Uploaded Agents",
                "Custom Numeric Slider"
            ],
            index=3
        )

        custom_limit = None
        if scope_option == "Custom Numeric Slider":
            custom_limit = st.slider("Target Limit (Custom Slider)", min_value=1, max_value=50, value=10)

        # Quick Load Preset Demo button
        st.markdown("##### 🎲 Instant Demo")
        if st.button("📂 Load Preset Benchmark Dataset (25 Public Agents)", use_container_width=True):
            if os.path.exists("sample_agents.csv"):
                df_sample = pd.read_csv("sample_agents.csv")
                sample_targets = []
                for _, row in df_sample.iterrows():
                    sample_targets.append(AgentTarget(
                        name=str(row["Agent_Name"]),
                        url=str(row["URL"]),
                        category=str(row.get("Category", "General"))
                    ))
                st.session_state.parsed_targets = sample_targets
                st.session_state.agent_boxes = [
                    make_box(t.name, t.url) for t in sample_targets
                ]
                st.success(f"Loaded {len(sample_targets)} sample agents into target pool and boxes!")
                st.rerun()

    with col2:
        st.markdown("#### **Step 2: Dynamic Link Upload (All at Once)**")
        upload_mode = st.tabs([
            "🔗 Agent Link Boxes (2 Boxes per Link)",
            "📝 Bulk Paste Text Area",
            "📁 File Uploader (.CSV / .JSON)"
        ])

        with upload_mode[0]:
            st.markdown("""
            <div style="background: rgba(56, 189, 248, 0.08); border-left: 3px solid #38bdf8; padding: 8px 12px; border-radius: 6px; margin-bottom: 12px; font-size: 0.85rem; color: #cbd5e1;">
                <b>Two Dedicated Boxes for Each Link:</b><br/>
                &bull; <b>Box 1:</b> Agent Name or Number (e.g. <code>Agent #1</code>, <code>Research Agent</code>)<br/>
                &bull; <b>Box 2:</b> Agent Deployment Link (e.g. <code>https://research-collaboration-agent.vercel.app/</code>)
            </div>
            """, unsafe_allow_html=True)

            # Column Headers
            hcol1, hcol2, hcol3 = st.columns([1.1, 2.5, 0.4])
            with hcol1:
                st.markdown("**🏷️ Box 1: Agent Name / #**")
            with hcol2:
                st.markdown("**🌐 Box 2: Agent Link (URL)**")
            with hcol3:
                st.markdown("**Del**")

            boxes_to_remove = None
            for idx, row in enumerate(st.session_state.agent_boxes):
                r_id = row["id"]
                rcol1, rcol2, rcol3 = st.columns([1.1, 2.5, 0.4])
                with rcol1:
                    row["name"] = st.text_input(
                        f"Box 1 Name #{idx+1}",
                        value=row["name"],
                        key=f"box_name_{r_id}",
                        placeholder=f"Agent #{idx+1}",
                        label_visibility="collapsed"
                    )
                with rcol2:
                    row["url"] = st.text_input(
                        f"Box 2 Link #{idx+1}",
                        value=row["url"],
                        key=f"box_url_{r_id}",
                        placeholder="https://... or agent.vercel.app",
                        label_visibility="collapsed"
                    )
                with rcol3:
                    if len(st.session_state.agent_boxes) > 1:
                        if st.button("🗑️", key=f"del_{r_id}", help=f"Remove Agent #{idx+1}"):
                            boxes_to_remove = r_id

            if boxes_to_remove:
                st.session_state.agent_boxes = [b for b in st.session_state.agent_boxes if b["id"] != boxes_to_remove]
                st.rerun()

            # Actions under boxes
            bcol1, bcol2, bcol3 = st.columns([1.2, 1, 1.4])
            with bcol1:
                if st.button("➕ Add Another Link Box", use_container_width=True):
                    next_idx = len(st.session_state.agent_boxes) + 1
                    st.session_state.agent_boxes.append(make_box(f"Agent #{next_idx}", ""))
                    st.rerun()
            with bcol2:
                if st.button("🧹 Clear All Boxes", use_container_width=True):
                    st.session_state.agent_boxes = [make_box("Agent #1", "")]
                    st.rerun()
            with bcol3:
                quick_add = st.selectbox(
                    "Quick Add Multiple Boxes:",
                    ["+ Add Multiple Boxes...", "+ 2 Boxes", "+ 5 Boxes", "+ 10 Boxes"],
                    label_visibility="collapsed"
                )
                if quick_add == "+ 2 Boxes":
                    for _ in range(2):
                        st.session_state.agent_boxes.append(make_box(f"Agent #{len(st.session_state.agent_boxes)+1}", ""))
                    st.rerun()
                elif quick_add == "+ 5 Boxes":
                    for _ in range(5):
                        st.session_state.agent_boxes.append(make_box(f"Agent #{len(st.session_state.agent_boxes)+1}", ""))
                    st.rerun()
                elif quick_add == "+ 10 Boxes":
                    for _ in range(10):
                        st.session_state.agent_boxes.append(make_box(f"Agent #{len(st.session_state.agent_boxes)+1}", ""))
                    st.rerun()

            # Automatically sync active targets from boxes
            box_targets = []
            for idx, b in enumerate(st.session_state.agent_boxes):
                n = b["name"].strip() or f"Agent #{idx+1}"
                u = b["url"].strip()
                if u:
                    box_targets.append(AgentTarget(name=n, url=normalize_url(u), category="General"))

            st.session_state.parsed_targets = box_targets

        with upload_mode[1]:
            st.caption("Paste multiple URLs (one per line, e.g. `Agent Name, https://...` or bare URLs):")
            bulk_text = st.text_area(
                "Paste links here",
                height=130,
                placeholder="Agent #1, https://research-collaboration-agent.vercel.app/\nAgent #2, https://feewise-red.vercel.app",
                label_visibility="collapsed"
            )
            if st.button("📥 Parse Pasted Links", use_container_width=True):
                if bulk_text.strip():
                    p_targets = parse_bulk_text(bulk_text)
                    st.session_state.parsed_targets = p_targets
                    st.session_state.agent_boxes = [
                        make_box(t.name, t.url) for t in p_targets
                    ]
                    st.success(f"Parsed {len(p_targets)} agents and populated the 2-box inputs!")
                    st.rerun()

        with upload_mode[2]:
            st.caption("Upload a `.csv` or `.json` file containing: `Agent_Name`, `URL`, `Category`")
            uploaded_file = st.file_uploader(
                "Choose file",
                type=["csv", "json"],
                accept_multiple_files=False,
                label_visibility="collapsed"
            )

            # Download Sample CSV & JSON Templates
            c_csv, c_json = st.columns(2)
            with c_csv:
                st.download_button(
                    "📥 Download Sample CSV",
                    data=get_sample_csv_template(),
                    file_name="sample_agent_template.csv",
                    mime="text/csv",
                    use_container_width=True
                )
            with c_json:
                st.download_button(
                    "📥 Download Sample JSON",
                    data=get_sample_json_template(),
                    file_name="sample_agent_template.json",
                    mime="application/json",
                    use_container_width=True
                )

            if uploaded_file is not None:
                try:
                    if uploaded_file.name.endswith(".csv"):
                        df = pd.read_csv(uploaded_file)
                        # Normalize column names
                        col_map = {c.strip().lower(): c for c in df.columns}
                        name_col = col_map.get("agent_name") or col_map.get("name") or df.columns[0]
                        url_col = col_map.get("url") or col_map.get("link") or df.columns[1]
                        cat_col = col_map.get("category") or col_map.get("role") or None

                        targets = []
                        for _, row in df.iterrows():
                            n = str(row[name_col]).strip()
                            u = str(row[url_col]).strip()
                            c = str(row[cat_col]).strip() if cat_col else "General"
                            if u:
                                targets.append(AgentTarget(name=n, url=normalize_url(u), category=c))
                        st.session_state.parsed_targets = targets
                        st.session_state.agent_boxes = [
                            make_box(t.name, t.url) for t in targets
                        ]
                        st.success(f"Parsed {len(targets)} agents from {uploaded_file.name} and populated boxes!")
                        st.rerun()
                    else:
                        json_data = json.load(uploaded_file)
                        targets = []
                        for item in json_data:
                            n = item.get("Agent_Name") or item.get("name") or "Agent"
                            u = item.get("URL") or item.get("url") or ""
                            c = item.get("Category") or item.get("role") or "General"
                            if u:
                                targets.append(AgentTarget(name=n, url=normalize_url(u), category=c))
                        st.session_state.parsed_targets = targets
                        st.session_state.agent_boxes = [
                            make_box(t.name, t.url) for t in targets
                        ]
                        st.success(f"Parsed {len(targets)} agents from {uploaded_file.name} and populated boxes!")
                        st.rerun()
                except Exception as e:
                    st.error(f"Error reading file: {str(e)}")

    # Determine Active Subslice Based on Step 1 Scope
    all_targets = st.session_state.parsed_targets
    selected_targets: List[AgentTarget] = []

    if all_targets:
        if scope_option == "1 – 10 Agents (Quick Demo)":
            selected_targets = all_targets[:10]
        elif scope_option == "1 – 20 Agents":
            selected_targets = all_targets[:20]
        elif scope_option == "20 – 30 Agents":
            selected_targets = all_targets[19:30] if len(all_targets) >= 20 else all_targets[:30]
        elif scope_option == "Custom Numeric Slider":
            selected_targets = all_targets[:custom_limit]
        else:
            selected_targets = all_targets

        st.markdown("---")
        col_summary, col_action = st.columns([2, 1])
        with col_summary:
            st.markdown(
                f"**Target Pool Summary**: **{len(all_targets)}** uploaded target(s). "
                f"Evaluation scope will benchmark **{len(selected_targets)}** agent(s)."
            )
        with col_action:
            if st.button("Clear Target Pool", type="secondary", use_container_width=True):
                st.session_state.parsed_targets = []
                st.session_state.agent_boxes = [make_box("Agent #1", "")]
                st.rerun()

        # Preview Table of Selected Targets
        with st.expander("👁️ View Selected Target Queue", expanded=False):
            preview_df = pd.DataFrame([
                {"#": i + 1, "Agent Name": t.name, "Target URL": t.url, "Category": t.category}
                for i, t in enumerate(selected_targets)
            ])
            st.dataframe(preview_df, use_container_width=True, hide_index=True)


# ==============================================================================
# STEP 3: Execution & Real-Time Progress
# ==============================================================================

all_targets = st.session_state.parsed_targets
active_targets: List[AgentTarget] = []
if all_targets:
    if scope_option == "1 – 10 Agents (Quick Demo)":
        active_targets = all_targets[:10]
    elif scope_option == "1 – 20 Agents":
        active_targets = all_targets[:20]
    elif scope_option == "20 – 30 Agents":
        active_targets = all_targets[19:30] if len(all_targets) >= 20 else all_targets[:30]
    elif scope_option == "Custom Numeric Slider":
        active_targets = all_targets[:(custom_limit or 10)]
    else:
        active_targets = all_targets

st.markdown("### 🚀 Step 3: Execution & Real-Time Progress")

col_btn, col_info = st.columns([1, 2], vertical_alignment="center")
with col_btn:
    start_eval = st.button(
        "🚀 Start Autonomous Evaluation",
        type="primary",
        use_container_width=True,
        disabled=len(active_targets) == 0
    )

with col_info:
    if len(active_targets) == 0:
        st.warning("⚠️ Please upload links or load the preset dataset in Step 1 & 2 to begin evaluation.")
    else:
        st.info(f"Ready to evaluate **{len(active_targets)} agent targets** across Network, Security, and AI Architecture stages.")

# Real-Time Evaluation Loop
if start_eval and active_targets:
    st.session_state.is_evaluating = True
    progress_bar = st.progress(0, text="Initializing evaluation engine...")
    live_status_container = st.empty()
    live_card_container = st.empty()

    results: List[EvaluationResult] = []
    total_targets = len(active_targets)

    # Run evaluation sequentially with animated real-time status cards
    for idx, target in enumerate(active_targets, start=1):
        # Progress calculation
        pct = int(((idx - 1) / total_targets) * 100)
        progress_bar.progress(pct, text=f"Evaluating Agent {idx} of {total_targets}: {target.name}...")

        # Animated live scan status card
        live_card_container.markdown(f"""
        <div class="scan-card">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span class="scan-card-title">🔍 Pinging & Scanning: {target.name}</span>
                <span style="color: #38bdf8; font-weight: 600; font-size: 0.85rem;">[Stage 1/2/3 Active]</span>
            </div>
            <div class="scan-card-meta">{target.url} &bull; Category: {target.category}</div>
            <div style="margin-top: 8px; font-size: 0.85rem; color: #cbd5e1;">
                ⚡ Measuring real-time TTFB &bull; 🛡️ Inspecting DOM & bundle scripts for leaked API secrets &bull; 🧠 Tech stack architecture analysis
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Execute evaluation asynchronously
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            eval_res = loop.run_until_complete(
                evaluate_single_agent(
                    target=target,
                    gemini_api_key=st.session_state.gemini_api_key,
                    timeout_sec=st.session_state.timeout_sec
                )
            )
            loop.close()
        except Exception as e:
            # Fallback error record
            eval_res = EvaluationResult(
                name=target.name,
                url=target.url,
                category=target.category,
                http_status=0,
                status_badge="Scan Exception",
                key_findings=f"Engine error: {str(e)[:80]}",
                evaluated_at=time.strftime("%Y-%m-%d %H:%M:%S")
            )

        results.append(eval_res)

    # Finalize progress bar
    progress_bar.progress(100, text=f"✅ Autonomous Evaluation Complete! ({total_targets}/{total_targets} Agents Evaluated)")
    live_card_container.empty()

    # Assign ranks sorted by overall score descending
    results.sort(key=lambda r: r.overall_score, reverse=True)
    for rank_idx, r in enumerate(results, start=1):
        r.rank = rank_idx

    st.session_state.evaluation_results = results
    st.session_state.is_evaluating = False
    st.success("🎉 All agents evaluated successfully! Leaderboard and security dossiers are populated below.")


# ==============================================================================
# STEP 4: Interactive Leaderboard Table & Dashboards
# ==============================================================================

eval_results: List[EvaluationResult] = st.session_state.evaluation_results

if eval_results:
    st.markdown("---")
    st.markdown("### 🏆 Fleet Evaluation Leaderboard & Intelligence")

    # High-Level Metric KPI Row
    total_eval = len(eval_results)
    avg_score = sum(r.overall_score for r in eval_results) / total_eval
    valid_latencies = [r.ttfb_ms for r in eval_results if r.ttfb_ms > 0]
    avg_lat = sum(valid_latencies) / len(valid_latencies) if valid_latencies else 0.0
    leaks_found = sum(1 for r in eval_results if "Leak Detected" in r.security_status)
    local_dev_count = sum(1 for r in eval_results if "Local Dev" in r.security_status)
    clean_pct = ((total_eval - leaks_found - local_dev_count) / total_eval) * 100.0

    kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
    with kpi1:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">Total Agents</div>
            <div class="kpi-value">{total_eval}</div>
            <span style="color: #64748b; font-size: 0.75rem;">Ranked #1 to #{total_eval}</span>
        </div>
        """, unsafe_allow_html=True)
    with kpi2:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">Fleet Avg Score</div>
            <div class="kpi-value" style="color: #38bdf8;">{avg_score:.2f} <span style="font-size: 1rem; color: #94a3b8;">/ 10</span></div>
            <span style="color: #64748b; font-size: 0.75rem;">UI: 35% | Perf: 35% | Tech: 30%</span>
        </div>
        """, unsafe_allow_html=True)
    with kpi3:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">Avg Edge Latency</div>
            <div class="kpi-value" style="color: {'#34d399' if avg_lat < 800 else '#f59e0b'};">{avg_lat:.0f} <span style="font-size: 1rem; color: #94a3b8;">ms</span></div>
            <span style="color: #64748b; font-size: 0.75rem;">Real-time TTFB probe</span>
        </div>
        """, unsafe_allow_html=True)
    with kpi4:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">Security Posture</div>
            <div class="kpi-value" style="color: {'#34d399' if clean_pct == 100 else '#f87171'};">{clean_pct:.0f}%</div>
            <span style="color: #64748b; font-size: 0.75rem;">Clean client bundles</span>
        </div>
        """, unsafe_allow_html=True)
    with kpi5:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-label">Secret Leaks</div>
            <div class="kpi-value" style="color: {'#34d399' if leaks_found == 0 else '#ef4444'};">{leaks_found}</div>
            <span style="color: #64748b; font-size: 0.75rem;">{'Zero leaks' if leaks_found == 0 else 'CRITICAL: Action needed'}</span>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br/>", unsafe_allow_html=True)

    # Main Tabs for Leaderboard, Security Scanner, AI Insights & Export
    tab_leader, tab_security, tab_arch, tab_export = st.tabs([
        "📊 Step 4: Interactive Leaderboard",
        "🚨 Stage 2: Secret & Security Leaks",
        "🧠 Stage 3: AI Architecture & UI",
        "📥 Step 5: Export Dossier (CSV / MD / PDF)"
    ])

    # --------------------------------------------------------------------------
    # Tab 1: Interactive Leaderboard Table
    # --------------------------------------------------------------------------
    with tab_leader:
        st.markdown("#### **Autonomous Fleet Leaderboard (Rank #1 to #N)**")

        # Filters
        fcol1, fcol2, fcol3 = st.columns([1, 1, 1])
        with fcol1:
            sec_filter = st.selectbox(
                "Filter by Security Status:",
                ["All Agents", "🟢 Clean Only", "🚨 Leaks Detected", "🟡 Local Dev URI"]
            )
        with fcol2:
            all_frameworks = sorted(list({r.detected_framework for r in eval_results}))
            fw_filter = st.selectbox(
                "Filter by Tech Framework:",
                ["All Frameworks"] + all_frameworks
            )
        with fcol3:
            search_query = st.text_input("🔍 Search by Agent Name or URL:", "")

        # Apply Filters
        filtered_results = eval_results
        if sec_filter == "🟢 Clean Only":
            filtered_results = [r for r in filtered_results if "Clean" in r.security_status]
        elif sec_filter == "🚨 Leaks Detected":
            filtered_results = [r for r in filtered_results if "Leak Detected" in r.security_status]
        elif sec_filter == "🟡 Local Dev URI":
            filtered_results = [r for r in filtered_results if "Local Dev" in r.security_status]

        if fw_filter != "All Frameworks":
            filtered_results = [r for r in filtered_results if r.detected_framework == fw_filter]

        if search_query.strip():
            sq = search_query.strip().lower()
            filtered_results = [r for r in filtered_results if sq in r.name.lower() or sq in r.url.lower()]

        # Generate Display Table
        df_display = generate_leaderboard_dataframe(filtered_results)

        st.dataframe(
            df_display,
            column_config={
                "Rank": st.column_config.TextColumn("Rank", width="small"),
                "Agent Name": st.column_config.TextColumn("Agent Name", width="medium"),
                "URL": st.column_config.LinkColumn("Target URL", width="medium"),
                "Overall Score": st.column_config.TextColumn("Overall Score", width="small"),
                "UI/UX Score": st.column_config.TextColumn("UI/UX (/10)", width="small"),
                "Perf Score": st.column_config.TextColumn("Perf (/10)", width="small"),
                "Tech Score": st.column_config.TextColumn("Tech (/10)", width="small"),
                "Latency (TTFB)": st.column_config.TextColumn("Latency", width="small"),
                "HTTP Status": st.column_config.TextColumn("HTTP Status", width="small"),
                "Tech Stack": st.column_config.TextColumn("Architecture Stack", width="medium"),
                "Security Status": st.column_config.TextColumn("Security Status", width="medium"),
                "Key Architectural Findings": st.column_config.TextColumn("Architectural Findings", width="large"),
            },
            use_container_width=True,
            hide_index=True,
            height=450
        )

        st.caption("ℹ️ Click any column header to sort in ascending or descending order.")

        # Top 3 Podium Cards
        if len(filtered_results) >= 1:
            st.markdown("##### 🏅 Top Performing Autonomous Agents")
            podium_cols = st.columns(min(3, len(filtered_results)))
            medals = ["🥇 Rank #1 Leader", "🥈 Rank #2 Runner Up", "🥉 Rank #3 Bronze"]
            colors = ["#eab308", "#94a3b8", "#d97706"]

            for p_idx, col in enumerate(podium_cols):
                if p_idx < len(filtered_results):
                    target_res = filtered_results[p_idx]
                    with col:
                        st.markdown(f"""
                        <div style="background: #0f172a; border: 1px solid {colors[p_idx]}; border-radius: 10px; padding: 14px; text-align: center;">
                            <div style="color: {colors[p_idx]}; font-weight: 700; font-size: 0.9rem;">{medals[p_idx]}</div>
                            <div style="font-size: 1.25rem; font-weight: 800; color: #f8fafc; margin: 4px 0;">{target_res.name}</div>
                            <div style="font-size: 1.5rem; font-weight: 800; color: #38bdf8;">{target_res.overall_score:.1f} <span style="font-size: 0.8rem; color: #94a3b8;">/ 10</span></div>
                            <div style="font-size: 0.75rem; color: #94a3b8; margin-top: 4px;">{target_res.tech_stack} &bull; {target_res.ttfb_ms:.0f}ms</div>
                            <div style="margin-top: 6px; font-size: 0.75rem;">{target_res.security_status}</div>
                        </div>
                        """, unsafe_allow_html=True)

    # --------------------------------------------------------------------------
    # Tab 2: Security & Secret Leak Inspector
    # --------------------------------------------------------------------------
    with tab_security:
        st.markdown("#### **Stage 2: Client-Side Secret & Security Leak Audit**")
        st.caption(
            "Every target's HTML and client-side JavaScript bundles were analyzed with deterministic regexes "
            "to detect unencrypted production credentials accidentally shipped to the browser."
        )

        sec_col1, sec_col2 = st.columns([1, 1])
        with sec_col1:
            st.metric("Total Inspected Agents", total_eval)
            st.metric("Critical Leaks Found", leaks_found, delta=-leaks_found if leaks_found > 0 else 0, delta_color="inverse")
        with sec_col2:
            st.metric("Clean Security Posture Rate", f"{clean_pct:.1f}%")
            st.metric("Localhost / Dev URI Warnings", local_dev_count, delta=-local_dev_count if local_dev_count > 0 else 0, delta_color="inverse")

        st.markdown("---")

        if leaks_found > 0 or local_dev_count > 0:
            st.markdown("##### 🚨 Critical Security Findings & Remediation")
            for r in eval_results:
                if r.secret_findings or "Local Dev" in r.security_status:
                    with st.expander(f"⚠️ {r.name} ({r.url}) — {r.security_status}", expanded=True):
                        st.markdown(f"**Target URL**: [{r.url}]({r.url})")
                        st.markdown(f"**Security Badge**: `{r.security_status}`")
                        st.markdown(f"**Scanned Bundles**: `{r.scanned_scripts_count}` first-party scripts inspected")

                        if r.secret_findings:
                            st.error(f"🚨 {len(r.secret_findings)} Credential Leak(s) Detected in Client Assets:")
                            for sf in r.secret_findings:
                                st.markdown(f"""
                                - **Vulnerability**: `{sf['pattern_name']}` ({sf['secret_type']})
                                - **Severity**: `{sf['severity']}`
                                - **Location**: `{sf['source_location']}`
                                - **Masked Preview**: `{sf['masked_value']}`
                                """)
                            st.warning("""
                            **Remediation Steps:**
                            1. **Immediate Revocation**: Go to your LLM / cloud provider console and immediately revoke this leaked key.
                            2. **Server-Side Proxy**: Move all API calls to server-side routes (FastAPI, Next.js API Routes, Express, or Edge Functions).
                            3. **Env Guard**: Ensure environment variables are not prefixed with `NEXT_PUBLIC_` or `VITE_`.
                            """)

                        if "Local Dev" in r.security_status:
                            st.info("🟡 **Localhost / 127.0.0.1 URI Found**: Client-side code contains hardcoded local endpoints. Ensure production builds use dynamic base URLs.")
        else:
            st.success("🟢 **No leaked API keys, tokens, or private credentials were found in any client assets!**")
            st.markdown("""
            **Scanned Signatures Included:**
            - Groq Cloud API Keys (`gsk_...`)
            - OpenAI API Keys (`sk-...`, `sk-proj-...`)
            - Google Cloud / Firebase Keys (`AIzaSy...`)
            - MongoDB Database Connection Strings (`mongodb+srv://...`)
            - GitHub Personal Access Tokens (`ghp_...`, `gho_...`)
            - Anthropic Claude Keys (`sk-ant-...`)
            - Hugging Face Tokens (`hf_...`)
            - AWS Access Key IDs (`AKIA...`)
            """)

    # --------------------------------------------------------------------------
    # Tab 3: AI Architecture & UI Evaluation
    # --------------------------------------------------------------------------
    with tab_arch:
        st.markdown("#### **Stage 3: AI Code & UI Architecture Evaluation**")
        st.caption("Deep inspection of client-side DOM hierarchy, framework modernness, edge infrastructure, and response telemetry.")

        arch_col1, arch_col2 = st.columns(2)
        with arch_col1:
            # Latency Bar Chart
            st.markdown("##### ⏱️ Latency Distribution (TTFB ms)")
            chart_df = pd.DataFrame({
                "Agent": [r.name for r in eval_results],
                "TTFB (ms)": [r.ttfb_ms for r in eval_results]
            }).sort_values("TTFB (ms)", ascending=True)
            st.bar_chart(chart_df.set_index("Agent"), color="#38bdf8")

        with arch_col2:
            # Framework Distribution
            st.markdown("##### 🏗️ Detected Framework Distribution")
            fw_counts = pd.Series([r.detected_framework for r in eval_results]).value_counts()
            st.dataframe(pd.DataFrame({"Framework": fw_counts.index, "Agents": fw_counts.values}), use_container_width=True, hide_index=True)

        st.markdown("---")
        st.markdown("##### 🔍 Per-Agent Architectural Dossier")
        for r in eval_results:
            with st.expander(f"#{r.rank} {r.name} — Overall Score: {r.overall_score:.1f}/10 ({r.detected_framework})"):
                ac1, ac2, ac3 = st.columns(3)
                with ac1:
                    st.metric("UI/UX Design Score", f"{r.ui_score:.1f} / 10")
                    st.caption(f"UI Findings: {r.ui_findings or 'DOM structure checked.'}")
                with ac2:
                    st.metric("Performance & Edge", f"{r.perf_score:.1f} / 10")
                    st.caption(f"TTFB: {r.ttfb_ms:.1f} ms ({r.status_badge})")
                with ac3:
                    st.metric("Tech Stack Score", f"{r.tech_score:.1f} / 10")
                    st.caption(f"Host: {r.edge_platform}")

                st.markdown(f"**Key Architectural Findings**: {r.key_findings}")
                st.markdown(f"**Target URL**: [{r.url}]({r.url}) &bull; **Category**: `{r.category}`")

    # --------------------------------------------------------------------------
    # Tab 4: Export Dossier (Step 5)
    # --------------------------------------------------------------------------
    with tab_export:
        st.markdown("### 📥 Step 5: Export Audit Dossier & Reports")
        st.caption("Generate executive-ready audit deliverables in CSV, Markdown, or PDF format with one click.")

        exp_col1, exp_col2, exp_col3 = st.columns(3)

        # 1. CSV Leaderboard
        with exp_col1:
            st.markdown("#### 📊 CSV Leaderboard")
            st.caption("Standard CSV format containing all scored metrics and findings.")
            df_export = generate_leaderboard_dataframe(eval_results)
            csv_data = df_export.to_csv(index=False).encode("utf-8")
            st.download_button(
                "📥 Download Leaderboard (.CSV)",
                data=csv_data,
                file_name=f"agent_evaluator_leaderboard_{int(time.time())}.csv",
                mime="text/csv",
                type="primary",
                use_container_width=True
            )

        # 2. Markdown Executive Dossier
        with exp_col2:
            st.markdown("#### 📄 Executive Markdown Dossier")
            st.caption("Comprehensive audit report formatted in GitHub-flavored Markdown.")
            md_dossier = generate_markdown_dossier(eval_results)
            st.download_button(
                "📥 Download Audit Dossier (.MD)",
                data=md_dossier.encode("utf-8"),
                file_name=f"agent_evaluator_dossier_{int(time.time())}.md",
                mime="text/markdown",
                type="primary",
                use_container_width=True
            )

        # 3. PDF Audit Report
        with exp_col3:
            st.markdown("#### 📑 Executive PDF Report")
            st.caption("Styled multi-page executive PDF with KPI badges and security alerts.")
            pdf_data = generate_pdf_report(eval_results)
            st.download_button(
                "📥 Download Audit Report (.PDF)",
                data=pdf_data,
                file_name=f"agent_evaluator_report_{int(time.time())}.pdf",
                mime="application/pdf",
                type="primary",
                use_container_width=True
            )

        st.markdown("---")
        st.markdown("#### 👁️ In-App Preview: Executive Markdown Audit Dossier")
        with st.expander("Expand to preview generated executive report", expanded=True):
            st.markdown(md_dossier)

else:
    # Empty State Guidance
    st.markdown("""
    <div style="background: #1e293b; border: 1px dashed #475569; border-radius: 12px; padding: 40px; text-align: center; margin-top: 20px;">
        <div style="font-size: 2.5rem; margin-bottom: 10px;">⚡</div>
        <div style="font-size: 1.25rem; font-weight: 700; color: #f8fafc;">Awaiting Evaluation Execution</div>
        <div style="color: #94a3b8; max-width: 600px; margin: 8px auto 20px auto; font-size: 0.9rem;">
            Upload your agent URLs via CSV/JSON in <b>Step 2</b>, select your evaluation scope in <b>Step 1</b>, or click <b>"Load Preset Benchmark Dataset"</b> to instantly test the suite.
        </div>
        <div style="font-size: 0.8rem; color: #64748b;">
            Zero Hardcoded URLs &bull; High-Resolution TTFB &bull; Regex Secret Detection &bull; AI Code Hierarchy Scoring
        </div>
    </div>
    """, unsafe_allow_html=True)
