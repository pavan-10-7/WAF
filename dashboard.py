"""
dashboard.py - Hybrid AI WAF SOC dashboard (Streamlit).
Run:  streamlit run dashboard.py
All data comes from data_access.py. Nothing here is hard-coded statistics.
"""
from datetime import datetime
from html import escape

import pandas as pd
import plotly.express as px
import streamlit as st

import data_access as da

st.set_page_config(page_title="Hybrid AI WAF", page_icon="🛡️", layout="wide",
                   initial_sidebar_state="expanded")

# ------------------------------------------------------------------ theme
GREEN, CYAN, BLUE = "#00FF9C", "#22D3EE", "#3B82F6"
RED, ORANGE, PURPLE, YELLOW, GREY = "#FF4D5E", "#FF9F43", "#A78BFA", "#FACC15", "#8A9BBE"
ATTACK_COLORS = {"SQL Injection": ORANGE, "XSS": PURPLE, "Path Traversal": YELLOW, "None": GREEN}
PRIORITY_COLORS = {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": YELLOW, "LOW": GREEN}
GOOD = {"ONLINE", "RUNNING", "ACTIVE", "LOADED", "READY", "HEALTHY", "TRAINED", "OK"}
WARN = {"DEGRADED", "WARNING", "TRAINING", "STALE", "LOADING"}

CSS = f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@500;700&display=swap');
html, body, [class*="css"] {{ font-family: 'Inter', sans-serif; }}
.stApp {{ background: radial-gradient(1100px 500px at 85% -10%, #12285655, transparent), #0A1128; }}
[data-testid="stToolbar"], footer, #MainMenu {{ display: none; }}
header[data-testid="stHeader"] {{ background: transparent; }}
.block-container {{ padding-top: 1.2rem; max-width: 1500px; }}
section[data-testid="stSidebar"] {{ background: #070D1F; border-right: 1px solid #1E2D4F; }}
section[data-testid="stSidebar"] div[role="radiogroup"] label {{
  width: 100%; padding: .55rem .8rem; border-radius: 10px; border: 1px solid transparent; margin-bottom: 2px; }}
section[data-testid="stSidebar"] div[role="radiogroup"] label:hover {{ background: #0F1A33; }}
section[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked) {{
  background: linear-gradient(90deg, {GREEN}22, transparent); border-color: {GREEN}55; }}
section[data-testid="stSidebar"] div[role="radiogroup"] label > div:first-child {{ display: none; }}
.brand {{ font-family: 'JetBrains Mono', monospace; font-weight: 700; font-size: 1.25rem; color: {GREEN};
  letter-spacing: .08em; text-shadow: 0 0 14px {GREEN}66; }}
.brand-sub {{ color: {GREY}; font-size: .72rem; letter-spacing: .18em; text-transform: uppercase; }}
.title {{ font-size: 1.85rem; font-weight: 700; color: #E6EDF7; line-height: 1.2; }}
.sub {{ color: {GREY}; font-size: .9rem; margin-bottom: .6rem; }}
.pill {{ display: inline-block; padding: 3px 11px; border-radius: 999px; border: 1px solid; font-size: .74rem;
  font-weight: 600; letter-spacing: .05em; white-space: nowrap; }}
.card {{ background: linear-gradient(160deg, #111C36, #0D1730); border: 1px solid #1E2D4F; border-radius: 14px;
  padding: 1rem 1.2rem; box-shadow: 0 6px 24px #00000055; }}
.kpi {{ background: linear-gradient(160deg, #111C36, #0D1730); border: 1px solid #1E2D4F; border-top: 3px solid var(--accent);
  border-radius: 14px; padding: 1rem 1.2rem; box-shadow: 0 6px 24px #00000055; }}
.kpi-label {{ color: {GREY}; font-size: .74rem; letter-spacing: .12em; text-transform: uppercase; }}
.kpi-value {{ font-family: 'JetBrains Mono', monospace; font-size: 2.1rem; font-weight: 700; color: var(--accent); }}
.kpi-sub {{ color: {GREY}; font-size: .78rem; }}
.sec {{ font-weight: 600; color: #E6EDF7; margin: .4rem 0 .5rem; font-size: 1rem; }}
.row {{ display: flex; justify-content: space-between; align-items: center; padding: .55rem 0; border-bottom: 1px solid #1E2D4F; }}
.row:last-child {{ border-bottom: none; }}
.row span:first-child {{ color: {GREY}; font-size: .85rem; }}
.empty {{ text-align: center; color: {GREY}; padding: 2.2rem 1rem; border: 1px dashed #1E2D4F; border-radius: 14px; }}
div[data-testid="stDataFrame"] {{ border: 1px solid #1E2D4F; border-radius: 12px; overflow: hidden; }}
.stButton > button {{ background: transparent; color: {GREEN}; border: 1px solid {GREEN}88; border-radius: 10px; font-weight: 600; }}
.stButton > button:hover {{ background: {GREEN}18; border-color: {GREEN}; color: {GREEN}; }}
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)


# ------------------------------------------------------------------ helpers
def pill(text, color):
    return (f'<span class="pill" style="color:{color};border-color:{color}66;background:{color}1A">'
            f'● {escape(str(text))}</span>')


def status_color(value):
    if value is None:
        return GREY
    v = str(value).upper()
    return GREEN if v in GOOD else ORANGE if v in WARN else RED


def status_pill(value):
    return pill(value if value else "UNAVAILABLE", status_color(value))


def sval(status, key):
    v = status.get(key)
    return str(v).upper() if v not in (None, "") else None


def kpi(label, value, sub, color):
    return (f'<div class="kpi" style="--accent:{color}"><div class="kpi-label">{label}</div>'
            f'<div class="kpi-value">{value}</div><div class="kpi-sub">{sub}</div></div>')


def empty(msg):
    st.markdown(f'<div class="empty">📭<br>{msg}</div>', unsafe_allow_html=True)


def fmt_pct(v):
    return "N/A" if v is None else f"{v:.1f}%"


def style_fig(fig, height=340):
    fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      height=height, margin=dict(l=10, r=10, t=30, b=10), font=dict(color="#C9D6EE"),
                      legend=dict(orientation="h", y=-0.15))
    fig.update_xaxes(gridcolor="#1E2D4F")
    fig.update_yaxes(gridcolor="#1E2D4F")
    return fig


def css_verdict(v):
    return {"BLOCK": f"color:{RED};font-weight:700", "ALLOW": f"color:{GREEN};font-weight:700"}.get(v, "")


def css_attack(v):
    c = ATTACK_COLORS.get(v)
    return f"color:{c};font-weight:600" if c and v != "None" else f"color:{GREY}"


def css_priority(v):
    c = PRIORITY_COLORS.get(str(v).upper())
    return f"color:{c};font-weight:700;background:{c}1A" if c else ""


def smap(sty, fn, cols):
    cols = [c for c in cols if c in sty.data.columns]
    if not cols:
        return sty
    return (getattr(sty, "map", None) or sty.applymap)(fn, subset=cols)


EVENT_LABELS = {"timestamp": "Timestamp", "source_ip": "Source IP", "method": "Method", "endpoint": "Endpoint",
                "attack_type": "Attack Type", "verdict": "Verdict", "score": "Detection Score"}


def events_table(df, height=420):
    v = df[da.EVENT_COLUMNS].rename(columns=EVENT_LABELS).copy()
    v["Timestamp"] = v["Timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    sty = v.style.format({"Detection Score": "{:.2f}"}, na_rep="—")
    sty = smap(sty, css_verdict, ["Verdict"])
    sty = smap(sty, css_attack, ["Attack Type"])
    st.dataframe(sty, hide_index=True, height=height)


def last_updated(status, events):
    if status.get("last_updated"):
        return str(status["last_updated"])
    if not events.empty and events["timestamp"].notna().any():
        return events["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S") + " (latest event)"
    return "Unavailable"


def header(title, subtitle, status, events, brand=False):
    left, right = st.columns([3, 2])
    if brand:
        left.markdown('<div class="brand" style="font-size:1.9rem">🛡️ HYBRID AI WAF</div>'
                      f'<div class="brand-sub">{subtitle}</div>', unsafe_allow_html=True)
    else:
        left.markdown(f'<div class="title">{title}</div><div class="sub">{subtitle}</div>', unsafe_allow_html=True)
    right.markdown(f'<div style="text-align:right">System {status_pill(sval(status, "waf_status"))}<br>'
                   f'<span class="sub">Last updated: {escape(last_updated(status, events))}</span></div>',
                   unsafe_allow_html=True)


def data_notices(emeta, smeta):
    if emeta.get("is_sample"):
        st.info("Showing bundled **SAMPLE data** for UI preview only. Put the real `events.jsonl` in `./data/` "
                "or set `WAF_DATA_DIR` to use live WAF data.")
    for m in (emeta, smeta):
        if m.get("error"):
            st.warning(m["error"])
    if emeta.get("skipped"):
        st.warning(f"{emeta['skipped']} malformed line(s) in the event log were skipped.")


# ------------------------------------------------------------------ pages
def page_overview(events, status, emeta, smeta):
    header("", "Security Operations Center", status, events, brand=True)
    data_notices(emeta, smeta)
    m = da.compute_metrics(events)
    c = st.columns(4)
    c[0].markdown(kpi("Total Requests", f"{m['total']:,}", "events in log", CYAN), unsafe_allow_html=True)
    c[1].markdown(kpi("Allowed Requests", f"{m['allowed']:,}", fmt_pct(100 * m['allowed'] / m['total'] if m['total'] else None) + " of traffic", GREEN), unsafe_allow_html=True)
    c[2].markdown(kpi("Blocked Requests", f"{m['blocked']:,}", fmt_pct(m['block_rate']) + " of traffic", RED), unsafe_allow_html=True)
    c[3].markdown(kpi("Attack Detection Rate", fmt_pct(m['detection_rate']), "attack events ÷ total requests", ORANGE), unsafe_allow_html=True)
    st.write("")
    if events.empty:
        empty("No security events yet. Charts appear once the WAF writes events.")
    else:
        a, b = st.columns(2)
        atk = events[events["attack_type"] != "None"]["attack_type"].value_counts().reset_index()
        atk.columns = ["Attack Type", "Count"]
        with a:
            st.markdown('<div class="sec">Attack distribution</div>', unsafe_allow_html=True)
            if atk.empty:
                empty("No attacks detected.")
            else:
                fig = px.pie(atk, names="Attack Type", values="Count", hole=.6, color="Attack Type",
                             color_discrete_map=ATTACK_COLORS)
                st.plotly_chart(style_fig(fig), key="ov_dist")
        with b:
            st.markdown('<div class="sec">Allowed vs blocked traffic</div>', unsafe_allow_html=True)
            vb = events["verdict"].value_counts().reset_index()
            vb.columns = ["Verdict", "Count"]
            fig = px.bar(vb, x="Verdict", y="Count", color="Verdict",
                         color_discrete_map={"ALLOW": GREEN, "BLOCK": RED})
            st.plotly_chart(style_fig(fig), key="ov_vb")
    left, right = st.columns([3, 2])
    with left:
        st.markdown('<div class="sec">Recent security events</div>', unsafe_allow_html=True)
        if events.empty:
            empty("Nothing to show yet.")
        else:
            events_table(events.head(8), height=330)
    with right:
        st.markdown('<div class="sec">System health</div>', unsafe_allow_html=True)
        rows = [("WAF status", sval(status, "waf_status")), ("Detection engine", sval(status, "detection_engine")),
                ("ML model", sval(status, "ml_model"))]
        rows += [(k.replace("_", " ").title(), str(v).upper()) for k, v in (status.get("components") or {}).items()]
        html = "".join(f'<div class="row"><span>{escape(k)}</span>{status_pill(v)}</div>' for k, v in rows)
        st.markdown(f'<div class="card">{html}</div>', unsafe_allow_html=True)


def page_live(status, emeta, smeta):
    events, _ = da.load_events()
    header("Live Traffic Monitoring", "Real-time request log · newest first", status, events)
    data_notices(emeta, smeta)
    f = st.columns([2.4, 1.3, 1.5, 1.4, .9, 1.1])
    q = f[0].text_input("Search", placeholder="🔍 Search IP, endpoint, attack…", label_visibility="collapsed")
    verdicts = f[1].multiselect("Verdict", ["ALLOW", "BLOCK"], placeholder="Verdict")
    attacks = f[2].multiselect("Attack", ["SQL Injection", "XSS", "Path Traversal", "None"], placeholder="Attack type")
    sort = f[3].selectbox("Sort", ["Newest first", "Oldest first", "Highest score", "Lowest score", "Source IP"],
                          label_visibility="collapsed")
    auto = f[4].toggle("Auto", value=True, help="Automatically reload the event log")
    every = f[5].selectbox("Every", [5, 10, 30], format_func=lambda s: f"{s}s", label_visibility="collapsed")

    @st.fragment(run_every=every if auto else None)
    def table():
        df, meta = da.load_events()
        if df.empty:
            empty(meta.get("error") or "No events logged yet.")
            return
        view = df
        if q:
            hay = view[["source_ip", "method", "endpoint", "attack_type", "verdict"]].astype(str).agg(" ".join, axis=1)
            view = view[hay.str.lower().str.contains(q.lower(), regex=False)]
        if verdicts:
            view = view[view["verdict"].isin(verdicts)]
        if attacks:
            view = view[view["attack_type"].isin(attacks)]
        col, asc = {"Newest first": ("timestamp", False), "Oldest first": ("timestamp", True),
                    "Highest score": ("score", False), "Lowest score": ("score", True),
                    "Source IP": ("source_ip", True)}[sort]
        view = view.sort_values(col, ascending=asc, na_position="last")
        st.caption(f"Showing {len(view):,} of {len(df):,} events · refreshed {datetime.now():%H:%M:%S}")
        if view.empty:
            empty("No events match the current filters.")
        else:
            events_table(view, height=560)

    table()


def page_analytics(events, status, emeta, smeta):
    header("Attack Analytics", "Detections, trends and distribution", status, events)
    data_notices(emeta, smeta)
    if events.empty:
        empty("No events available, so there are no statistics to display.")
        return
    attacks = events[events["attack_type"] != "None"]
    counts = attacks["attack_type"].value_counts()
    total_att = int(counts.sum())
    cols = st.columns(3)
    for col, (name, color) in zip(cols, [("SQL Injection", ORANGE), ("XSS", PURPLE), ("Path Traversal", YELLOW)]):
        n = int(counts.get(name, 0))
        col.markdown(kpi(name, f"{n:,}", f"{fmt_pct(n / total_att * 100 if total_att else None)} of attacks", color),
                     unsafe_allow_html=True)
    st.write("")
    ts = events.dropna(subset=["timestamp"])
    span = (ts["timestamp"].max() - ts["timestamp"].min()) if not ts.empty else pd.Timedelta(0)
    freq = "1min" if span < pd.Timedelta(hours=2) else "1h" if span < pd.Timedelta(days=3) else "1D"
    a, b = st.columns(2)
    with a:
        st.markdown(f'<div class="sec">Attack frequency over time ({freq} buckets)</div>', unsafe_allow_html=True)
        t = ts[ts["attack_type"] != "None"]
        if t.empty:
            empty("No attacks detected yet.")
        else:
            g = t.groupby([pd.Grouper(key="timestamp", freq=freq), "attack_type"]).size().reset_index(name="Count")
            fig = px.line(g, x="timestamp", y="Count", color="attack_type", markers=True,
                          color_discrete_map=ATTACK_COLORS, labels={"timestamp": "", "attack_type": "Attack"})
            st.plotly_chart(style_fig(fig), key="an_freq")
    with b:
        st.markdown('<div class="sec">Allowed vs blocked over time</div>', unsafe_allow_html=True)
        if ts.empty:
            empty("No timestamps available.")
        else:
            g = ts.groupby([pd.Grouper(key="timestamp", freq=freq), "verdict"]).size().reset_index(name="Count")
            fig = px.bar(g, x="timestamp", y="Count", color="verdict", barmode="stack",
                         color_discrete_map={"ALLOW": GREEN, "BLOCK": RED}, labels={"timestamp": "", "verdict": "Verdict"})
            st.plotly_chart(style_fig(fig), key="an_vb")
    c, d = st.columns(2)
    with c:
        st.markdown('<div class="sec">Attack distribution (%)</div>', unsafe_allow_html=True)
        if attacks.empty:
            empty("No attacks detected yet.")
        else:
            df = counts.reset_index()
            df.columns = ["Attack Type", "Count"]
            fig = px.pie(df, names="Attack Type", values="Count", hole=.45, color="Attack Type",
                         color_discrete_map=ATTACK_COLORS)
            fig.update_traces(textinfo="percent+label")
            st.plotly_chart(style_fig(fig), key="an_pie")
    with d:
        st.markdown('<div class="sec">Most targeted endpoints</div>', unsafe_allow_html=True)
        if attacks.empty:
            empty("No attacks detected yet.")
        else:
            df = attacks.groupby(["endpoint", "attack_type"]).size().reset_index(name="Count")
            fig = px.bar(df, x="Count", y="endpoint", color="attack_type", orientation="h",
                         color_discrete_map=ATTACK_COLORS, labels={"endpoint": "", "attack_type": "Attack"})
            fig.update_yaxes(categoryorder="total ascending")
            st.plotly_chart(style_fig(fig), key="an_ep")


def page_triage(events, status, emeta, smeta):
    header("Vulnerability Triage", "Risk-based prioritisation and virtual patches", status, events)
    df, tmeta = da.load_triage()
    data_notices(tmeta, smeta)
    if df.empty:
        empty("No triage results available yet.")
        return
    counts = df["priority"].value_counts()
    c = st.columns(4)
    for col, p in zip(c, ["CRITICAL", "HIGH", "MEDIUM", "LOW"]):
        col.markdown(kpi(p.title(), int(counts.get(p, 0)), "vulnerabilities", PRIORITY_COLORS[p]), unsafe_allow_html=True)
    st.write("")
    f = st.columns([2.5, 2, 1.6])
    q = f[0].text_input("Search", placeholder="🔍 Search ID, title, endpoint…", label_visibility="collapsed", key="tq")
    prio = f[1].multiselect("Priority", list(PRIORITY_COLORS), placeholder="Priority filter")
    sort = f[2].selectbox("Sort", ["Risk score ↓", "Risk score ↑", "CVSS ↓", "Observed attacks ↓"], label_visibility="collapsed")
    view = df
    if q:
        hay = view[["vuln_id", "title", "endpoint", "attack_type"]].astype(str).agg(" ".join, axis=1)
        view = view[hay.str.lower().str.contains(q.lower(), regex=False)]
    if prio:
        view = view[view["priority"].isin(prio)]
    col, asc = {"Risk score ↓": ("risk_score", False), "Risk score ↑": ("risk_score", True),
                "CVSS ↓": ("cvss", False), "Observed attacks ↓": ("observed_attacks", False)}[sort]
    view = view.sort_values(col, ascending=asc, na_position="last")
    if view.empty:
        empty("No vulnerabilities match the current filters.")
        return
    labels = {"vuln_id": "ID", "title": "Title", "endpoint": "Endpoint", "attack_type": "Attack Type", "cvss": "CVSS",
              "asset_criticality": "Asset Criticality", "observed_attacks": "Observed Attacks",
              "risk_score": "Risk Score", "priority": "Priority", "virtual_patch": "Suggested Virtual Patch"}
    sty = view.rename(columns=labels).style.format({"CVSS": "{:.1f}", "Risk Score": "{:.1f}", "Observed Attacks": "{:.0f}"}, na_rep="—")
    sty = smap(sty, css_priority, ["Priority"])
    sty = smap(sty, css_attack, ["Attack Type"])
    st.dataframe(sty, hide_index=True, height=340)
    st.markdown('<div class="sec">Vulnerability details</div>', unsafe_allow_html=True)
    pick = st.selectbox("Select vulnerability", view["vuln_id"].tolist(), label_visibility="collapsed")
    r = view[view["vuln_id"] == pick].iloc[0]
    left, right = st.columns([1, 1.4])
    num = lambda x, f="{:.1f}": "—" if pd.isna(x) else f.format(x)
    rows = [("Title", escape(str(r["title"]))), ("Endpoint", escape(str(r["endpoint"]))),
            ("Attack type", escape(str(r["attack_type"]))), ("CVSS", num(r["cvss"])),
            ("Asset criticality", escape(str(r["asset_criticality"]))),
            ("Observed attacks", num(r["observed_attacks"], "{:.0f}")), ("Risk score", num(r["risk_score"])),
            ("Priority", pill(r["priority"], PRIORITY_COLORS.get(r["priority"], GREY)))]
    left.markdown('<div class="card">' + "".join(f'<div class="row"><span>{k}</span><span>{v}</span></div>' for k, v in rows)
                  + '</div>', unsafe_allow_html=True)
    right.markdown("**Suggested virtual patch**")
    right.code("" if pd.isna(r["virtual_patch"]) else str(r["virtual_patch"]), language="text")


def page_model(events, status, emeta, smeta):
    header("Model Management", "Machine-learning detection engine", status, events)
    data_notices(emeta, smeta)
    model = status.get("model") or {}
    algo = model.get("algorithm", "Logistic Regression")
    feat = model.get("feature_extraction", "TF-IDF Character N-grams")
    c = st.columns(3)
    c[0].markdown(kpi("ML Model", sval(status, "ml_model") or "UNAVAILABLE", "loaded in WAF", status_color(sval(status, "ml_model"))), unsafe_allow_html=True)
    c[1].markdown(kpi("Detection Engine", sval(status, "detection_engine") or "UNAVAILABLE", "runtime state", status_color(sval(status, "detection_engine"))), unsafe_allow_html=True)
    ts = str(model.get("training_status", "")).upper() or None
    c[2].markdown(kpi("Training Status", ts or "UNAVAILABLE", "last known", status_color(ts)), unsafe_allow_html=True)
    st.write("")
    a, b = st.columns(2)
    with a:
        st.markdown('<div class="sec">Model information</div>', unsafe_allow_html=True)
        info = {"Algorithm": algo, "Feature extraction": feat}
        info.update({k.replace("_", " ").title(): v for k, v in model.items() if k not in ("algorithm", "feature_extraction", "training_status")})
        html = "".join(f'<div class="row"><span>{escape(k)}</span><span>{escape(str(v))}</span></div>' for k, v in info.items())
        st.markdown(f'<div class="card">{html}</div>', unsafe_allow_html=True)
    with b:
        st.markdown('<div class="sec">Retrain model</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="card">Calls the backend retraining interface '
                    f'<code>{escape(da.retrain_entrypoint())}</code>. No retraining is simulated.</div>', unsafe_allow_html=True)
        st.write("")
        if st.button("⟳ Retrain Model"):
            with st.spinner("Retraining via backend…"):
                st.session_state["retrain"] = da.run_retrain()
        res = st.session_state.get("retrain")
        if res:
            (st.success if res["ok"] else st.error)(res["message"])
            if res.get("result") is not None:
                st.json(res["result"] if isinstance(res["result"], (dict, list)) else str(res["result"]))


# ------------------------------------------------------------------ main
NAV = {"Overview": "◉", "Live Traffic": "⚡", "Attack Analytics": "📈", "Vulnerability Triage": "🐞", "Model Management": "🧠"}

events, emeta = da.load_events()
status, smeta = da.load_status()

with st.sidebar:
    st.markdown('<div class="brand">🛡️ HYBRID AI WAF</div><div class="brand-sub">Threat defence platform</div>', unsafe_allow_html=True)
    st.write("")
    page = st.radio("Navigation", list(NAV), format_func=lambda p: f"{NAV[p]}  {p}", label_visibility="collapsed", key="nav")
    st.divider()
    st.markdown('<div class="brand-sub">System information</div>', unsafe_allow_html=True)
    info = [("WAF Status", sval(status, "waf_status")), ("Detection Engine", sval(status, "detection_engine")),
            ("ML Model", sval(status, "ml_model"))]
    st.markdown("".join(f'<div class="row"><span>{k}</span>{status_pill(v)}</div>' for k, v in info), unsafe_allow_html=True)
    st.caption(f"Last updated: {last_updated(status, events)}")
    if st.button("⟳ Refresh data"):
        st.rerun()

if page == "Overview":
    page_overview(events, status, emeta, smeta)
elif page == "Live Traffic":
    page_live(status, emeta, smeta)
elif page == "Attack Analytics":
    page_analytics(events, status, emeta, smeta)
elif page == "Vulnerability Triage":
    page_triage(events, status, emeta, smeta)
else:
    page_model(events, status, emeta, smeta)
