#!/usr/bin/env python3
import datetime
import html

SENSITIVE_HINTS = ("iam:", "sts:", ":delete", ":terminate", ":create",
                   ":put", ":attach", ":passrole", "*")

def _is_sensitive(action):
    a = action.lower()
    return any(h in a for h in (":delete", ":terminate", "iam:", ":passrole",
                                ":createuser", ":attach")) or action.endswith("*")

def _severity(pct):
    if pct >= 80:
        return "critique", "#b3261e"
    if pct >= 50:
        return "élevé", "#e8710a"
    if pct >= 20:
        return "modéré", "#f9ab00"
    return "faible", "#1e8e3e"

def generate(report, roles, meta=None):
    """report: dict produit par le script principal. Retourne une chaîne HTML."""
    meta = meta or {}
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    n_roles = len(roles)

    cards = []
    for r in roles:
        d = report[r]
        pct = d["gap_ratio_pct"]
        sev_label, sev_color = _severity(pct)
        used_chips = "".join(
            f'<span class="chip used">{html.escape(u)}</span>' for u in d["used_list"]
        ) or '<span class="muted">aucune action utilisée observée</span>'

        source_blocks = []
        for src, info in d["gap_by_source"].items():
            by_wc = {}
            literals = []
            for item in info["actions"]:
                if item["via_wildcard"]:
                    by_wc.setdefault(item["wildcard"], []).append(item["action"])
                else:
                    literals.append(item["action"])

            sub_blocks = []
            for wc, acts in by_wc.items():
                chips = "".join(
                    f'<span class="chip gap{" sens" if _is_sensitive(a) else ""}">'
                    f'{html.escape(a)}</span>' for a in sorted(acts))
                sub_blocks.append(
                    f'<div class="wc">accordé via le wildcard '
                    f'<code>{html.escape(wc)}</code> ({len(acts)}) :</div>'
                    f'<div class="chips">{chips}</div>')
            if literals:
                chips = "".join(
                    f'<span class="chip gap{" sens" if _is_sensitive(a) else ""}">'
                    f'{html.escape(a)}</span>' for a in sorted(literals))
                sub_blocks.append(
                    f'<div class="wc">accordées littéralement '
                    f'({len(literals)}) :</div>'
                    f'<div class="chips">{chips}</div>')

            source_blocks.append(f"""
              <div class="source">
                <div class="source-head">
                  <span class="count">{info['count']} inutilisée(s)</span>
                </div>
                {''.join(sub_blocks)}
              </div>""")

        ref_items = "".join(
            f'<div class="ref-item"><span class="loc">{html.escape(src)}</span></div>'
            for src in d["gap_by_source"].keys()
        ) or '<span class="muted">aucune référence localisée dans le .tf</span>'

        exhaustive_note = "" if d["exhaustive"] else (
            '<div class="warn">Wildcards dépliés sur la base de l\'usage observé '
            '(policyuniverse absent) : le gap peut être sous-estimé.</div>')

        cards.append(f"""
        <section class="card">
          <header class="card-head">
            <h2>{html.escape(r)}</h2>
            <span class="badge" style="background:{sev_color}">{sev_label} · {pct}%</span>
          </header>
          <div class="gauge"><div class="gauge-fill" style="width:{pct}%;background:{sev_color}"></div></div>
          <div class="stats">
            <div><span class="num">{d['granted_actions']}</span><span class="lbl">accordées</span></div>
            <div><span class="num">{d['used_actions']}</span><span class="lbl">utilisées</span></div>
            <div><span class="num">{d['gap_actions']}</span><span class="lbl">inutilisées</span></div>
          </div>
          {exhaustive_note}
          <div class="section-title">reference du role en sur-privilège</div>
          {ref_items}
          <div class="section-title">Utilise réellement</div>
          <div class="chips">{used_chips}</div>
          <div class="section-title">Actions inutilisées (sur-privilège)</div>
          {''.join(source_blocks)}
        </section>""")

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rapport d'analyse</title>
<style>
  :root {{
    --bg:#0f1115; --panel:#171a21; --line:#262b35; --txt:#e6e8ec;
    --muted:#8a929e; --used:#1e8e3e; --gap:#3a3f4b; --sens:#b3261e;
    --mono:'SFMono-Regular',Consolas,'Liberation Mono',monospace;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--txt);
    font-family:-apple-system,Segoe UI,Roboto,sans-serif; line-height:1.5; }}
  .wrap {{ max-width:980px; margin:0 auto; padding:40px 24px 80px; }}
  h1 {{ font-size:1.7rem; margin:0 0 4px; letter-spacing:-.02em; }}
  .sub {{ color:var(--muted); font-size:.9rem; margin-bottom:28px; }}
  .overview {{ display:flex; gap:24px; padding:20px 24px; background:var(--panel);
    border:1px solid var(--line); border-radius:12px; margin-bottom:32px; }}
  .overview div {{ display:flex; flex-direction:column; }}
  .overview .num {{ font-size:1.8rem; font-weight:700; }}
  .overview .lbl {{ color:var(--muted); font-size:.8rem; text-transform:uppercase; letter-spacing:.05em; }}
  .card {{ background:var(--panel); border:1px solid var(--line);
    border-radius:12px; padding:24px; margin-bottom:24px; }}
  .card-head {{ display:flex; align-items:center; justify-content:space-between; }}
  .card-head h2 {{ margin:0; font-size:1.25rem; font-family:var(--mono); }}
  .badge {{ color:#fff; font-size:.8rem; font-weight:600; padding:4px 12px;
    border-radius:999px; }}
  .gauge {{ height:8px; background:var(--gap); border-radius:999px; overflow:hidden;
    margin:16px 0; }}
  .gauge-fill {{ height:100%; }}
  .stats {{ display:flex; gap:32px; margin-bottom:8px; }}
  .stats .num {{ font-size:1.4rem; font-weight:700; }}
  .stats .lbl {{ color:var(--muted); font-size:.78rem; text-transform:uppercase;
    letter-spacing:.05em; display:block; }}
  .section-title {{ margin:20px 0 8px; font-size:.78rem; text-transform:uppercase;
    letter-spacing:.06em; color:var(--muted); border-top:1px solid var(--line);
    padding-top:16px; }}
  .chips {{ display:flex; flex-wrap:wrap; gap:6px; }}
  .chip {{ font-family:var(--mono); font-size:.78rem; padding:3px 8px;
    border-radius:6px; background:var(--gap); }}
  .chip.used {{ background:rgba(30,142,62,.18); color:#7ee2a0;
    border:1px solid rgba(30,142,62,.4); }}
  .chip.gap {{ background:#20242d; color:#c3c9d2; border:1px solid var(--line); }}
  .chip.gap.sens {{ background:rgba(179,38,30,.15); color:#ff8a80;
    border:1px solid rgba(179,38,30,.5); }}
  .source {{ margin:12px 0; padding:14px 16px; background:#12151b;
    border:1px solid var(--line); border-radius:10px; }}
  .source-head {{ display:flex; justify-content:space-between; align-items:baseline;
    margin-bottom:10px; gap:12px; flex-wrap:wrap; }}
  .loc {{ font-family:var(--mono); font-size:.82rem; color:#9ec5ff; }}
  .ref-item {{ padding:10px 14px; background:#12151b; border:1px solid var(--line);
    border-radius:10px; margin:6px 0; }}
  .count {{ font-size:.78rem; color:var(--muted); white-space:nowrap; }}
  .wc {{ font-size:.8rem; color:var(--muted); margin-bottom:10px; }}
  .wc code, .loc code {{ font-family:var(--mono); }}
  .warn {{ background:rgba(249,171,0,.12); border:1px solid rgba(249,171,0,.4);
    color:#ffd666; font-size:.82rem; padding:8px 12px; border-radius:8px; margin:12px 0; }}
  .muted {{ color:var(--muted); }}
  code {{ font-family:var(--mono); }}
  footer {{ color:var(--muted); font-size:.8rem; margin-top:40px;
    border-top:1px solid var(--line); padding-top:16px; }}
</style>
</head>
<body>
  <div class="wrap">
    <h1>Rapport d'analyse de politique de moindre privilège</h1>
    <div class="sub">Généré le {now}
      {("· région " + html.escape(meta.get("region",""))) if meta.get("region") else ""}
      · une permission « sensible » est
      <span style="color:#ff8a80">surlignée en rouge</span>.</div>

    <div class="overview">
      <div><span class="num">{n_roles}</span><span class="lbl">rôles analysés</span></div>
    </div>

    {''.join(cards)}
  </div>
</body>
</html>"""