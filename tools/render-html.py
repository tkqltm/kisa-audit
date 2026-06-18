#!/usr/bin/env python3
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
"""KISA Audit — report.json → report.html 변환기.

사용:
    python3 tools/render-html.py <report.json> [-o <out.html>]

단일 자체 완결 HTML 파일 (CSS/JS inline, 외부 의존성 없음).
Python 3.6+ 호환 (Rocky 8 platform-python 대응).
"""

import argparse
import difflib
import html
import json
import os
import sys
from datetime import datetime

# Import remediation guide
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from remediation_guide import REMEDIATION_GUIDE


SEVERITY_RANK = {"상": 0, "중": 1, "하": 2}


def _esc(s):
    if s is None:
        return ""
    return html.escape(str(s), quote=True)


def _detail_html(detail):
    """결과 사유 렌더링: 줄바꿈(\\n)을 <br> 로 보존하고 첫 줄(verdict)을 강조.
    '조치:' 로 시작하는 줄은 들여쓰기해 가독성 향상."""
    if not detail:
        return ""
    lines = [ln.rstrip() for ln in str(detail).split("\n")]
    lines = [ln for ln in lines if ln != ""]
    if not lines:
        return ""
    out = []
    for i, ln in enumerate(lines):
        esc = _esc(ln)
        if i == 0:
            out.append(f'<strong class="kd-verdict">{esc}</strong>')
        elif ln.lstrip().startswith(("조치:", "조치 ", "→", "- ")):
            out.append(f'<span class="kd-action-line">{esc}</span>')
        else:
            out.append(esc)
    return "<br>".join(out)


# 조치와 무관한 stat 메타데이터/타임스탬프 노이즈 라인 (조치 부수효과로 바뀌어 의미 없음)
_DIFF_NOISE = (
    '접근:', '수정:', '변경:', '생성:', '크기:', '블록:', '입출력', '장치:', '아이노드:', '링크:',
    '컨텍스트:', '파일:',
    'Access:', 'Modify:', 'Change:', 'Birth:', 'Size:', 'Blocks:', 'IO Block', 'Device:',
    'Inode:', 'Links:', 'Context:', 'File:',
)

def _diff_noise(line):
    t = line.strip()
    return any(t.startswith(p) for p in _DIFF_NOISE)

def _diff_html(before, after):
    """조치 전→후 '실제 바뀐 값'만 색상 표시 (제거=빨강 -, 추가=녹색 +).
    변경 없는 줄(context)과 조치 무관 노이즈(타임스탬프·stat 메타)는 제외해 핵심만 노출."""
    bl = (before or "").splitlines()
    al = (after or "").splitlines()
    sm = difflib.SequenceMatcher(None, bl, al)
    out = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == 'equal':
            continue                                   # 변경 없는 줄은 표시 안 함
        for ln in bl[i1:i2]:
            if ln.strip() and not _diff_noise(ln):
                out.append(f'<span class="dl del">- {_esc(ln.strip())}</span>')
        for ln in al[j1:j2]:
            if ln.strip() and not _diff_noise(ln):
                out.append(f'<span class="dl add">+ {_esc(ln.strip())}</span>')
    if not out:
        return '<pre class="diffbox"><span class="dl ctx">(조치 변경 없음 — 현재 상태 유지)</span></pre>'
    return '<pre class="diffbox">' + "\n".join(out) + '</pre>'


def _fmt_time(iso):
    if not iso:
        return ""
    try:
        dt = datetime.fromisoformat(iso)
        return dt.strftime("%Y-%m-%d %H:%M:%S %Z").strip()
    except Exception:
        return iso


def _result_chip(value):
    cls = {
        "양호": "chip chip-good",
        "취약": "chip chip-bad",
        "판정불가": "chip chip-warn",
        "": "chip chip-na",
    }.get(value, "chip chip-na")
    return f'<span class="{cls}">{_esc(value or "-")}</span>'


def _action_chip(value):
    label = value or "-"
    cls = {
        "applied": "chip chip-applied",
        "skipped": "chip chip-skipped",
        "manual": "chip chip-manual",
        "failed": "chip chip-failed",
        "not_applicable": "chip chip-na",
        "checked": "chip chip-checked",
    }.get(value, "chip chip-na")
    return f'<span class="{cls}">{_esc(label)}</span>'


def _severity_chip(value):
    cls = {
        "상": "chip sev-h",
        "중": "chip sev-m",
        "하": "chip sev-l",
    }.get(value, "chip chip-na")
    return f'<span class="{cls}">{_esc(value or "-")}</span>'


def _stat_block(title, c, mode):
    rows = [
        ("점검 항목", c["total"]),
        ("[점검 전] 양호", c["before_good"]),
        ("[점검 전] 취약", c["before_bad"]),
    ]
    if mode == "apply":
        rows += [
            ("[조치 후] 양호", c["after_good"]),
            ("[조치 후] 취약", c["after_bad"]),
            ("자동 조치 완료(applied)", c["applied"]),
            ("이미 양호(skipped)", c["skipped"]),
            ("수동 조치 필요(manual)", c["manual"]),
            ("조치 실패(failed)", c["failed"]),
            ("해당없음(n/a)", c["not_applicable"]),
        ]
    body = "".join(f"<tr><th>{_esc(k)}</th><td>{int(v)}</td></tr>" for k, v in rows)
    return f"""
    <section class="card">
      <h3>{_esc(title)}</h3>
      <table class="kv"><tbody>{body}</tbody></table>
    </section>
    """


def _evidence_block(ev):
    """evidence: dict (예: {"before": "<file content>", "after": "<file content>", "command": "..."}) — handler 가 채우면 표시."""
    if not ev:
        return ""
    if isinstance(ev, str):
        return f'<pre class="evidence">{_esc(ev)}</pre>'
    parts = []
    if isinstance(ev, dict):
        for label, content in ev.items():
            if content is None:
                continue
            if isinstance(content, (dict, list)):
                content = json.dumps(content, ensure_ascii=False, indent=2)
            parts.append(
                f'<div class="ev-block"><div class="ev-label">{_esc(label)}</div>'
                f'<pre class="evidence">{_esc(content)}</pre></div>'
            )
    return "\n".join(parts)


def _kisa_detail_table(it, mode):
    """KISA 가이드 PDF 와 동일한 단일 표 형식의 상세 표 렌더러.
    표 행 클릭 시 인라인 expand 영역에 삽입됨."""
    code = it.get("code", "")
    sev = it.get("severity", "")
    title = it.get("title", "")
    cat = it.get("category", "")
    before = it.get("before", "") or ""
    after = it.get("after", "") or ""
    action = it.get("action", "") or ""
    detail = it.get("detail", "") or ""

    purpose = it.get("purpose") or ""
    threat = it.get("threat") or ""
    crit_good = it.get("criterion_good") or ""
    crit_bad = it.get("criterion_bad") or ""
    method = it.get("method") or []
    action_method = REMEDIATION_GUIDE.get(code, it.get("action_method") or "")
    action_impact = it.get("action_impact") or ""
    references = it.get("references") or []

    if isinstance(method, str):
        method = [method]

    evidence = it.get("evidence") or {}
    if not isinstance(evidence, dict):
        evidence = {}
    ev_before = evidence.get("before") or evidence.get("current") or ""
    ev_after = evidence.get("after") or ""

    is_apply = mode == "apply"

    rows = []
    rows.append(
        f'<tr class="kd-head"><td class="kd-code-cell" rowspan="2">'
        f'<div class="kd-code mono">{_esc(code)}</div>'
        f'<div class="kd-sev">{_severity_chip(sev)}</div></td>'
        f'<td class="kd-cat">UNIX &gt; {_esc(cat)}</td></tr>'
        f'<tr class="kd-head"><td class="kd-name">{_esc(title)}</td></tr>'
    )

    # 개요
    rows.append('<tr class="kd-grp"><td colspan="2">개요</td></tr>')
    if method:
        method_inner = "<br>".join(_esc(m) for m in method)
        rows.append(f'<tr><th>점검 내용</th><td>{method_inner}</td></tr>')
    if purpose:
        rows.append(f'<tr><th>점검 목적</th><td>{_esc(purpose)}</td></tr>')
    if threat:
        rows.append(f'<tr><th>보안 위협</th><td>{_esc(threat)}</td></tr>')

    # 점검 대상 및 판단 기준
    if crit_good or crit_bad or action_method or action_impact:
        rows.append('<tr class="kd-grp"><td colspan="2">점검 대상 및 판단 기준</td></tr>')
        rows.append('<tr><th>대상</th><td>Rocky Linux 8 / 9 / 10 (KISA 가이드 UNIX 항목)</td></tr>')
        crit_html = []
        if crit_good:
            crit_html.append(f'<span class="chip chip-good">양호</span> {_esc(crit_good)}')
        if crit_bad:
            crit_html.append(f'<span class="chip chip-bad">취약</span> {_esc(crit_bad)}')
        if crit_html:
            rows.append(f'<tr><th>판단 기준</th><td>{"<br>".join(crit_html)}</td></tr>')
        if action_method:
            rows.append(f'<tr><th>조치 방법</th><td style="white-space:pre-wrap">{_esc(action_method)}</td></tr>')
        if action_impact:
            rows.append(f'<tr><th>조치 시 영향</th><td>{_esc(action_impact)}</td></tr>')

    # 점검 결과
    rows.append('<tr class="kd-grp"><td colspan="2">점검 결과</td></tr>')
    if is_apply:
        result_inner = (
            f'<span class="kd-rl">조치 전</span> {_result_chip(before)} '
            f'<span class="kd-arrow">→</span> '
            f'<span class="kd-rl">조치 후</span> {_result_chip(after)} '
            f'<span class="kd-actwrap"><span class="kd-rl">동작</span> {_action_chip(action)}</span>'
        )
    else:
        result_inner = f'<span class="kd-rl">결과</span> {_result_chip(before)}'
    rows.append(f'<tr><th>결과</th><td>{result_inner}</td></tr>')
    if detail:
        rows.append(f'<tr><th>결과 사유</th><td class="kd-detail">{_detail_html(detail)}</td></tr>')

    # 조치 변경 내역 (조치 전 → 조치 후 · 빨강=제거 / 녹색=추가) — apply 모드 전 항목 통일 표시.
    # 장황한 evidence 덤프(stat/타임스탬프 등)는 표시하지 않고, 실제 바뀐 값만 diff 로.
    if is_apply and (ev_before or ev_after):
        rows.append('<tr class="kd-grp"><td colspan="2">조치 변경 내역 (조치 전 → 조치 후 · <span style="color:#f85149">빨강=제거</span> / <span style="color:#3fb950">녹색=추가</span>)</td></tr>')
        if ev_before and ev_after and ev_before.strip() != ev_after.strip():
            diff_box = _diff_html(ev_before, ev_after)
        else:
            diff_box = '<pre class="diffbox"><span class="dl ctx">(조치 변경 없음 — 현재 상태 유지)</span></pre>'
        rows.append(f'<tr><td colspan="2">{diff_box}</td></tr>')

    # 참고
    if references:
        refs_inner = "<br>".join(_esc(r) for r in references)
        rows.append(f'<tr class="kd-grp"><td colspan="2">참고</td></tr>')
        rows.append(f'<tr><td colspan="2">{refs_inner}</td></tr>')

    return '<table class="kisa-detail">' + "".join(rows) + "</table>"


def _items_table(items, table_id, mode):
    if not items:
        return ""
    is_apply = mode == "apply"
    # check 모드: "동작" / "조치 후" 컬럼은 의미 없으니 숨김
    if is_apply:
        header = (
            '<thead><tr>'
            '<th class="col-code">코드</th>'
            '<th class="col-sev">중요도</th>'
            '<th class="col-cat">카테고리</th>'
            '<th class="col-title">제목</th>'
            '<th class="col-state">조치 전</th>'
            '<th class="col-action">동작</th>'
            '<th class="col-state">조치 후</th>'
            '<th class="col-detail">상세</th>'
            '</tr></thead>'
        )
    else:
        header = (
            '<thead><tr>'
            '<th class="col-code">코드</th>'
            '<th class="col-sev">중요도</th>'
            '<th class="col-cat">카테고리</th>'
            '<th class="col-title">제목</th>'
            '<th class="col-state">결과</th>'
            '<th class="col-detail">상세</th>'
            '</tr></thead>'
        )
    rows = []
    for it in items:
        code = it.get("code", "")
        sev = it.get("severity", "")
        cat = it.get("category", "")
        title = it.get("title", "")
        before = it.get("before", "") or ""
        after = it.get("after", "") or ""
        action = it.get("action", "") or ""
        detail = it.get("detail", "") or ""
        evidence = it.get("evidence")
        error = it.get("error")
        rollback = it.get("rollback_plan") or []

        sev_attr = SEVERITY_RANK.get(sev, 9)
        # filter data attrs (소문자)
        data_attrs = (
            f' data-code="{_esc(code).lower()}"'
            f' data-sev="{_esc(sev)}"'
            f' data-sev-rank="{sev_attr}"'
            f' data-before="{_esc(before)}"'
            f' data-after="{_esc(after)}"'
            f' data-action="{_esc(action)}"'
        )
        rid = f"{table_id}-{_esc(code)}"
        sub_inner_parts = []
        # KISA 가이드 형식 단일 표 — meta(purpose/criterion/method 등) 가 있으면 풀 표 렌더링
        if it.get("purpose") or it.get("criterion_good") or it.get("method"):
            sub_inner_parts.append(_kisa_detail_table(it, mode))
        else:
            # 메타 없는 fallback — 기존 ev-block 들 재사용
            if detail:
                sub_inner_parts.append(
                    f'<div class="ev-block"><div class="ev-label">상세 사유</div>'
                    f'<pre class="evidence">{_esc(detail)}</pre></div>'
                )
            ev_html = _evidence_block(evidence)
            if ev_html:
                sub_inner_parts.append(ev_html)

        # rollback plan / error 는 별도 영역으로 항상 추가 (있을 때만)
        if error:
            sub_inner_parts.append(
                f'<div class="ev-block"><div class="ev-label ev-error">에러</div>'
                f'<pre class="evidence">{_esc(error)}</pre></div>'
            )
        if rollback:
            rb_text = "\n".join(
                f'{p.get("op","")}: {p.get("args","")}' if isinstance(p, dict) else str(p)
                for p in rollback
            )
            sub_inner_parts.append(
                f'<div class="ev-block"><div class="ev-label">rollback plan</div>'
                f'<pre class="evidence">{_esc(rb_text)}</pre></div>'
            )

        colspan = 8 if is_apply else 6
        sub_html = (
            f'<tr class="sub-row" id="sub-{rid}" hidden>'
            f'<td colspan="{colspan}"><div class="sub-wrap">{"".join(sub_inner_parts)}</div></td></tr>'
        ) if sub_inner_parts else ""

        short_detail = detail.replace("\n", " ").strip()
        if len(short_detail) > 110:
            short_detail = short_detail[:107] + "..."
        toggle_indicator = '<span class="kc-toggle">▸</span>' if sub_html else ''
        if is_apply:
            row_html = (
                f'<tr class="item-row"{data_attrs} onclick="toggleSub(\'sub-{rid}\', this)">'
                f'<td class="col-code mono">{toggle_indicator}{_esc(code)}</td>'
                f'<td class="col-sev">{_severity_chip(sev)}</td>'
                f'<td class="col-cat">{_esc(cat)}</td>'
                f'<td class="col-title">{_esc(title)}</td>'
                f'<td class="col-state">{_result_chip(before)}</td>'
                f'<td class="col-action">{_action_chip(action)}</td>'
                f'<td class="col-state">{_result_chip(after)}</td>'
                f'<td class="col-detail">{_esc(short_detail)}</td>'
                f'</tr>'
            )
        else:
            row_html = (
                f'<tr class="item-row"{data_attrs} onclick="toggleSub(\'sub-{rid}\', this)">'
                f'<td class="col-code mono">{toggle_indicator}{_esc(code)}</td>'
                f'<td class="col-sev">{_severity_chip(sev)}</td>'
                f'<td class="col-cat">{_esc(cat)}</td>'
                f'<td class="col-title">{_esc(title)}</td>'
                f'<td class="col-state">{_result_chip(before)}</td>'
                f'<td class="col-detail">{_esc(short_detail)}</td>'
                f'</tr>'
            )
        rows.append(row_html)
        rows.append(sub_html)

    return f'<table id="{table_id}" class="items">{header}<tbody>{"".join(rows)}</tbody></table>'


def render(state):
    mode = state.get("mode", "")
    is_apply = mode == "apply"

    items = state.get("items", []) or []
    kisa_items = [it for it in items if (it.get("code") or "").startswith("U-")]
    ext_items = [it for it in items if (it.get("code") or "").startswith("E-")]

    # 정렬: 코드 오름차순
    def _sort_key(it):
        c = it.get("code") or ""
        try:
            num = int(c.split("-", 1)[1])
        except Exception:
            num = 9999
        return (c[0], num)

    kisa_items.sort(key=_sort_key)
    ext_items.sort(key=_sort_key)

    sk = state.get("summary_kisa") or {}
    se = state.get("summary_ext") or {}

    title = f"KISA 점검·조치 결과 리포트 — {state.get('host', '')}"
    head = f"""
<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<title>{_esc(title)}</title>
<style>
:root{{
  --bg:#f6f7f9; --fg:#1f2328; --muted:#57606a; --line:#d0d7de; --line-soft:#eaeef2;
  --good:#116329; --good-bg:#dcfce7; --bad:#c01818; --bad-bg:#ffe5e5;
  --warn:#9a6700; --warn-bg:#fff8c5; --info:#0969da; --info-bg:#ddf4ff;
  --na:#57606a; --na-bg:#eef0f2;
  --sev-h:#b91c1c; --sev-m:#c2410c; --sev-l:#0969da;
  --header:#0d1117; --header-fg:#f5f5f5;
}}
*{{box-sizing:border-box}}
html,body{{margin:0;padding:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI","Apple SD Gothic Neo","Malgun Gothic","Noto Sans KR",sans-serif}}
.container{{max-width:1280px;margin:0 auto;padding:24px}}
header.top{{background:var(--header);color:var(--header-fg);padding:24px;border-radius:10px;margin-bottom:20px}}
header.top h1{{margin:0 0 10px;font-size:22px;font-weight:600;display:flex;align-items:center;gap:12px;flex-wrap:wrap}}
header.top .meta{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:6px 18px;font-size:13px;color:#cfd5dc}}
header.top .meta b{{color:#fff;margin-right:6px}}
.mode-badge{{display:inline-block;padding:3px 12px;border-radius:999px;font-size:12px;font-weight:600;letter-spacing:.04em;border:1px solid transparent}}
.mode-badge.mode-check{{background:#ddf4ff;color:#0969da;border-color:#79c0ff}}
.mode-badge.mode-apply{{background:#dcfce7;color:#116329;border-color:#7ee7a3}}
.notice{{padding:14px 18px;border-radius:8px;margin-bottom:18px;font-size:13px;line-height:1.7}}
.notice-info{{background:#ddf4ff;border:1px solid #79c0ff;color:#0a3069}}
.notice b{{color:#0a3069}}
.notice ul.notice-legend{{margin:8px 0 0;padding-left:0;list-style:none;display:flex;flex-wrap:wrap;gap:8px 18px}}
.notice ul.notice-legend li{{display:flex;align-items:center;gap:6px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px;margin-bottom:18px}}
.card{{background:#fff;border:1px solid var(--line);border-radius:8px;padding:16px}}
.card h3{{margin:0 0 8px;font-size:14px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}}
table.kv{{width:100%;border-collapse:collapse}}
table.kv th{{text-align:left;font-weight:500;color:var(--muted);padding:4px 8px 4px 0;width:55%}}
table.kv td{{text-align:right;font-weight:600;padding:4px 0;font-variant-numeric:tabular-nums}}
.section{{background:#fff;border:1px solid var(--line);border-radius:8px;margin-bottom:18px;overflow:hidden}}
.section h2{{margin:0;padding:14px 18px;border-bottom:1px solid var(--line);font-size:16px;background:#fafbfc}}
.section .filters{{padding:10px 18px;border-bottom:1px solid var(--line-soft);display:flex;flex-wrap:wrap;gap:8px;align-items:center;background:#fcfcfd}}
.filters input[type=text]{{flex:1;min-width:180px;padding:6px 10px;border:1px solid var(--line);border-radius:6px;font-size:13px}}
.filter-btn{{padding:4px 10px;border:1px solid var(--line);border-radius:999px;background:#fff;font-size:12px;cursor:pointer;color:var(--muted)}}
.filter-btn.active{{background:var(--header);color:#fff;border-color:var(--header)}}
table.items{{width:100%;border-collapse:collapse;font-size:13px}}
table.items thead th{{background:#fafbfc;border-bottom:1px solid var(--line);padding:8px 10px;text-align:left;font-weight:600;color:var(--muted);position:sticky;top:0;z-index:1}}
table.items tbody td{{padding:8px 10px;border-bottom:1px solid var(--line-soft);vertical-align:middle}}
table.items tbody tr.item-row{{cursor:pointer}}
table.items tbody tr.item-row:hover{{background:#f6f8fa}}
table.items tr.sub-row td{{padding:0;background:#fafbfc}}
.sub-wrap{{padding:14px 18px;border-bottom:1px solid var(--line)}}
.ev-block{{margin-bottom:12px}}
.ev-block:last-child{{margin-bottom:0}}
.ev-label{{font-size:12px;font-weight:600;color:var(--muted);margin-bottom:4px;text-transform:uppercase;letter-spacing:.04em}}
.ev-label.ev-error{{color:var(--bad)}}
pre.evidence{{margin:0;padding:10px 12px;background:#0d1117;color:#e6edf3;border-radius:6px;overflow-x:auto;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre-wrap;word-break:break-all}}
pre.diffbox{{margin:0;padding:10px 12px;background:#0d1117;border-radius:6px;overflow-x:auto;font:12px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre-wrap;word-break:break-all;max-height:360px}}
pre.diffbox .dl{{display:block}}
pre.diffbox .add{{color:#3fb950;background:rgba(63,185,80,.13)}}
pre.diffbox .del{{color:#f85149;background:rgba(248,81,73,.13)}}
pre.diffbox .ctx{{color:#8b949e}}
table.kisa-detail .kd-arrow{{font-weight:700;font-size:16px;color:#475569;margin:0 4px;vertical-align:middle}}
table.kisa-detail .kd-actwrap{{margin-left:14px;padding-left:14px;border-left:1px solid #d0d7de}}
pre.evidence.note{{background:#1a1f2e;border-left:3px solid var(--good);color:#cdd6e0}}
pre.evidence.note::first-line{{color:var(--good);font-weight:600}}
.col-code{{width:70px}}
.col-sev{{width:64px;text-align:center}}
.col-cat{{width:160px}}
.col-title{{width:auto}}
.col-state{{width:78px;text-align:center}}
.col-action{{width:96px;text-align:center}}
.col-detail{{color:var(--muted)}}
.mono{{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}}
.chip{{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600;line-height:1.4}}
.chip-good{{background:var(--good-bg);color:var(--good)}}
.chip-bad{{background:var(--bad-bg);color:var(--bad)}}
.chip-warn{{background:var(--warn-bg);color:var(--warn)}}
.chip-na{{background:var(--na-bg);color:var(--na)}}
.chip-applied{{background:var(--good-bg);color:var(--good)}}
.chip-skipped{{background:var(--info-bg);color:var(--info)}}
.chip-manual{{background:var(--warn-bg);color:var(--warn)}}
.chip-failed{{background:var(--bad-bg);color:var(--bad)}}
.chip-checked{{background:var(--info-bg);color:var(--info)}}
.chip-dryrun{{background:var(--warn-bg);color:var(--warn)}}
.sev-h{{background:#fee2e2;color:var(--sev-h)}}
.sev-m{{background:#ffedd5;color:var(--sev-m)}}
.sev-l{{background:#dbeafe;color:var(--sev-l)}}
footer.bottom{{color:var(--muted);font-size:12px;padding:16px;text-align:center}}
.cmd{{display:inline-block;padding:2px 6px;background:#eaeef2;border-radius:4px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}}
/* KISA 가이드 형식 카드 */
.kisa-cards{{padding:18px;display:flex;flex-direction:column;gap:18px;background:#f6f7f9}}
article.kisa-card{{background:#fff;border:1px solid var(--line);border-radius:8px;overflow:hidden;break-inside:avoid}}
.kc-head{{display:grid;grid-template-columns:80px 60px 1fr;align-items:center;gap:12px;padding:14px 18px;background:#0d1117;color:#fff;border-bottom:1px solid var(--line)}}
.kc-head .kc-code{{font-size:18px;font-weight:700;letter-spacing:.04em}}
.kc-head .kc-cat{{font-size:11px;color:#9da7b1;letter-spacing:.04em;text-transform:uppercase}}
.kc-head .kc-name{{font-size:15px;font-weight:600;color:#fff}}
.kc-section{{padding:14px 18px;border-bottom:1px solid var(--line-soft)}}
.kc-section:last-child{{border-bottom:0}}
.kc-h3{{font-size:11px;font-weight:700;color:var(--muted);letter-spacing:.06em;text-transform:uppercase;margin-bottom:8px;padding-bottom:6px;border-bottom:2px solid var(--line)}}
table.kc-tbl{{width:100%;border-collapse:collapse;font-size:13px}}
table.kc-tbl th{{width:120px;text-align:left;color:var(--muted);font-weight:600;padding:8px 12px 8px 0;vertical-align:top;border-bottom:1px solid var(--line-soft)}}
table.kc-tbl td{{padding:8px 0;vertical-align:top;border-bottom:1px solid var(--line-soft);line-height:1.6}}
table.kc-tbl tr:last-child th, table.kc-tbl tr:last-child td{{border-bottom:0}}
.kc-cmd-list{{margin:0;padding-left:22px;display:flex;flex-direction:column;gap:4px}}
.kc-cmd-list code{{background:#eaeef2;padding:2px 6px;border-radius:4px;font-size:12px}}
table.kc-result{{width:100%;border-collapse:collapse;font-size:13px}}
table.kc-result th{{background:#fafbfc;text-align:left;color:var(--muted);font-weight:600;padding:8px 12px;border:1px solid var(--line-soft);width:90px}}
table.kc-result td{{padding:8px 12px;border:1px solid var(--line-soft);line-height:1.6}}
.kc-evidence-grid{{padding:14px 18px;display:grid;grid-template-columns:1fr 1fr;gap:14px;border-bottom:1px solid var(--line-soft)}}
.kc-ev-col pre.evidence{{max-height:320px;overflow:auto}}
.kc-refs{{padding:10px 18px;font-size:12px;color:var(--muted);background:#fafbfc;border-top:1px solid var(--line-soft)}}
@media (max-width:900px){{.kc-evidence-grid{{grid-template-columns:1fr}}}}
/* KISA 가이드 PDF 풍 단일 표 (인라인 expand 영역) */
.kc-toggle{{display:inline-block;width:14px;color:var(--muted);font-size:11px;transition:transform .15s}}
tr.item-row.expanded{{background:#eef4ff}}
tr.item-row{{cursor:pointer}}
tr.item-row:hover{{background:#f3f6fa}}
.sub-wrap{{padding:14px 16px;background:#fafbfc}}
table.kisa-detail{{width:100%;border-collapse:collapse;background:#fff;border:1px solid #aab2bd;font-size:13px;margin:0;table-layout:fixed}}
table.kisa-detail tr.kd-head td{{background:#0d1117;color:#fff;padding:10px 14px;border:1px solid #aab2bd;font-weight:600;vertical-align:middle}}
table.kisa-detail tr.kd-head td.kd-code-cell{{width:140px;text-align:center;padding:14px;background:#1a1f2e}}
table.kisa-detail tr.kd-head td.kd-code-cell .kd-code{{font-size:18px;font-weight:700;letter-spacing:.05em;margin-bottom:6px}}
table.kisa-detail tr.kd-head td.kd-cat{{font-size:11px;color:#9da7b1;letter-spacing:.06em;text-transform:uppercase;border-left:0;padding:8px 14px}}
table.kisa-detail tr.kd-head td.kd-name{{font-size:15px;border-left:0;padding:8px 14px;border-top:0}}
table.kisa-detail tr.kd-grp td{{background:#f5f5f5;color:#333;font-weight:700;text-align:center;padding:8px 14px;border:1px solid #aab2bd;letter-spacing:.04em;font-size:12px}}
table.kisa-detail th{{background:#fafbfc;color:#374151;font-weight:600;text-align:left;padding:8px 12px;border:1px solid #aab2bd;width:120px;vertical-align:top;font-size:12px}}
table.kisa-detail td{{padding:8px 12px;border:1px solid #aab2bd;vertical-align:top;line-height:1.65;color:#1a1d23;word-break:break-word}}
table.kisa-detail td pre.evidence{{max-height:340px;overflow:auto;margin:0;font-size:11.5px;line-height:1.45}}
table.kisa-detail .kd-rl{{display:inline-block;font-size:11px;color:var(--muted);font-weight:700;letter-spacing:.04em;margin-right:4px;vertical-align:middle}}
table.kisa-detail td.kd-detail{{line-height:1.6}}
table.kisa-detail td.kd-detail .kd-verdict{{font-weight:700;color:#1f2937}}
table.kisa-detail td.kd-detail .kd-action-line{{display:inline-block;color:#475569;padding-left:8px}}
@media (max-width:760px){{
  table.kisa-detail, table.kisa-detail tr, table.kisa-detail td, table.kisa-detail th{{display:block;width:auto}}
  table.kisa-detail th{{width:auto;border-bottom:0}}
}}
@media print {{
  body{{background:#fff}} header.top{{background:#fff;color:#000;border:1px solid #000}} header.top .meta b{{color:#000}}
  .filters{{display:none}} pre.evidence{{background:#fff;color:#000;border:1px solid #ccc}}
  .section,.card{{box-shadow:none;break-inside:avoid}}
}}
</style>
</head>
<body>
<div class="container">
"""

    # header
    rb_run = state.get("run_id", "")
    mode_label = {
        "check": "점검(check)",
        "apply": "조치(apply)",
    }.get(mode, mode)
    mode_badge_cls = "mode-apply" if is_apply else "mode-check"
    header_html = f"""
<header class="top">
  <h1>KISA 점검·조치 결과 리포트 <span class="mode-badge {mode_badge_cls}">{_esc(mode_label)}</span></h1>
  <div class="meta">
    <div><b>host</b><span class="cmd">{_esc(state.get('host',''))}</span></div>
    <div><b>OS</b>{_esc(state.get('os_pretty',''))} ({_esc(state.get('os_family',''))})</div>
    <div><b>run-id</b><span class="cmd">{_esc(rb_run)}</span></div>
    <div><b>started</b>{_esc(_fmt_time(state.get('started_at')))}</div>
    <div><b>ended</b>{_esc(_fmt_time(state.get('ended_at')))}</div>
    <div><b>script</b>{_esc(state.get('script_version','?'))}</div>
  </div>
</header>
"""

    # mode 안내 박스
    if not is_apply:
        notice_html = """
<div class="notice notice-info">
  <b>이 리포트는 점검(check) 결과입니다.</b>
  실제 조치(파일 변경)는 수행되지 않았습니다.
  취약 항목을 자동 조치하려면 <span class="cmd">./kisa-audit.sh apply</span> 를 실행하세요.
  <ul class="notice-legend">
    <li><span class="chip chip-good">양호</span> KISA 가이드 기준 충족</li>
    <li><span class="chip chip-bad">취약</span> 조치 필요</li>
    <li><span class="chip chip-warn">판정불가</span> 점검 자체가 환경상 불가능 (예: 평가 대상 계정·파일·서비스 없음)</li>
  </ul>
</div>
"""
    else:
        notice_html = """
<div class="notice notice-info">
  <b>이 리포트는 조치(apply) 결과입니다.</b>
  자동 조치된 항목은 <span class="chip chip-applied">applied</span>, 이미 양호하던 항목은 <span class="chip chip-skipped">skipped</span>,
  운영자 판단이 필요한 항목은 <span class="chip chip-manual">manual</span> 로 표시됩니다.
  롤백은 <span class="cmd">./kisa-audit.sh rollback</span> (시스템 전수 *.kisa.bak 스캔 후 복원).
</div>
"""

    # cards (summary)
    cards_html = '<div class="cards">'
    if sk:
        cards_html += _stat_block("KISA 표준 (U-01~U-67)", sk, mode)
    if se and se.get("total", 0) > 0:
        cards_html += _stat_block("확장 (E-01~ — KISA 범위 외)", se, mode)
    cards_html += "</div>"

    # site env snapshot (감사 추적용)
    site_env = state.get("site_env") or {}
    site_env_set = [(k, v) for k, v in site_env.items() if v]
    site_env_html = ""
    if site_env_set:
        rows = "".join(
            f"<tr><th>{_esc(k)}</th><td><code>{_esc(v)}</code></td></tr>"
            for k, v in site_env_set
        )
        site_env_html = (
            '<section class="card" style="margin-bottom:18px">'
            '<h3>사이트 환경변수 (이번 점검에 적용됨)</h3>'
            f'<table class="kv">{rows}</table>'
            '</section>'
        )

    # 잔존 취약 핵심 요약 — apply 모드는 after, check 모드는 before 기준
    focus_field = "after" if mode == "apply" else "before"
    bad_items = [it for it in items if it.get(focus_field) == "취약"]
    quick_html = ""
    if bad_items:
        label = "조치 후" if mode == "apply" else "현재"
        rows = []
        for it in bad_items:
            code = it.get("code", "")
            det = (it.get("detail") or "").replace("\n", " ").strip()
            if len(det) > 200:
                det = det[:197] + "..."
            
            guide = REMEDIATION_GUIDE.get(code)
            guide_html = ""
            if guide:
                clean_guide = guide.replace("[조치 방법] ", "").strip()
                guide_html = f'<div style="background:#fafbfc; border:1px solid #d1d5db; border-radius:6px; padding:8px 12px; margin-top:6px; font-size:11.5px; font-family:ui-monospace,SFMono-Regular,Consolas,monospace; white-space:pre-wrap; color:#24292e; line-height:1.55;"><b>[추천 조치 방법 및 명령어]</b>\n{_esc(clean_guide)}</div>'

            rows.append(
                f'<li style="margin-bottom:14px;"><b>{_esc(code)}</b> '
                f'<span class="sev sev-{_esc((it.get("severity","")))}">[{_esc(it.get("severity",""))}]</span> '
                f'{_esc(it.get("title",""))}'
                + (f'<div style="color:var(--muted);margin-top:4px;font-size:13px">{_esc(det)}</div>' if det else '')
                + guide_html
                + '</li>'
            )
        quick_html = (
            '<section class="card" style="margin-bottom:18px;border-left:4px solid var(--bad)">'
            f'<h3>{_esc(label)} 취약 항목 핵심 요약 ({len(bad_items)}건 — 조치 필요)</h3>'
            f'<ul style="margin:8px 0 0;padding-left:20px;line-height:1.9">{"".join(rows)}</ul>'
            '</section>'
        )

    # filters JS controls per table
    def _section_for(items, sect_id, title):
        if not items:
            return ""
        table_html = _items_table(items, f"tbl-{sect_id}", mode)
        if is_apply:
            filter_buttons = """
    <button class="filter-btn active" data-filter="all" onclick="setFilter(this,'all')">전체</button>
    <button class="filter-btn" data-filter="bad" onclick="setFilter(this,'bad')">조치 전 취약</button>
    <button class="filter-btn" data-filter="after-bad" onclick="setFilter(this,'after-bad')">조치 후 취약</button>
    <button class="filter-btn" data-filter="manual" onclick="setFilter(this,'manual')">수동 조치</button>
    <button class="filter-btn" data-filter="applied" onclick="setFilter(this,'applied')">자동 조치 완료</button>
    <button class="filter-btn" data-filter="failed" onclick="setFilter(this,'failed')">조치 실패</button>"""
        else:
            filter_buttons = """
    <button class="filter-btn active" data-filter="all" onclick="setFilter(this,'all')">전체</button>
    <button class="filter-btn" data-filter="bad" onclick="setFilter(this,'bad')">취약만</button>
    <button class="filter-btn" data-filter="warn" onclick="setFilter(this,'warn')">판정불가</button>
    <button class="filter-btn" data-filter="good" onclick="setFilter(this,'good')">양호만</button>"""
        return f"""
<section class="section" id="sec-{sect_id}">
  <h2>{_esc(title)} <small style="color:var(--muted);font-weight:400">— 총 {len(items)}건</small></h2>
  <div class="filters" data-target="tbl-{sect_id}">
    <input type="text" placeholder="검색 (코드·제목·카테고리·상세)" oninput="filterTable(this)">
    {filter_buttons}
  </div>
  {table_html}
</section>
"""

    sections_html = notice_html

    # KISA 가이드 형식 상세표는 표 행 클릭 시 인라인 expand 영역으로 통합됨 — 별도 카드 섹션 제거
    sections_html += _section_for(kisa_items, "kisa", "항목별 결과 (KISA 표준 U-01~U-67)")
    sections_html += _section_for(ext_items, "ext", "항목별 결과 (확장 E-01~ — KISA 범위 외)")

    rollback_html = (
        '<section class="card"><h3>롤백 명령</h3>'
        '<pre class="evidence">./kisa-audit.sh rollback</pre>'
        '<p style="margin:8px 0 0 0; font-size:12px; color:#475569;">'
        '시스템 디렉터리(<code>/etc /root /home /var /usr/local /opt /boot</code>)에서 '
        '<code>*.kisa.bak</code> 파일을 전수 검색해 원복합니다.</p>'
        '</section>'
        if is_apply
        else ""
    )

    js = """
<script>
function toggleSub(id, row){
  var el=document.getElementById(id); if(!el) return;
  el.hidden=!el.hidden;
  if(row){
    var t=row.querySelector('.kc-toggle');
    if(t){ t.textContent = el.hidden ? '▸' : '▾'; }
    row.classList.toggle('expanded', !el.hidden);
  }
}
function setFilter(btn, kind){
  var box=btn.closest('.filters');
  box.querySelectorAll('.filter-btn').forEach(function(b){b.classList.toggle('active',b===btn);});
  applyFilters(box);
}
function filterTable(input){
  applyFilters(input.closest('.filters'));
}
function applyFilters(box){
  var tableId=box.dataset.target;
  var table=document.getElementById(tableId); if(!table) return;
  var q=(box.querySelector('input[type=text]').value||'').toLowerCase().trim();
  var kind=(box.querySelector('.filter-btn.active')||{}).dataset?.filter||'all';
  table.querySelectorAll('tbody tr.item-row').forEach(function(tr){
    var sub=document.getElementById('sub-'+tr.getAttribute('onclick').match(/'([^']+)'/)[1].replace(/^sub-/,''));
    var text=tr.innerText.toLowerCase();
    var ok=true;
    if(q && text.indexOf(q)===-1) ok=false;
    if(ok && kind!=='all'){
      var b=tr.dataset.before, a=tr.dataset.after, ac=tr.dataset.action;
      if(kind==='bad' && b!=='취약') ok=false;
      if(kind==='good' && b!=='양호') ok=false;
      if(kind==='warn' && b!=='판정불가') ok=false;
      if(kind==='after-bad' && a!=='취약') ok=false;
      if(kind==='manual' && ac!=='manual') ok=false;
      if(kind==='applied' && ac!=='applied') ok=false;
      if(kind==='failed' && ac!=='failed') ok=false;
    }
    tr.style.display=ok?'':'none';
    if(sub){ if(!ok) sub.hidden=true; sub.style.display=ok?'':'none'; }
  });
}
</script>
"""

    footer = f"""
<footer class="bottom">
  생성: {_esc(_fmt_time(datetime.now().astimezone().isoformat(timespec='seconds')))} —
  KISA-Audit (script {_esc(state.get('script_version','?'))})
</footer>
</div>
{js}
</body></html>
"""

    return head + header_html + cards_html + site_env_html + quick_html + sections_html + rollback_html + footer


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("input", help="report.json 경로")
    ap.add_argument("-o", "--output", help="report.html 경로 (기본: 같은 디렉터리)")
    args = ap.parse_args(argv)

    with open(args.input, encoding="utf-8") as f:
        state = json.load(f)

    out = args.output or os.path.join(os.path.dirname(os.path.abspath(args.input)) or ".", "report.html")
    html_text = render(state)
    with open(out, "w", encoding="utf-8") as f:
        f.write(html_text)
    try:
        os.chmod(out, 0o600)
    except Exception:
        pass
    print(out)


if __name__ == "__main__":
    main(sys.argv[1:])
