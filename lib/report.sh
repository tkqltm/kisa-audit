#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# KISA Audit - render single report.html into the invocation directory.
#
# 입력:  $KISA_TMP_DIR/items.jsonl  (run_handler 가 누적)
# 출력:  $KISA_INVOCATION_DIR/report.html  (덮어쓰기)
#
# json/md 사이드카는 더 이상 생성하지 않음. report.html 만 영구 산출물.

[[ -n "${_KISA_REPORT_LOADED:-}" ]] && return 0
_KISA_REPORT_LOADED=1

render_report() {
    [[ -n "${KISA_TMP_DIR:-}" && -d "$KISA_TMP_DIR" ]] || { log_error "KISA_TMP_DIR 미설정"; return 1; }
    [[ -n "${KISA_INVOCATION_DIR:-}" ]] || { log_error "KISA_INVOCATION_DIR 미설정"; return 1; }

    local items="$KISA_TMP_DIR/items.jsonl"
    [[ -f "$items" ]] || : > "$items"

    # report.json 은 render-html.py 입력용 임시 파일 (TMP_DIR 안에서만 살다가 사라짐).
    local tmp_state="$KISA_TMP_DIR/report.json"
    local out_html="$KISA_INVOCATION_DIR/report.html"

    "$PYTHON" - "$KISA_TMP_DIR" "$items" "$tmp_state" "$KISA_BASE" <<'PY'
import signal
try: signal.signal(signal.SIGPIPE, signal.SIG_DFL)
except (AttributeError, ValueError): pass

import json, os, sys, datetime, socket
tmp_dir, items_path, state_path, base = sys.argv[1:5]

mode    = os.environ.get("KISA_MODE", "check")

# script version
ver = "unknown"
try:
    with open(os.path.join(base, "VERSION"), encoding="utf-8") as f:
        ver = f.read().strip() or "unknown"
except Exception:
    pass

# OS info from env (set by os_detect.sh)
os_family = os.environ.get("OS_FAMILY", "unknown")
os_pretty = os.environ.get("OS_PRETTY", "unknown")

# site env passthrough — audit.conf 정책 변수 (감사 추적)
keys = [
    "ALLOWED_HOSTS","FIREWALL_SERVICES","FIREWALL_PORTS","SSH_PORT",
    "EXEMPT_GROUPS","EXTRA_FLAG_GROUPS","EXEMPT_ACCOUNTS",
    "NFS_ALLOWED_NETWORKS","SSH_BANNER",
    "PASSWORD_MIN_LEN","PASSWORD_MAX_AGE","PASSWORD_MIN_AGE","PASSWORD_WARN_AGE",
    "LOGIN_MAX_RETRY","LOGIN_LOCK_TIME","SESSION_TIMEOUT","UMASK_VALUE",
    "SSH_PERMIT_ROOT_LOGIN","ADMIN_USER","DENY_HOSTS",
    "DNS_ZONE_ALLOW_TRANSFER","NTP_SERVERS","SUDOERS_ADMIN_GROUP",
    "FTP_MODE","TELNET_MODE","AUTO_UPDATE","SELINUX_MODE",
]
site_env = {k: os.environ.get(k, "") for k in keys}

state = {
    "run_id": datetime.datetime.now().strftime("%Y%m%d-%H%M%S"),
    "started_at": datetime.datetime.now().astimezone().isoformat(timespec='seconds'),
    "host": socket.gethostname(),
    "os_family": os_family,
    "os_pretty": os_pretty,
    "script_version": ver,
    "mode": mode,
    "site_env": site_env,
    "items": [],
}

items = []
with open(items_path, encoding='utf-8') as f:
    for ln in f:
        ln = ln.strip()
        if not ln: continue
        try: items.append(json.loads(ln))
        except Exception: pass

state["items"] = items
state["ended_at"] = datetime.datetime.now().astimezone().isoformat(timespec='seconds')

def _new_counts(total):
    return {"total": total, "before_good":0, "before_bad":0,
            "applied":0, "skipped":0, "manual":0, "failed":0,
            "not_applicable":0, "checked":0,
            "after_good":0, "after_bad":0}

kisa_items = [it for it in items if (it.get("code","") or "").startswith("U-")]
ext_items  = [it for it in items if (it.get("code","") or "").startswith("E-")]

def _tally(target, src):
    for it in src:
        if it.get("before") == "양호": target["before_good"] += 1
        elif it.get("before") == "취약": target["before_bad"] += 1
        a = it.get("action","")
        if a in target: target[a] += 1
        if it.get("after") == "양호": target["after_good"] += 1
        elif it.get("after") == "취약": target["after_bad"] += 1

counts      = _new_counts(len(items));     _tally(counts,      items)
kisa_counts = _new_counts(len(kisa_items)); _tally(kisa_counts, kisa_items)
ext_counts  = _new_counts(len(ext_items));  _tally(ext_counts,  ext_items)

state["summary"]      = counts
state["summary_kisa"] = kisa_counts
state["summary_ext"]  = ext_counts

with open(state_path, "w", encoding='utf-8') as f:
    json.dump(state, f, ensure_ascii=False, indent=2)

# console summary
GREEN="\033[32m"; RED="\033[31m"; YELLOW="\033[33m"; BOLD="\033[1m"; RESET="\033[0m"
if not sys.stdout.isatty():
    GREEN=RED=YELLOW=BOLD=RESET=""

print()
print("="*60)
print(f"  KISA 점검 결과 요약   host={state['host']}   os={state['os_family']}")
print(f"  mode={state['mode']}")
print("="*60)
print(f"  [KISA 표준 U-01~U-67]  항목수 : {kisa_counts['total']}")
print(f"  [점검 전] {GREEN}양호: {kisa_counts['before_good']}{RESET}   {YELLOW}취약: {kisa_counts['before_bad']}{RESET}")
if state["mode"] == "apply":
    print(f"  [조치 후] {GREEN}양호: {kisa_counts['after_good']}{RESET}   {RED}취약: {kisa_counts['after_bad']}{RESET}")
    print(f"  {GREEN}자동 조치 완료 : {kisa_counts['applied']}{RESET}    이미 양호(skip): {kisa_counts['skipped']}    {YELLOW}수동 조치 필요 : {kisa_counts['manual']}{RESET}    {BOLD}{RED}조치 실패 : {kisa_counts['failed']}{RESET}")
    if kisa_counts['not_applicable']:
        print(f"  해당없음       : {kisa_counts['not_applicable']}")
if ext_counts['total'] > 0:
    print("-"*60)
    print(f"  [확장 E-01~ — KISA 범위 외]  항목수 : {ext_counts['total']}")
    print(f"  [점검 전] {GREEN}양호: {ext_counts['before_good']}{RESET}   {YELLOW}취약: {ext_counts['before_bad']}{RESET}")
    if state["mode"] == "apply":
        print(f"  [조치 후] {GREEN}양호: {ext_counts['after_good']}{RESET}   {RED}취약: {ext_counts['after_bad']}{RESET}")
        print(f"  {GREEN}자동 조치 완료 : {ext_counts['applied']}{RESET}    이미 양호(skip): {ext_counts['skipped']}    {YELLOW}수동 조치 필요 : {ext_counts['manual']}{RESET}    {BOLD}{RED}조치 실패 : {ext_counts['failed']}{RESET}")
print("="*60)
PY

    # report.json 및 report.html 생성
    # (report.json 은 check/apply 모두에 대해 저장해 둡니다)
    local out_json="$KISA_INVOCATION_DIR/report.json"
    cp -f "$tmp_state" "$out_json" 2>/dev/null || true
    chmod 644 "$out_json" 2>/dev/null || true

    # report.html 은 apply 모드에서만 생성 (check 는 콘솔 결과만)
    if [[ "${KISA_MODE:-check}" == "apply" ]]; then
        local html_renderer="$KISA_BASE/tools/render-html.py"
        if [[ -f "$html_renderer" ]]; then
            if "$PYTHON" "$html_renderer" "$tmp_state" -o "$out_html" >/dev/null 2>&1; then
                chmod 644 "$out_html" 2>/dev/null || true   # 644: admin/일반계정도 SFTP(MobaXterm) 로 회수 가능
                log_info ""
                log_info "  Report  : $out_html"
            else
                log_warn "report.html 생성 실패"
            fi
        else
            log_warn "render-html.py 없음: $html_renderer"
        fi
    fi
}
