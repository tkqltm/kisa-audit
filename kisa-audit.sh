#!/usr/bin/env bash
#
# ─────────────────────────────────────────────────────────────────────────
#  kisa-audit — KISA 주요정보통신기반시설 Unix 서버 취약점 점검·조치 도구
#
#  Copyright (c) 2026 정하늘 (Ha-Neul Jung) <ahanaoal@gmail.com>
#  This software is released under the MIT License.
#  See the LICENSE file for details.
# ─────────────────────────────────────────────────────────────────────────
#
# kisa-audit.sh — KISA 주요정보통신기반시설 Unix 서버 취약점(U-01~U-67) 점검·조치·롤백 원샷 스크립트
#                 + 확장 항목(E-01~E-04: SSH Port/SELinux/Firewall)
#
# 단일 호스트 자가 완결 실행:
#   - tar.gz 풀어서 config/audit.conf 편집 후 ./kisa-audit.sh apply
#   - 산출물: 실행 디렉터리에 report.html (덮어쓰기)
#   - 백업:   조치된 원본 옆 <file>.kisa.bak (이미 있으면 skip — 최초 원본 보존)
#   - 정리:   런 종료 시 임시 디렉터리 자동 삭제. 시스템에 남는 파일은
#             (1) 조치된 시스템 파일, (2) *.kisa.bak 백업, (3) ./report.html.
#
# 사용법:
#   ./kisa-audit.sh check                  : 점검만 (변경없음)
#   ./kisa-audit.sh apply                  : 취약 항목 자동 조치 + report.html
#   ./kisa-audit.sh rollback               : 시스템 전수 *.kisa.bak 스캔 후 원복
#   ./kisa-audit.sh help                   : 도움말
# 추가 옵션:
#   --only U-01,E-02,...    : 지정 항목만
#   --skip U-07,U-08        : 지정 항목 제외
#
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INVOCATION_DIR="$(pwd)"   # report.html 생성 경로 (사용자가 ./kisa-audit.sh 를 호출한 위치)
export KISA_BASE="$SCRIPT_DIR"
export KISA_INVOCATION_DIR="$INVOCATION_DIR"

# ─────────────────────────────────────────────────────────────────────────
#  무결성 검증 (저작권 보호 — 핸들러/라이브러리 변조 차단)
#  Copyright (c) 2026 정하늘 <ahanaoal@gmail.com>
# ─────────────────────────────────────────────────────────────────────────
_kisa_verify_integrity() {
    local manifest="$KISA_BASE/lib/.integrity.sha256"
    [[ -f "$manifest" ]] || {
        echo "[ERROR] 무결성 매니페스트 누락: $manifest" >&2
        echo "        패키지 손상 또는 변조 의심. 정품 패키지로 재배포하세요." >&2
        echo "        문의: 정하늘 <ahanaoal@gmail.com>" >&2
        exit 99
    }
    if ! command -v sha256sum >/dev/null 2>&1; then
        echo "[ERROR] sha256sum 명령 없음 — 무결성 검증 불가" >&2
        exit 99
    fi
    local fail=0
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local expect_hash file_path
        expect_hash="${line%% *}"
        file_path="${line##* }"
        local target="$KISA_BASE/$file_path"
        if [[ ! -f "$target" ]]; then
            echo "[ERROR] 파일 누락: $file_path" >&2
            fail=1; continue
        fi
        local actual
        actual=$(sha256sum "$target" 2>/dev/null | awk '{print $1}')
        if [[ "$actual" != "$expect_hash" ]]; then
            echo "[ERROR] 무결성 검증 실패: $file_path" >&2
            echo "        예상: $expect_hash" >&2
            echo "        실제: $actual" >&2
            fail=1
        fi
    done < "$manifest"
    if (( fail )); then
        echo "" >&2
        echo "[ERROR] kisa-audit 무결성 검증 실패 — 실행 중단." >&2
        echo "        본 프로그램은 정하늘 <ahanaoal@gmail.com> 의 저작물입니다." >&2
        echo "        무단 수정 금지. 정품 패키지로 재배포하세요." >&2
        exit 99
    fi
}
_kisa_verify_integrity

# shellcheck source=lib/common.sh
source "$KISA_BASE/lib/common.sh"
# shellcheck source=lib/os_detect.sh
source "$KISA_BASE/lib/os_detect.sh"
# shellcheck source=lib/report.sh
source "$KISA_BASE/lib/report.sh"

# ---------- trap ----------
_on_err() {
    local rc=$?
    if (( rc == 141 || rc == 120 )); then
        return 0
    fi
    log_error "예외 발생 (rc=$rc) at line $1"
    [[ -n "${KISA_TMP_DIR:-}" ]] && render_report || true
    exit $rc
}
_on_int() {
    log_warn "중단 요청 감지 (Ctrl+C)."
    if [[ -n "${KISA_TMP_DIR:-}" ]]; then
        log_warn "부분 조치 상태입니다. 필요 시: $0 rollback"
        render_report || true
    fi
    exit 130
}
trap '_on_err $LINENO' ERR
trap '_on_int' INT TERM
# SIGHUP 무시 — apply/rollback 도중 SSH 세션 끊김 (admin 자기 삭제 → sshd reload → 세션 끊김) 시
# kisa-audit.sh 가 SIGHUP 받아 죽지 않도록. trap '' HUP 으로 무시 처리.
trap '' HUP

# ---------- defaults (KISA 권고 기본값; env → audit.conf 순으로 override 가능) ----------
PASSWORD_MIN_LEN="${PASSWORD_MIN_LEN:-8}"
PASSWORD_MAX_AGE="${PASSWORD_MAX_AGE:-90}"
PASSWORD_MIN_AGE="${PASSWORD_MIN_AGE:-1}"
PASSWORD_WARN_AGE="${PASSWORD_WARN_AGE:-7}"
LOGIN_MAX_RETRY="${LOGIN_MAX_RETRY:-5}"
LOGIN_LOCK_TIME="${LOGIN_LOCK_TIME:-120}"
SESSION_TIMEOUT="${SESSION_TIMEOUT:-600}"
UMASK_VALUE="${UMASK_VALUE:-022}"
SSH_PERMIT_ROOT_LOGIN="${SSH_PERMIT_ROOT_LOGIN:-no}"
ADMIN_USER="${ADMIN_USER:-}"
ADMIN_USER_PASSWORD="${ADMIN_USER_PASSWORD:-}"
ADMIN_USER_PUBKEY="${ADMIN_USER_PUBKEY:-}"
ALLOWED_HOSTS="${ALLOWED_HOSTS:-}"
DENY_HOSTS="${DENY_HOSTS:-ALL}"
NFS_ALLOWED_NETWORKS="${NFS_ALLOWED_NETWORKS:-}"
SNMP_COMMUNITY_ENV_VAR="${SNMP_COMMUNITY_ENV_VAR:-KISA_SNMP_COMMUNITY}"
SNMP_ALLOWED_NETWORKS="${SNMP_ALLOWED_NETWORKS:-}"
DNS_ZONE_ALLOW_TRANSFER="${DNS_ZONE_ALLOW_TRANSFER:-none}"
LOGIN_BANNER_TEXT="${LOGIN_BANNER_TEXT:-}"
NTP_SERVERS="${NTP_SERVERS:-}"
SUDOERS_ADMIN_GROUP="${SUDOERS_ADMIN_GROUP:-wheel}"
FTP_MODE="${FTP_MODE:-disable}"
TELNET_MODE="${TELNET_MODE:-disable}"
SSH_PORT="${SSH_PORT:-}"
SELINUX_MODE="${SELINUX_MODE:-}"
FIREWALL_MODE="${FIREWALL_MODE:-}"
FIREWALL_SERVICES="${FIREWALL_SERVICES:-}"
FIREWALL_PORTS="${FIREWALL_PORTS:-}"
RSYSLOG_REMOTE_SERVER="${RSYSLOG_REMOTE_SERVER:-}"
SKIP_ITEMS=""
ONLY_ITEMS=""

# ---------- load audit.conf if present ----------
AUDIT_CONF="$KISA_BASE/config/audit.conf"
if [[ -f "$AUDIT_CONF" ]]; then
    chmod 600 "$AUDIT_CONF"
    chown root:root "$AUDIT_CONF" 2>/dev/null || true
    # 1) syntax 사전 검증 (열린 따옴표/짝 안 맞는 괄호 등 catch).
    if ! bash -n "$AUDIT_CONF" 2>/tmp/.kisa_conf_err.$$; then
        log_error "audit.conf 문법 오류 — 따옴표/괄호 짝 확인 필요:"
        sed 's/^/  /' /tmp/.kisa_conf_err.$$ >&2
        rm -f /tmp/.kisa_conf_err.$$
        exit 2
    fi
    rm -f /tmp/.kisa_conf_err.$$
    # shellcheck disable=SC1090
    source "$AUDIT_CONF"
    _AUDIT_CONF_LOADED=1
else
    _AUDIT_CONF_LOADED=0
fi
export _AUDIT_CONF_LOADED

# 1.5) 숫자 단축 입력 정규화 — enable/disable 의미를 갖는 설정에 1/2 단축 허용.
#      1 = enable, 2 = disable. 빈값("")·기존 문자열값(yes/no/enforcing/keep 등)은 그대로.
#      (SSH_PORT 는 포트 숫자라 제외)
_kisa_norm_endis() {   # $1=변수명  $2=enable 값  $3=disable 값
    local _n="$1"
    case "${!_n:-}" in
        1) printf -v "$_n" '%s' "$2" ;;
        2) printf -v "$_n" '%s' "$3" ;;
    esac
}
_kisa_norm_endis SSH_PERMIT_ROOT_LOGIN "yes"       "no"
_kisa_norm_endis SELINUX_MODE          "enforcing" "disabled"
_kisa_norm_endis FIREWALL_MODE         "enable"    "disable"
_kisa_norm_endis FTP_MODE              "enable"    "disable"
_kisa_norm_endis TELNET_MODE           "enable"    "disable"

# 2) 의미 검증 (값 형식)
_validate_audit_conf() {
    if [[ -n "${ADMIN_USER:-}" ]]; then
        if [[ "$ADMIN_USER" == "root" ]]; then
            log_error "ADMIN_USER=root 금지 — root 외 sudo 가능 일반계정명 입력 (예: ops, admin)."
            exit 2
        fi
        if ! [[ "$ADMIN_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
            log_error "ADMIN_USER=\"$ADMIN_USER\" 형식 오류 — POSIX 계정명 규칙 위반 (소문자·숫자·_·- 만, 32자 이내)."
            exit 2
        fi
        # 신규 계정 생성 케이스 — 시스템에 계정 없으면 ADMIN_USER_PASSWORD 필수
        if ! id -u "$ADMIN_USER" >/dev/null 2>&1; then
            if [[ -z "${ADMIN_USER_PASSWORD:-}" ]]; then
                log_error "ADMIN_USER=\"$ADMIN_USER\" 계정이 시스템에 없음 — 신규 생성 시 ADMIN_USER_PASSWORD 필수 (빈값 거부)."
                exit 2
            fi
        fi
    fi
    if [[ -n "${SSH_PORT:-}" ]] && ! [[ "$SSH_PORT" =~ ^[0-9]+$ && "$SSH_PORT" -ge 1 && "$SSH_PORT" -le 65535 ]]; then
        log_error "SSH_PORT=\"$SSH_PORT\" 형식 오류 — 1~65535 정수 필요."
        exit 2
    fi
    if [[ -n "${SELINUX_MODE:-}" ]] && ! [[ "$SELINUX_MODE" =~ ^(enforcing|permissive|disabled)$ ]]; then
        log_error "SELINUX_MODE=\"$SELINUX_MODE\" 형식 오류 — enforcing|permissive|disabled 중 하나."
        exit 2
    fi
    if [[ -n "${FTP_MODE:-}" ]] && ! [[ "$FTP_MODE" =~ ^(disable|enable|keep)$ ]]; then
        log_error "FTP_MODE=\"$FTP_MODE\" 형식 오류 — disable|enable|keep 중 하나."
        exit 2
    fi
    if [[ -n "${TELNET_MODE:-}" ]] && ! [[ "$TELNET_MODE" =~ ^(disable|enable|keep)$ ]]; then
        log_error "TELNET_MODE=\"$TELNET_MODE\" 형식 오류 — disable|enable|keep 중 하나."
        exit 2
    fi
    if [[ -n "${SSH_PERMIT_ROOT_LOGIN:-}" ]] && ! [[ "$SSH_PERMIT_ROOT_LOGIN" =~ ^(no|yes|prohibit-password|forced-commands-only)$ ]]; then
        log_error "SSH_PERMIT_ROOT_LOGIN=\"$SSH_PERMIT_ROOT_LOGIN\" 형식 오류."
        exit 2
    fi
    if [[ -n "${FIREWALL_MODE:-}" ]] && ! [[ "$FIREWALL_MODE" =~ ^(enable|disable)$ ]]; then
        log_error "FIREWALL_MODE=\"$FIREWALL_MODE\" 형식 오류 — enable|disable|\"\"(빈값=유지) 중 하나."
        exit 2
    fi
}

# audit.conf 가 빈값으로 두거나 미설정이면 보안 디폴트 적용 (U-62 배너만 적용 — 미설정 = 노출)
# NTP_SERVERS / 그외는 빈값 그대로 두고 핸들러가 manual 처리.
if [[ -z "${LOGIN_BANNER_TEXT:-}" ]]; then
    LOGIN_BANNER_TEXT='***************************************************************
  [경고] 본 시스템은 인가된 사용자만 사용할 수 있습니다.
  모든 접속 및 행위는 기록·감시되며, 비인가 접근 시
  관련 법령에 따라 민·형사상 처벌될 수 있습니다.

  WARNING: Authorized access only. All activity is
  monitored and recorded. Unauthorized access will be
  prosecuted to the full extent of the law.
***************************************************************'
fi

# export for handlers
export PASSWORD_MIN_LEN PASSWORD_MAX_AGE PASSWORD_MIN_AGE PASSWORD_WARN_AGE
export LOGIN_MAX_RETRY LOGIN_LOCK_TIME SESSION_TIMEOUT UMASK_VALUE
export SSH_PERMIT_ROOT_LOGIN ADMIN_USER ADMIN_USER_PASSWORD ADMIN_USER_PUBKEY ALLOWED_HOSTS DENY_HOSTS
export NFS_ALLOWED_NETWORKS SNMP_ALLOWED_NETWORKS SNMP_COMMUNITY_ENV_VAR
export DNS_ZONE_ALLOW_TRANSFER LOGIN_BANNER_TEXT NTP_SERVERS SUDOERS_ADMIN_GROUP
export FTP_MODE TELNET_MODE
export SSH_PORT SELINUX_MODE FIREWALL_MODE FIREWALL_SERVICES FIREWALL_PORTS
export RSYSLOG_REMOTE_SERVER
# audit.conf 의 SNMP_COMMUNITY (example 표기) → KISA_SNMP_COMMUNITY (실제 핸들러 사용 변수) 매핑
export KISA_SNMP_COMMUNITY="${KISA_SNMP_COMMUNITY:-${SNMP_COMMUNITY:-}}"

# ---------- CLI parsing ----------
CMD="${1:-help}"; shift || true

while (( $# )); do
    case "$1" in
        --only)        shift; ONLY_ITEMS="${1:-}" ;;
        --skip)        shift; SKIP_ITEMS="${1:-}" ;;
        *)
            log_error "알 수 없는 인자: $1"
            exit 2
            ;;
    esac
    shift
done

# ---------- subcommands ----------
usage() {
    sed -n '3,28p' "$0" | sed 's/^# \{0,1\}//'
}

_list_handlers() {
    find "$KISA_BASE/lib/handlers" -maxdepth 1 \( -name 'U-*.sh' -o -name 'E-*.sh' \) -type f 2>/dev/null \
        | awk -F/ '{print $NF}' | sed 's/\.sh$//' | sort -V
}

_filter_codes() {
    local line
    while IFS= read -r line; do
        if [[ -n "$ONLY_ITEMS" ]]; then
            [[ ",$ONLY_ITEMS," == *",$line,"* ]] || continue
        fi
        if [[ -n "$SKIP_ITEMS" ]]; then
            [[ ",$SKIP_ITEMS," == *",$line,"* ]] && continue
        fi
        printf '%s\n' "$line"
    done
}

cmd_check_or_apply() {
    local mode="$1"   # check | apply
    export KISA_MODE="$mode"
    preflight_check
    detect_os
    acquire_lock
    init_run
    _validate_audit_conf

    log_info ""
    log_info "${C_BOLD}${C_CYAN}=== KISA 점검·조치 스크립트 v$(cat "$KISA_BASE/VERSION") ===${C_RESET}"
    log_info "  host        : $(hostname)"
    log_info "  OS          : $OS_PRETTY  (family=$OS_FAMILY)"
    log_info "  mode        : $mode"
    [[ "$mode" == "apply" ]] && log_info "  report      : $INVOCATION_DIR/report.html"
    if (( _AUDIT_CONF_LOADED == 1 )); then
        log_info "  audit.conf  : loaded ($AUDIT_CONF)"
    else
        die "audit.conf 없음 — 실행 거부.
       먼저 sample 파일을 audit.conf 로 복사한 뒤 정책값을 설정하세요:
         cp $KISA_BASE/config/audit.conf.example $AUDIT_CONF
       복사 후 $AUDIT_CONF 편집 → 다시 실행."
    fi
    log_info ""

    local codes
    mapfile -t codes < <(_list_handlers | _filter_codes)
    if (( ${#codes[@]} == 0 )); then
        die "실행할 handler 없음. lib/handlers/ 디렉터리에 U-XX.sh 파일이 있는지, --only/--skip 조건을 확인하세요."
    fi

    if [[ "$mode" == "check" ]]; then
        # check 는 읽기 전용 → 병렬 점검 후 결과를 코드 순서로 한꺼번에 출력
        run_handlers_parallel "${codes[@]}"
    else
        # apply 는 시스템 변경 경합·롤백 순서 안전을 위해 순차 실행 (병렬 금지)
        local code
        for code in "${codes[@]}"; do
            run_handler "$code" || true
        done
    fi

    render_report

    if [[ "$mode" == "apply" ]]; then
        log_info ""
        log_info "롤백이 필요하면: ${C_BOLD}$0 rollback${C_RESET}  (시스템 전수 *.kisa.bak 스캔 후 복원)"
    fi
}

cmd_rollback() {
    export KISA_MODE="rollback"
    preflight_check
    detect_os
    acquire_lock
    init_run
    rollback_run
}

case "$CMD" in
    check)       cmd_check_or_apply check ;;
    apply)       cmd_check_or_apply apply ;;
    rollback)    cmd_rollback ;;
    help|-h|--help|"") usage ;;
    *)           log_error "알 수 없는 명령: $CMD"; usage; exit 2 ;;
esac
