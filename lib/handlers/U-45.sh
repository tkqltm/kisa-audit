#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-45: 메일 서비스 버전 점검 (중요도: 상)
# KISA 가이드: 메일 서비스(postfix/sendmail/exim) 버전 확인 및 최신 패치 권고.
#
# Rocky 8/9/10: Postfix 기본 설치됨.
#   점검: postconf mail_version / sendmail -d0 -bt / exim -bV 버전 출력.
#   취약 여부: 정확한 취약 버전 기준 없음 → 버전 정보 제공 + 패치 권고.
#   메일 서비스 패치는 운영자 수동 안내 (audit.conf 자동 패치 변수 없음).
#   기본값 manual → 버전 출력 후 return 2 (manual).
#
# 조치 전략:
#   apply 는 항상 수동 패치 안내 (return 2). 운영자가 dnf update 직접 수행.
#
# 롤백: 패키지 업데이트이므로 파일 수준 rollback 없음.

h_U_45_meta() {
    cat <<'JSON'
{
  "code": "U-45",
  "title": "메일 서비스 버전 점검",
  "severity": "상",
  "category": "서비스 관리",
  "purpose": "메일 서비스 사용 목적 검토 및 취약점이 없는 버전의 사용 유무 점검으로 최적화된 메일 서비스의 운영하기 위함",
  "threat": "취약점이 발견된 메일 버전의 경우 버퍼 오버플로우(Buffer Overflow) 공격에 의한 시스템 권한 획득 및 주요 정보 노출의 위험이 존재함",
  "criterion_good": "메일 서비스 버전이 최신 버전인 경우",
  "criterion_bad": "메일 서비스 버전이 최신 버전이 아닌 경우",
  "action_method": "- 메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 - 메일 서비스 사용 시 패치 관리 정책을 수립하여 주기적으로 패치 적용 설정",
  "action_impact": "패치 적용 시 시스템 및 서비스의 영향 정도를 충분히 고려해야 함",
  "method": [
    "취약한 버전의 메일 서비스 이용 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-45 (2026 ver.)"
  ]
}
JSON
}

_u_45_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: 메일 서비스(postfix/sendmail/exim) 버전 확인"
        echo "## postfix"
        if command -v postconf >/dev/null 2>&1; then
            postconf mail_version 2>&1 | head -3 || true
            echo "is-enabled: $(systemctl is-enabled postfix 2>&1)"
            echo "is-active : $(systemctl is-active  postfix 2>&1)"
        else
            echo "(postfix 미설치)"
        fi
        echo
        echo "## sendmail"
        if command -v sendmail >/dev/null 2>&1; then
            sendmail -d0.4 -bt </dev/null 2>&1 | head -10 || true
        else
            echo "(sendmail 미설치)"
        fi
        echo
        echo "## exim"
        if command -v exim >/dev/null 2>&1; then
            exim -bV 2>&1 | head -3 || true
        else
            echo "(exim 미설치)"
        fi
        echo
        echo "## 패치 정책: 운영자 수동 조치 (audit.conf 자동 패치 변수 없음)"
    } | _evidence_capture "$label"
}


_u45_postfix_version() {
    postconf mail_version 2>/dev/null | awk '{print $NF}' || true
}
_u45_sendmail_version() {
    sendmail -d0 -bt </dev/null 2>/dev/null | awk '/Version/{print $2; exit}' || true
}
_u45_exim_version() {
    exim -bV 2>/dev/null | awk '/version/{print $NF; exit}' || true
}

_u45_mail_installed() {
    command -v postconf >/dev/null 2>&1 && return 0
    command -v sendmail >/dev/null 2>&1 && return 0
    command -v exim >/dev/null 2>&1 && return 0
    return 1
}

# 메일 서비스 실제 사용(active) 여부 — 설치돼 있어도 비활성이면 미사용으로 판단.
_u45_mail_active() {
    systemctl is-active --quiet postfix  2>/dev/null && return 0
    systemctl is-active --quiet sendmail 2>/dev/null && return 0
    systemctl is-active --quiet exim     2>/dev/null && return 0
    return 1
}

h_U_45_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_45_capture_state "$KISA_PHASE"
    fi

    if ! _u45_mail_installed; then
        printf '양호 — 메일 서비스(postfix/sendmail/exim) 미설치(취약점 해당없음)'
        return 0
    fi

    # 설치돼 있어도 비활성(미사용)이면 버전 점검 대상 아님 → 양호.
    # (KISA U-45 는 "사용 중인" 메일 서비스 버전 점검. 미사용 서비스는 위협 표면 없음)
    if ! _u45_mail_active; then
        printf '양호 — 메일 서비스 설치됐으나 비활성(미사용) — 버전 점검 대상 아님'
        return 0
    fi

    local info=""
    local pv sv ev
    pv="$(_u45_postfix_version)"
    sv="$(_u45_sendmail_version)"
    ev="$(_u45_exim_version)"

    [[ -n "$pv" ]] && info+="postfix-${pv} "
    [[ -n "$sv" ]] && info+="sendmail-${sv} "
    [[ -n "$ev" ]] && info+="exim-${ev} "

    if [[ -z "$info" ]]; then
        printf '메일 서비스 버전 확인 불가'
        return 2
    fi

    # 메일 서비스 버전 자동 패치는 운영자 정책 영역 — 항상 manual 안내.
    printf '취약 — 메일 서비스 설치됨(현재 버전: %s) 운영자 주기적 패치 권고 (수동 조치)' "${info}"
    return 1
}

h_U_45_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        local rc; h_U_45_check >/dev/null 2>&1; rc=$?
        case $rc in
            3) printf '(dry-run) 메일 서비스 미설치, 조치 불필요(N/A)' ;;
            *) printf '(dry-run) 메일 서비스 패치는 수동 안내 — 운영자가 dnf update 직접 수행' ;;
        esac
        return 0
    fi

    local rc; h_U_45_check >/dev/null 2>&1; rc=$?
    if (( rc == 3 )); then printf '해당없음 — 메일 서비스(postfix/sendmail/exim) 미설치'; return 3; fi
    if (( rc == 0 )); then printf '양호 — 이미 패치 관리 설정 양호'; return 0; fi

    local pv; pv="$(_u45_postfix_version)"
    log_warn "U-45: 현재 postfix 버전: ${pv:-확인불가}"
    log_warn "  최신 버전 확인: https://www.postfix.org/packages.html"
    log_warn "  패치 명령: dnf update postfix"
    printf '수동 조치 필요 — 메일 서비스 버전 수동 패치 (현재: postfix-%s)\n조치: 운영자가 dnf update postfix 직접 수행' "${pv:-확인불가}"
    return 2
}
