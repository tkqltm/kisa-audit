#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-58: 불필요한 SNMP 서비스 구동 점검 (중요도: 중)
# KISA 가이드: SNMP 서비스 사용 여부 점검, 불필요 시 비활성화.
#
# Rocky 8/9/10: net-snmp 패키지, 서비스명 snmpd.
#   SNMP_ALLOWED_NETWORKS 또는 KISA_SNMP_COMMUNITY 가 설정된 경우 → 사용 허가,
#   비활성화 생략 (U-59~U-61 조치 대상).
#   두 변수 모두 비어있으면 → snmpd disable+mask.
#
# 조치 전략:
#   1) net-snmp 미설치 → N/A
#   2) SNMP_ALLOWED_NETWORKS 또는 KISA_SNMP_COMMUNITY 비어있지 않으면 → 사용 허가 (skip)
#   3) 두 변수 모두 빈 값 → snmpd disable+mask
#
# 롤백 전략: systemctl_state 큐잉

h_U_58_meta() {
    cat <<'JSON'
{
  "code": "U-58",
  "title": "불필요한 SNMP 서비스 구동 점검",
  "severity": "중",
  "category": "서비스 관리",
  "purpose": "불필요한 SNMP 서비스를 비활성화하여 필요 이상의 정보가 노출되는 것을 방지하기 위함",
  "threat": "SNMP 서비스가 활성화되어 있을 경우, 비인가자가 시스템의 중요 정보를 유출하거나 불법적으로 수정할 위험이 존재함",
  "criterion_good": "SNMP 서비스를 사용하지 않는 경우",
  "criterion_bad": "SNMP 서비스를 사용하는 경우",
  "action_method": "SNMP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "SNMP 서비스 활성화 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-58 (2026 ver.)"
  ]
}
JSON
}

_u_58_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령:"
        echo "## net-snmp 패키지 설치 여부"
        rpm -q net-snmp 2>&1 || true
        echo
        echo "## SNMP 서비스 상태"
        for svc in snmpd snmptrapd; do
            printf '%-12s is-enabled=%s   is-active=%s\n' \
                "$svc" \
                "$(systemctl is-enabled "$svc" 2>&1)" \
                "$(systemctl is-active  "$svc" 2>&1)"
        done
        echo
        echo "## SNMP 사용 정책 (환경변수)"
        echo "KISA_SNMP_COMMUNITY  = ${KISA_SNMP_COMMUNITY:-(미설정)}"
        echo "SNMP_ALLOWED_NETWORKS= ${SNMP_ALLOWED_NETWORKS:-(미설정)}"
        echo
        echo "## SNMP 포트 LISTEN 상태"
        if command -v ss >/dev/null 2>&1; then
            ss -tulnp 2>/dev/null | grep -E ':(161|162)\b' || echo "(snmp/snmptrap 포트 LISTEN 없음)"
        fi
    } | _evidence_capture "$label"
}


_u58_netsnmp_installed() {
    rpm -q net-snmp >/dev/null 2>&1
}

_u58_snmpd_active() {
    systemctl is-active snmpd >/dev/null 2>&1
}

_u58_snmpd_enabled() {
    local st; st="$(systemctl is-enabled snmpd 2>/dev/null || printf 'disabled')"
    [[ "$st" == "enabled" || "$st" == "static" ]]
}

_u58_snmp_allowed() {
    # SNMP 사용이 허가된 환경인지 확인
    local community; community="${KISA_SNMP_COMMUNITY:-}"
    local networks;  networks="${SNMP_ALLOWED_NETWORKS:-}"
    [[ -n "$community" || -n "$networks" ]]
}

h_U_58_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_58_capture_state "$KISA_PHASE"
    fi

    if ! _u58_netsnmp_installed; then
        printf '양호 — net-snmp 미설치(SNMP 서비스 없음, 취약점 해당없음)'
        return 0
    fi

    if _u58_snmpd_active || _u58_snmpd_enabled; then
        if _u58_snmp_allowed; then
            printf '취약 — snmpd 구동 중 (SNMP 사용 허가 환경, U-59~61 조치 필요)'
            return 1
        fi
        printf '취약 — snmpd 서비스 구동 중 (불필요한 SNMP 서비스 활성화)'
        return 1
    fi

    local st; st="$(systemctl is-enabled snmpd 2>/dev/null || printf 'unknown')"
    printf '양호 — snmpd 비활성화 상태 (%s)' "$st"
    return 0
}

h_U_58_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        if ! _u58_netsnmp_installed; then
            printf '(dry-run) net-snmp 미설치, 조치 불필요(N/A)'
            return 0
        fi
        local rc; h_U_58_check >/dev/null 2>&1; rc=$?
        if (( rc == 0 )); then
            printf '(dry-run) 이미 양호, 조치 불필요'
        elif _u58_snmp_allowed; then
            printf '(dry-run) SNMP 사용 허가 환경 — snmpd 비활성화 생략, U-59~61 조치 진행'
        else
            printf '(dry-run) snmpd disable+mask 예정'
        fi
        return 0
    fi

    if ! _u58_netsnmp_installed; then
        printf '해당없음 — net-snmp 미설치(SNMP 서비스 없음)'
        return 3
    fi

    local rc; h_U_58_check >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then
        printf '양호 — 이미 snmpd 비활성화 상태, 조치 불필요'
        return 0
    fi

    if _u58_snmp_allowed; then
        printf '양호 — SNMP 사용 허가 환경(KISA_SNMP_COMMUNITY 또는 SNMP_ALLOWED_NETWORKS 설정됨)이라 snmpd 비활성화 생략; U-59~61 조치 적용 필요'
        return 0
    fi

    # snmpd disable+mask
    local cur_state
    cur_state="$(systemctl is-enabled snmpd 2>/dev/null || printf 'disabled')"
    if [[ "$cur_state" != "masked" ]]; then
        _queue_rollback systemctl_state "snmpd:${cur_state}"
        systemctl disable --now snmpd 2>/dev/null || true
        systemctl mask snmpd 2>/dev/null || true
    fi

    printf '조치 완료 — snmpd disable+mask 적용'
    return 0
}
