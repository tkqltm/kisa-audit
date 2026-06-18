#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-59: 안전한 SNMP 버전 사용 (중요도: 상)
# KISA 가이드: SNMPv3 강제, v1/v2c 설정 제거.
#
# Rocky 8/9/10: /etc/snmp/snmpd.conf 에서
#   - rocommunity / rwcommunity / com2sec 설정 → v1/v2c 사용 → 취약
#   - rouser / rwuser (v3) 설정 + v1/v2c 제거 → 양호
#   net-snmp 미설치 시 N/A.
#   snmpd 비활성화 상태면 N/A (U-58 에서 처리).
#
# 조치 전략 (drop-in 방식):
#   /etc/snmp/snmpd.d/kisa-v3.conf 생성:
#     - v1/v2c community 지시어 주석화 (snmpd.conf 에서)
#     - SNMPv3 user 가 없으면 manual (사용자 이름·암호는 관리자 설정 필요)
#   /etc/snmp/snmpd.conf 에 v1/v2c 라인 주석 처리
#   snmpd restart 큐잉
#
# 롤백 전략: /etc/snmp/snmpd.conf restore_file + snmpd restart

h_U_59_meta() {
    cat <<'JSON'
{
  "code": "U-59",
  "title": "안전한 SNMP 버전 사용",
  "severity": "상",
  "category": "서비스 관리",
  "purpose": "안전한 SNMP 버전 사용으로 전송되는 데이터를 보호하기 위함",
  "threat": "SNMP 버전이 기준보다 낮을 경우, 응답 패킷이 평문으로 전송되어 스니핑 위험이 존재함",
  "criterion_good": "SNMP 서비스를 v3 이상으로 사용하는 경우",
  "criterion_bad": "SNMP 서비스를 v2 이하로 사용하는 경우",
  "action_method": "- SNMP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 - SNMP 서비스 사용 시 SNMP 버전을 v3 이상으로 적용하도록 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "안전한 SNMP 버전 사용 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-59 (2026 ver.)"
  ]
}
JSON
}

_u_59_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: SNMP community string 'public'/'private' 사용 여부"
        echo
        echo "## /etc/snmp/snmpd.conf 의 community string 라인 (com2sec/rocommunity/rwcommunity)"
        if [[ -f /etc/snmp/snmpd.conf ]]; then
            _dump_path "/etc/snmp/snmpd.conf" "^[[:space:]]*(com2sec|rocommunity|rwcommunity|com2sec6|rocommunity6|rwcommunity6)[[:space:]]+"
        else
            echo "(/etc/snmp/snmpd.conf 없음)"
        fi
        echo
        echo "## /etc/snmp/snmpd.d/ 드롭인 파일 community 라인"
        if [[ -d /etc/snmp/snmpd.d ]]; then
            local _f _had=0
            for _f in /etc/snmp/snmpd.d/*.conf; do
                [[ -f "$_f" ]] || continue
                _had=1
                echo "### $_f"
                grep -nE '^[[:space:]]*(com2sec|rocommunity|rwcommunity|com2sec6|rocommunity6|rwcommunity6)[[:space:]]+' "$_f" 2>/dev/null || echo "(community 라인 없음)"
            done
            (( _had == 0 )) && echo "(*.conf 파일 없음)"
        else
            echo "(/etc/snmp/snmpd.d 디렉터리 없음)"
        fi
        echo
        echo "## net-snmp 설치 + 서비스 상태"
        rpm -q net-snmp 2>&1 || true
        echo "is-enabled snmpd: $(systemctl is-enabled snmpd 2>&1)"
        echo "is-active  snmpd: $(systemctl is-active  snmpd 2>&1)"
    } | _evidence_capture "$label"
}


_u59_snmpd_conf()  { printf '/etc/snmp/snmpd.conf'; }
_u59_snmpd_dropin_dir() { printf '/etc/snmp/snmpd.d'; }

_u59_netsnmp_installed() {
    rpm -q net-snmp >/dev/null 2>&1
}

_u59_snmpd_active_or_enabled() {
    systemctl is-active snmpd >/dev/null 2>&1 \
        || [[ "$(systemctl is-enabled snmpd 2>/dev/null)" == "enabled" ]]
}

# v1/v2c community 설정 존재 여부
_u59_v12c_present() {
    local cf; cf="$(_u59_snmpd_conf)"
    [[ -r "$cf" ]] || return 1
    grep -qE '^[[:space:]]*(rocommunity6?|rwcommunity6?|com2sec6?)[[:space:]]' "$cf"
}

# v3 user 설정 존재 여부
_u59_v3_present() {
    local cf; cf="$(_u59_snmpd_conf)"
    [[ -r "$cf" ]] || return 1
    grep -qE '^[[:space:]]*(rouser|rwuser|createUser)[[:space:]]' "$cf"
}

h_U_59_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_59_capture_state "$KISA_PHASE"
    fi

    if ! _u59_netsnmp_installed; then
        printf '양호 — net-snmp 미설치(SNMP 서비스 없음, 취약점 해당없음)'
        return 0
    fi

    if ! _u59_snmpd_active_or_enabled; then
        printf '양호 — snmpd 비활성화(SNMP 미사용, 취약점 해당없음)'
        return 0
    fi

    local cf; cf="$(_u59_snmpd_conf)"
    if [[ ! -r "$cf" ]]; then
        printf 'snmpd.conf 읽기 실패: %s' "$cf"
        return 2
    fi

    local v12c=0 v3=0
    _u59_v12c_present && v12c=1
    _u59_v3_present   && v3=1

    if (( v12c == 1 )); then
        printf '취약 — SNMPv1/v2c community 설정 존재(평문 인증 사용 중)'
        return 1
    fi

    if (( v3 == 0 )); then
        printf '취약 — SNMPv3 사용자 설정 없음'
        return 1
    fi

    printf '양호 — SNMPv3 설정됨, v1/v2c community 없음'
    return 0
}

h_U_59_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        if ! _u59_netsnmp_installed; then
            printf '(dry-run) net-snmp 미설치, 조치 불필요(N/A)'
            return 0
        fi
        if ! _u59_snmpd_active_or_enabled; then
            printf '(dry-run) snmpd 비활성화 상태, 조치 불필요(N/A)'
            return 0
        fi
        printf '(dry-run) snmpd.conf v1/v2c community 주석 처리 예정; SNMPv3 미설정 시 manual 안내'
        return 0
    fi

    if ! _u59_netsnmp_installed; then
        printf '해당없음 — net-snmp 미설치(SNMP 서비스 없음)'
        return 3
    fi

    if ! _u59_snmpd_active_or_enabled; then
        printf '해당없음 — snmpd 비활성화 상태(SNMP 미사용)'
        return 3
    fi

    local rc; h_U_59_check >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then
        printf '양호 — 이미 양호 상태(SNMPv3 설정, v1/v2c community 없음)'
        return 0
    fi

    local cf; cf="$(_u59_snmpd_conf)"
    if [[ ! -f "$cf" ]]; then
        printf '조치 실패 — snmpd.conf 없음: %s' "$cf"
        return 1
    fi

    backup_file "$cf"

    local tmp; tmp="${KISA_TMP_DIR}/tmp/u59.$$.${RANDOM}"
    mkdir -p "${KISA_TMP_DIR}/tmp"

    # v1/v2c community 라인 주석 처리 (IPv6 변형 com2sec6/rocommunity6/rwcommunity6 포함)
    awk '
        /^[[:space:]]*(rocommunity6?|rwcommunity6?|com2sec6?)[[:space:]]/ {
            print "# [KISA U-59] " $0
            next
        }
        { print }
    ' "$cf" > "$tmp"

    local om ou og
    om=$(stat -c '%a' "$cf" 2>/dev/null || printf '600')
    ou=$(stat -c '%u' "$cf" 2>/dev/null || printf '0')
    og=$(stat -c '%g' "$cf" 2>/dev/null || printf '0')
    mv -f "$tmp" "$cf"
    chmod "$om" "$cf" 2>/dev/null || true
    chown "$ou:$og" "$cf" 2>/dev/null || true
    command -v restorecon >/dev/null 2>&1 && restorecon "$cf" 2>/dev/null || true

    _queue_service_op restart snmpd
    _queue_rollback   systemctl_restart snmpd

    if ! _u59_v3_present; then
        printf '수동 조치 필요 — v1/v2c community 주석 처리 완료, SNMPv3 사용자 수동 설정 필요\n조치: net-snmp-create-v3-user -ro -A <인증암호> -X <암호화암호> -a SHA -x AES <사용자명> 실행 후 snmpd 재시작'
        return 2
    fi

    printf '조치 완료 — v1/v2c community 주석 처리, SNMPv3 설정 유지, snmpd restart 지연'
    return 0
}
