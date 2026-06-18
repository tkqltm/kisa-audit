#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-61: SNMP Access Control 설정 (중요도: 상)
# KISA 가이드: SNMP 접근을 허가된 네트워크/호스트로만 제한.
#
# Rocky 8/9/10: /etc/snmp/snmpd.conf 의 com2sec 지시어에서
#   'default' 대신 허용 네트워크 주소 명시.
#   SNMP_ALLOWED_NETWORKS 환경변수 (콤마 구분 IP/CIDR 목록).
#   빈 값이면 → manual 안내.
#   net-snmp 미설치 또는 snmpd 비활성 → N/A.
#
# 조치 전략:
#   SNMP_ALLOWED_NETWORKS 비어있으면 → return 2 (manual)
#   있으면 → com2sec default → 허용 네트워크로 교체 (여러 네트워크면 multiple com2sec 라인)
#   snmpd restart 큐잉
#
# 롤백 전략: /etc/snmp/snmpd.conf restore_file + snmpd restart

h_U_61_meta() {
    cat <<'JSON'
{
  "code": "U-61",
  "title": "SNMP Access Control 설정",
  "severity": "상",
  "category": "서비스 관리",
  "purpose": "SNMP 접근 제어 설정을 통해 비인가자의 접근을 차단하기 위함",
  "threat": "SNMP 서비스에 접근 제어가 설정되어 있지 않을 경우, 비인가자의 접근, 네트워크 정보 유출, 시스템 및 네트워크 설정 변경, DoS 공격 등의 위험이 존재함",
  "criterion_good": "SNMP 서비스에 접근 제어 설정이 되어 있는 경우",
  "criterion_bad": "SNMP 서비스에 접근 제어 설정이 되어 있지 않은 경우",
  "action_method": "- SNMP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 - SNMP 서비스 사용 시 SNMP 접근 제어 설정하도록 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "SNMP 접근 제어 설정 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-61 (2026 ver.)"
  ]
}
JSON
}

_u_61_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: SNMP 접근 제어 (com2sec 의 source 부분)"
        echo
        echo "## /etc/snmp/snmpd.conf 의 com2sec/rocommunity/rwcommunity 라인"
        if [[ -f /etc/snmp/snmpd.conf ]]; then
            _dump_path "/etc/snmp/snmpd.conf" "^[[:space:]]*(com2sec|rocommunity|rwcommunity|com2sec6|rocommunity6|rwcommunity6)[[:space:]]+"
        else
            echo "(/etc/snmp/snmpd.conf 없음)"
        fi
        echo
        echo "## net-snmp 설치 + 서비스 상태"
        rpm -q net-snmp 2>&1 || true
        echo "is-enabled snmpd: $(systemctl is-enabled snmpd 2>&1)"
        echo "is-active  snmpd: $(systemctl is-active  snmpd 2>&1)"
        echo
        echo "## 환경변수: SNMP_ALLOWED_NETWORKS=${SNMP_ALLOWED_NETWORKS:-(미설정 — manual)}"
    } | _evidence_capture "$label"
}


_u61_snmpd_conf() { printf '/etc/snmp/snmpd.conf'; }

_u61_netsnmp_installed() {
    rpm -q net-snmp >/dev/null 2>&1
}

_u61_snmpd_active_or_enabled() {
    systemctl is-active snmpd >/dev/null 2>&1 \
        || [[ "$(systemctl is-enabled snmpd 2>/dev/null)" == "enabled" ]]
}

_u61_v12c_present() {
    local cf; cf="$(_u61_snmpd_conf)"
    [[ -r "$cf" ]] || return 1
    grep -qE '^[[:space:]]*(rocommunity|rwcommunity|com2sec)[[:space:]]' "$cf"
}

# 접근 제어 현황 확인: default 가 있으면 취약
_u61_has_default_access() {
    local cf; cf="$(_u61_snmpd_conf)"
    [[ -r "$cf" ]] || return 1
    # com2sec ... default ... 또는 rocommunity <string> (source 생략 = default)
    grep -qE '^[[:space:]]*com2sec[[:space:]].*[[:space:]]default[[:space:]]' "$cf" && return 0
    grep -qE '^[[:space:]]*(rocommunity|rwcommunity)[[:space:]][^[:space:]]+[[:space:]]*$' "$cf" && return 0
    return 1
}

h_U_61_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_61_capture_state "$KISA_PHASE"
    fi

    if ! _u61_netsnmp_installed; then
        printf '양호 — net-snmp 미설치(SNMP 서비스 없음, 취약점 해당없음)'
        return 0
    fi

    if ! _u61_snmpd_active_or_enabled; then
        printf '양호 — snmpd 비활성화(SNMP 미사용, 취약점 해당없음)'
        return 0
    fi

    if ! _u61_v12c_present; then
        # 사용자가 audit.conf 에 community + networks 둘 다 명시했으면 → 취약 판정 (apply 가 신규 라인 생성)
        if [[ -n "${SNMP_ALLOWED_NETWORKS:-}" && -n "${KISA_SNMP_COMMUNITY:-}" ]]; then
            printf '취약 — snmpd 활성·v1/v2c community 미설정이나 audit.conf 에 SNMP_ALLOWED_NETWORKS+KISA_SNMP_COMMUNITY 명시됨(신규 라인 추가 필요)'
            return 1
        fi
        printf '양호 — v1/v2c community 미설정(SNMPv3 전용 환경, v1/v2c Access Control 취약점 해당없음)'
        return 0
    fi

    local cf; cf="$(_u61_snmpd_conf)"
    if [[ ! -r "$cf" ]]; then
        printf 'snmpd.conf 읽기 실패'
        return 2
    fi

    if _u61_has_default_access; then
        printf '취약 — com2sec/rocommunity 에 "default" 소스 설정(모든 호스트 접근 허용)'
        return 1
    fi

    # default 없고 특정 네트워크 명시됐는지 확인 (com2sec 또는 rocommunity/rwcommunity 둘 다 검사)
    if grep -qE '^[[:space:]]*com2sec[[:space:]]' "$cf"; then
        local src
        src=$(grep -E '^[[:space:]]*com2sec[[:space:]]' "$cf" | awk '{print $(NF-1)}' | head -1)
        printf '양호 — com2sec 소스 제한됨: %s' "$src"
        return 0
    fi
    # rocommunity <comm> <source>  (source 가 마지막 토큰, 위 _u61_has_default_access 가 default 케이스 잡음)
    if grep -qE '^[[:space:]]*(rocommunity|rwcommunity)[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+' "$cf"; then
        local src
        src=$(grep -E '^[[:space:]]*(rocommunity|rwcommunity)[[:space:]]' "$cf" | awk '{print $NF}' | head -1)
        printf '양호 — rocommunity 소스 제한됨: %s' "$src"
        return 0
    fi

    printf '취약 — SNMP 접근 제어 설정 확인 필요(허용 소스 미명시)'
    return 1
}

h_U_61_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        if ! _u61_netsnmp_installed || ! _u61_snmpd_active_or_enabled || ! _u61_v12c_present; then
            printf '(dry-run) SNMP v1/v2c 미사용 또는 미설치, 조치 불필요(N/A)'
            return 0
        fi
        local nets; nets="${SNMP_ALLOWED_NETWORKS:-}"
        if [[ -z "$nets" ]]; then
            printf '(dry-run) SNMP_ALLOWED_NETWORKS 미설정 — 수동 조치 필요(manual)'
        else
            printf '(dry-run) com2sec 소스를 "%s" 로 제한 예정; snmpd restart 지연' "$nets"
        fi
        return 0
    fi

    if ! _u61_netsnmp_installed; then
        printf '해당없음 — net-snmp 미설치(SNMP 서비스 없음)'
        return 3
    fi

    if ! _u61_snmpd_active_or_enabled; then
        printf '해당없음 — snmpd 비활성화 상태(SNMP 미사용)'
        return 3
    fi

    local nets; nets="${SNMP_ALLOWED_NETWORKS:-}"
    local community; community="${KISA_SNMP_COMMUNITY:-}"

    # v1/v2c community 라인 자체가 없는 경우:
    # - 사용자가 SNMP_ALLOWED_NETWORKS + KISA_SNMP_COMMUNITY 둘 다 명시하면 신규 라인 생성
    # - 그 외엔 SNMPv3 전용 환경으로 간주 (해당없음)
    if ! _u61_v12c_present; then
        if [[ -n "$nets" && -n "$community" ]]; then
            local cf; cf="$(_u61_snmpd_conf)"
            backup_file "$cf"
            local first_net
            first_net="$(printf '%s' "$nets" | cut -d',' -f1 | tr -d ' ')"
            {
                printf '\n# [KISA U-61] managed — admin-supplied community + access network\n'
                local n
                IFS=',' read -r -a _arr <<< "$nets"
                for n in "${_arr[@]}"; do
                    n="${n// /}"
                    [[ -z "$n" ]] && continue
                    printf 'rocommunity %s %s\n' "$community" "$n"
                done
            } >> "$cf"
            _queue_service_op restart snmpd
            _queue_rollback   systemctl_restart snmpd
            printf '조치 완료 — rocommunity 신규 추가(community="%s", networks="%s"); snmpd restart 지연' "$community" "$nets"
            return 0
        fi
        printf '해당없음 — v1/v2c community 미설정(SNMPv3 전용 환경)'
        return 3
    fi

    local rc; h_U_61_check >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then
        printf '양호 — 이미 SNMP 접근 제어가 설정된 상태'
        return 0
    fi

    if [[ -z "$nets" ]]; then
        printf '수동 조치 필요 — SNMP_ALLOWED_NETWORKS 환경변수 미설정\n조치: 허용할 NMS 서버 IP/네트워크 대역(콤마 구분)을 SNMP_ALLOWED_NETWORKS 에 설정 후 재실행. 예: SNMP_ALLOWED_NETWORKS=192.168.1.0/24,192.168.2.100'
        return 2
    fi

    local cf; cf="$(_u61_snmpd_conf)"
    backup_file "$cf"

    local tmp; tmp="${KISA_TMP_DIR}/tmp/u61.$$.${RANDOM}"
    mkdir -p "${KISA_TMP_DIR}/tmp"

    # 다중 네트워크 지원: 첫 번째 네트워크는 기존 com2sec default 라인 교체,
    # 나머지는 동일 라인을 복제하여 source 만 변경한 새 com2sec 라인 추가.
    local first_net rest_nets
    first_net="$(printf '%s' "$nets" | cut -d',' -f1 | tr -d ' ')"
    rest_nets="$(printf '%s' "$nets" | cut -d',' -f2- -s | tr -d ' ')"

    awk -v first_net="$first_net" -v rest_nets="$rest_nets" '
        /^[[:space:]]*com2sec[[:space:]].*[[:space:]]default[[:space:]]/ && !replaced {
            orig = $0
            sub(/[[:space:]]default[[:space:]]/, " " first_net " ")
            print
            if (rest_nets != "") {
                n = split(rest_nets, arr, ",")
                for (i=1; i<=n; i++) {
                    if (arr[i] != "") {
                        new_line = orig
                        sub(/[[:space:]]default[[:space:]]/, " " arr[i] " ", new_line)
                        print new_line
                    }
                }
            }
            replaced = 1
            next
        }
        /^[[:space:]]*(rocommunity|rwcommunity)[[:space:]][^[:space:]]+[[:space:]]*$/ {
            $0 = $0 " " first_net
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

    printf '조치 완료 — com2sec 소스를 "%s" 로 제한; snmpd restart 지연' "$nets"
    return 0
}
