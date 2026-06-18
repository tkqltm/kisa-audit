#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-60: SNMP Community String 복잡성 설정 (중요도: 중)
# KISA 가이드: Community String 기본값(public/private) 사용 금지,
#   복잡도 기준: 영문+숫자 10자 이상 또는 영문+숫자+특수문자 8자 이상.
#
# Rocky 8/9/10: /etc/snmp/snmpd.conf 의 com2sec 지시어.
#   KISA_SNMP_COMMUNITY 환경변수로 신규 Community String 전달.
#   변수 미설정(빈 값) → manual 안내.
#   net-snmp 미설치 또는 snmpd 비활성 → N/A.
#   SNMPv3 전용 환경(v1/v2c 없음) → N/A (U-59 에서 처리).
#
# 조치 전략:
#   KISA_SNMP_COMMUNITY 비어있으면 → return 2 (manual)
#   있으면 → com2sec 라인의 community string 교체
#            snmpd restart 큐잉
#
# 롤백 전략: /etc/snmp/snmpd.conf restore_file + snmpd restart

h_U_60_meta() {
    cat <<'JSON'
{
  "code": "U-60",
  "title": "SNMP Community String 복잡성 설정",
  "severity": "중",
  "category": "서비스 관리",
  "purpose": "SNMP 서비스의 Community String의 복잡성 설정을 통해 비인가자의 비밀번호 추측 공격에 대비하기 위함",
  "threat": "Community String에 복잡성 설정이 되어 있지 않을 경우, 비인가자가 비밀번호 추측 공격을 통해 계정 탈취 시 환경설정 파일 열람 및 수정, 각종 정보수집, 관리자 권한 획득 등 다양한 위험이 존재함",
  "criterion_good": "SNMP Community String 기본값인 “public”, “private”이 아닌 영문자, 숫자 포함 10자리 이상 또는 영문자, 숫자, 특수문자 포함 8자리 이상인 경우 ※ SNMP v3의 경우 별도 인증 기능을 사용하고, 해당 비밀번호가 복잡도를 만족하는 경우 양호",
  "criterion_bad": "아래의 내용 중 하나라도 해당되는 경우 1. SNMP Community String 기본값인 “public”, “private”일 경우 2. 영문자, 숫자 포함 10자리 미만인 경우 3. 영문자, 숫자, 특수문자 포함 8자리 미만인 경우",
  "action_method": "- SNMP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 - SNMP 서비스 사용 시 SNMP Community String 기본값인 “public”, “private”이 아닌 영문자, 숫자 포함 10자리 이상 또는 영문자, 숫자, 특수문자 포함 8자리 이상으로 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "SNMP Community String 복잡성 설정 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-60 (2026 ver.)"
  ]
}
JSON
}

_u_60_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: SNMP Community String 복잡성"
        echo
        echo "## /etc/snmp/snmpd.conf community 라인"
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
        echo "## 환경변수: KISA_SNMP_COMMUNITY=${KISA_SNMP_COMMUNITY:-(미설정 — manual)}"
    } | _evidence_capture "$label"
}


_u60_snmpd_conf() { printf '/etc/snmp/snmpd.conf'; }

_u60_netsnmp_installed() {
    rpm -q net-snmp >/dev/null 2>&1
}

_u60_snmpd_active_or_enabled() {
    systemctl is-active snmpd >/dev/null 2>&1 \
        || [[ "$(systemctl is-enabled snmpd 2>/dev/null)" == "enabled" ]]
}

# v1/v2c community 사용 여부
_u60_v12c_present() {
    local cf; cf="$(_u60_snmpd_conf)"
    [[ -r "$cf" ]] || return 1
    grep -qE '^[[:space:]]*(rocommunity6?|rwcommunity6?|com2sec6?)[[:space:]]' "$cf"
}

# 현재 community string 추출 (com2sec → 마지막 필드, rocommunity/rwcommunity → 두 번째 필드)
_u60_current_community() {
    local cf; cf="$(_u60_snmpd_conf)"
    [[ -r "$cf" ]] || { printf ''; return; }
    awk '
        /^[[:space:]]*com2sec6?[[:space:]]/                   { print $NF; exit }
        /^[[:space:]]*(rocommunity6?|rwcommunity6?)[[:space:]]/ { print $2; exit }
    ' "$cf"
}

# 복잡도 검사: 0=OK, 1=취약
_u60_complexity_ok() {
    local s="$1"
    [[ -z "$s" ]] && return 1
    # public/private
    [[ "$s" == "public" || "$s" == "private" ]] && return 1
    local len=${#s}
    # 영문+숫자+특수문자 8자 이상
    if (( len >= 8 )); then
        if printf '%s' "$s" | grep -qP '[A-Za-z]' 2>/dev/null \
           && printf '%s' "$s" | grep -qP '[0-9]' 2>/dev/null \
           && printf '%s' "$s" | grep -qP '[^A-Za-z0-9]' 2>/dev/null; then
            return 0
        fi
    fi
    # 영문+숫자 10자 이상
    if (( len >= 10 )); then
        if printf '%s' "$s" | grep -qP '[A-Za-z]' 2>/dev/null \
           && printf '%s' "$s" | grep -qP '[0-9]' 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

h_U_60_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_60_capture_state "$KISA_PHASE"
    fi

    if ! _u60_netsnmp_installed; then
        printf '양호 — net-snmp 미설치(SNMP 서비스 없음, 취약점 해당없음)'
        return 0
    fi

    if ! _u60_snmpd_active_or_enabled; then
        printf '양호 — snmpd 비활성화(SNMP 미사용, 취약점 해당없음)'
        return 0
    fi

    if ! _u60_v12c_present; then
        printf '양호 — v1/v2c community 미설정(SNMPv3 전용 환경, Community String 취약점 해당없음)'
        return 0
    fi

    local cur; cur="$(_u60_current_community)"
    if [[ -z "$cur" ]]; then
        printf '수동 조치 필요 — com2sec community string 파악 불가'
        return 2
    fi

    if _u60_complexity_ok "$cur"; then
        printf '양호 — Community String 복잡도 기준 충족'
        return 0
    fi

    printf '취약 — Community String "%s" 복잡도 기준 미충족(기본값 또는 단순값)' "$cur"
    return 1
}

h_U_60_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        if ! _u60_netsnmp_installed || ! _u60_snmpd_active_or_enabled || ! _u60_v12c_present; then
            printf '(dry-run) SNMP v1/v2c 미사용 또는 미설치, 조치 불필요(N/A)'
            return 0
        fi
        local new_cs; new_cs="${KISA_SNMP_COMMUNITY:-}"
        if [[ -z "$new_cs" ]]; then
            printf '(dry-run) KISA_SNMP_COMMUNITY 미설정 — 수동 조치 필요(manual)'
        else
            printf '(dry-run) snmpd.conf com2sec community string 교체 예정; snmpd restart 지연'
        fi
        return 0
    fi

    if ! _u60_netsnmp_installed; then
        printf '해당없음 — net-snmp 미설치(SNMP 서비스 없음)'
        return 3
    fi

    if ! _u60_snmpd_active_or_enabled; then
        printf '해당없음 — snmpd 비활성화 상태(SNMP 미사용)'
        return 3
    fi

    if ! _u60_v12c_present; then
        printf '해당없음 — v1/v2c community 미설정(SNMPv3 전용 환경)'
        return 3
    fi

    local rc; h_U_60_check >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then
        printf '양호 — 이미 Community String 복잡도 기준 충족'
        return 0
    fi

    local new_cs; new_cs="${KISA_SNMP_COMMUNITY:-}"
    if [[ -z "$new_cs" ]]; then
        printf '수동 조치 필요 — KISA_SNMP_COMMUNITY 환경변수 미설정\n조치: 복잡한 Community String 설정 후 재실행(영문+숫자+특수문자 8자 이상 또는 영문+숫자 10자 이상, public/private 금지)'
        return 2
    fi

    if ! _u60_complexity_ok "$new_cs"; then
        printf '조치 실패 — KISA_SNMP_COMMUNITY 값이 복잡도 기준 미충족(영문+숫자+특수문자 8자 이상 또는 영문+숫자 10자 이상 필요)'
        return 1
    fi

    local cf; cf="$(_u60_snmpd_conf)"
    backup_file "$cf"

    local tmp; tmp="${KISA_TMP_DIR}/tmp/u60.$$.${RANDOM}"
    mkdir -p "${KISA_TMP_DIR}/tmp"

    # com2sec 라인에서 마지막 필드(community string) 교체
    awk -v newcs="$new_cs" '
        /^[[:space:]]*com2sec[[:space:]]/ {
            # com2sec <name> <source> <community>
            n = split($0, a, /[[:space:]]+/)
            if (n >= 4) {
                a[n] = newcs
                line = a[1]
                for (i=2; i<=n; i++) line = line " " a[i]
                print line
                next
            }
        }
        # rocommunity/rwcommunity <community> [source]
        /^[[:space:]]*(rocommunity|rwcommunity)[[:space:]]/ {
            # replace second field
            $2 = newcs
            print
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

    printf '조치 완료 — Community String 교체; snmpd restart 큐잉'
    return 0
}
