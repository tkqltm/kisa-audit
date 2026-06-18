#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-50: DNS Zone Transfer 설정 (중요도: 상)
# KISA 가이드: Secondary Name Server 에만 Zone Transfer 허용.
#
# Rocky 8/9/10: BIND 9 기반, /etc/named.conf 의 options 블록 및 zone 블록에
#   allow-transfer { <허용IP>; }; 설정.
#   bind 미설치 시 해당없음(N/A).
#   DNS_ZONE_ALLOW_TRANSFER 환경변수(기본값 none) 사용.
#     "none" → allow-transfer { none; };
#     IP/CIDR 목록(콤마 구분) → 해당 주소만 허용
#
# 조치 전략:
#   1) bind 미설치 → N/A
#   2) named.conf 에 allow-transfer { any; }; 또는 미설정이면 취약
#   3) options 블록에 allow-transfer 설정 (named-checkconf 검증 후 적용)
#   4) named restart 큐잉
#
# 롤백 전략: /etc/named.conf restore_file + named restart

h_U_50_meta() {
    cat <<'JSON'
{
  "code": "U-50",
  "title": "DNS ZoneTransfer 설정",
  "severity": "상",
  "category": "서비스 관리",
  "purpose": "DNS Zone Transfer 설정을 통해 비인가자에 대한 무단 접근을 방지하기 위함",
  "threat": "Zone Transfer를 모든 사용자에게 허용할 경우, 비인가자에게 호스트 정보, 시스템 정보 등 중요 정보가 유출될 위험이 존재함",
  "criterion_good": "Zone Transfer를 허가된 사용자에게만 허용한 경우",
  "criterion_bad": "Zone Transfer를 모든 사용자에게 허용한 경우",
  "action_method": "- DNS 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 - DNS 서비스 사용 시 DNS Zone Transfer를 허가된 사용자에게만 전송 허용하도록 설정",
  "action_impact": "Zone Transfer 설정에서 허용할 대상을 정상적으로 등록하였다면 일반적으로 영향 없음",
  "method": [
    "Secondary Name Server로만 Zone 정보 전송 제한 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-50 (2026 ver.)"
  ]
}
JSON
}

_u_50_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: bind 설치 여부 + named.conf 의 allow-transfer 설정 확인"
        echo "## rpm -q bind"
        rpm -q bind 2>&1 || true
        echo
        echo "## named 서비스 상태"
        echo "is-enabled named: $(systemctl is-enabled named 2>&1)"
        echo "is-active  named: $(systemctl is-active  named 2>&1)"
        echo
        echo "## allow-transfer 설정 추출"
        if [[ -r /etc/named.conf ]]; then
            grep -nE 'allow-transfer' /etc/named.conf 2>/dev/null || echo "(설정 없음 — KISA 기본은 default any)"
        else
            echo "(/etc/named.conf 읽기 불가)"
        fi
    } | _evidence_capture "$label"
}


_u50_named_conf() { printf '/etc/named.conf'; }

_u50_bind_installed() {
    rpm -q bind >/dev/null 2>&1
}

# named.conf 에서 options 블록 내 allow-transfer 값 추출
# echo: none | any | <ip list> | ""(absent)
_u50_current_transfer() {
    local cf; cf="$(_u50_named_conf)"
    [[ -r "$cf" ]] || { printf ''; return; }
    # 단순 grep — options 블록 밖 zone 블록의 값도 감지
    local val
    val=$(grep -E '[[:space:]]*allow-transfer[[:space:]]*\{' "$cf" \
          | head -1 \
          | sed 's/.*allow-transfer[[:space:]]*{[[:space:]]*//' \
          | sed 's/[[:space:]]*};.*//' \
          | tr -d ' ')
    printf '%s' "$val"
}

_u50_is_ok() {
    local cf; cf="$(_u50_named_conf)"
    [[ -r "$cf" ]] || return 1
    local val; val="$(_u50_current_transfer)"
    # any 또는 absent 이면 취약
    [[ -z "$val" ]] && return 1
    [[ "$val" == "any" ]] && return 1
    return 0
}

h_U_50_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_50_capture_state "$KISA_PHASE"
    fi

    if ! _u50_bind_installed; then
        printf '양호 — bind 패키지 미설치, DNS 서비스 없음'
        return 0
    fi

    local cf; cf="$(_u50_named_conf)"
    if [[ ! -r "$cf" ]]; then
        printf 'named.conf 읽기 실패: %s' "$cf"
        return 2
    fi

    local val; val="$(_u50_current_transfer)"
    if [[ -z "$val" ]]; then
        printf '취약 — allow-transfer 미설정, Zone Transfer 전체 허용'
        return 1
    fi
    if [[ "$val" == "any" ]]; then
        printf '취약 — allow-transfer { any; }, Zone Transfer 전체 허용'
        return 1
    fi

    printf '양호 — allow-transfer { %s; } 로 허가 대상 제한됨' "$val"
    return 0
}

h_U_50_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        if ! _u50_bind_installed; then
            printf '(dry-run) bind 미설치, 조치 불필요(해당없음)'
            return 0
        fi
        local target="${DNS_ZONE_ALLOW_TRANSFER:-none}"
        printf '(dry-run) named.conf options 블록에 allow-transfer { %s; } 설정 예정; named-checkconf 검증; named restart 지연' "$target"
        return 0
    fi

    if ! _u50_bind_installed; then
        printf '해당없음 — bind 미설치, DNS 서비스 없음'
        return 3
    fi

    local rc; h_U_50_check >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then
        printf '양호 — 이미 Zone Transfer 가 허가 대상으로 제한됨'
        return 0
    fi

    local cf; cf="$(_u50_named_conf)"
    if [[ ! -f "$cf" ]]; then
        printf '조치 실패 — named.conf 없음: %s' "$cf"
        return 1
    fi

    local target="${DNS_ZONE_ALLOW_TRANSFER:-none}"
    # 입력 형태:
    #   "none"                         → none
    #   "any"                          → any
    #   "192.168.1.0/24,10.0.0.5"      → 192.168.1.0/24;10.0.0.5
    #   "{ 192.168.1.0/24; }"          → 192.168.1.0/24  (외곽 중괄호+세미콜론 제거 — 이중중괄호 방지)
    local acl_value
    if [[ "$target" == "none" || "$target" == "any" ]]; then
        acl_value="$target"
    else
        # BIND 블록 형태로 들어왔다면 외곽 { } 와 세미콜론을 정리
        local cleaned="$target"
        # 앞뒤 공백/따옴표 제거
        cleaned="${cleaned#"${cleaned%%[![:space:]]*}"}"
        cleaned="${cleaned%"${cleaned##*[![:space:]]}"}"
        # 외곽 중괄호 제거 (한 번만)
        if [[ "$cleaned" =~ ^\{(.*)\}$ ]]; then
            cleaned="${BASH_REMATCH[1]}"
            # 세미콜론·공백 정리
            cleaned="${cleaned%"${cleaned##*[![:space:]]}"}"
            cleaned="${cleaned%;}"
            cleaned="${cleaned#"${cleaned%%[![:space:]]*}"}"
        fi
        # 콤마 구분 → 세미콜론 구분
        acl_value="$(printf '%s' "$cleaned" | tr ',' ';')"
    fi

    backup_file "$cf"

    local tmp; tmp="${KISA_TMP_DIR}/tmp/u50.$$.${RANDOM}"
    mkdir -p "${KISA_TMP_DIR}/tmp"

    # options 블록에 allow-transfer 가 있으면 교체, 없으면 options { 다음 줄에 삽입
    if grep -q 'allow-transfer' "$cf"; then
        # 기존 allow-transfer 라인 교체 (options/zone 모두)
        awk -v acl="$acl_value" '
            /allow-transfer[[:space:]]*\{/ {
                # 한 줄 형태: allow-transfer { ... };
                sub(/allow-transfer[[:space:]]*\{[^}]*\}[[:space:]]*;/, \
                    "allow-transfer { " acl "; };")
            }
            { print }
        ' "$cf" > "$tmp"
    else
        # options 블록 첫 번째 { 다음에 삽입
        awk -v acl="$acl_value" '
            !inserted && /^options[[:space:]]*\{/ {
                print
                print "\tallow-transfer { " acl "; };"
                inserted=1
                next
            }
            { print }
        ' "$cf" > "$tmp"
    fi

    local om ou og
    om=$(stat -c '%a' "$cf" 2>/dev/null || printf '640')
    ou=$(stat -c '%u' "$cf" 2>/dev/null || printf '0')
    og=$(stat -c '%g' "$cf" 2>/dev/null || printf '0')
    mv -f "$tmp" "$cf"
    chmod "$om" "$cf" 2>/dev/null || true
    chown "$ou:$og" "$cf" 2>/dev/null || true
    command -v restorecon >/dev/null 2>&1 && restorecon "$cf" 2>/dev/null || true

    # named-checkconf 검증
    if command -v named-checkconf >/dev/null 2>&1; then
        if ! named-checkconf "$cf" 2>/dev/null; then
            restore_file "$cf"
            printf '조치 실패 — named-checkconf 검증 실패로 변경 원복 완료'
            return 1
        fi
    fi

    _queue_service_op restart named
    _queue_rollback   systemctl_restart named

    printf '조치 완료 — allow-transfer { %s; } 설정, named restart 지연' "$acl_value"
    return 0
}
