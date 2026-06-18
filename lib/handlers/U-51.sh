#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-51: DNS 서비스의 취약한 동적 업데이트 설정 금지 (중요도: 중)
# KISA 가이드: named.conf 의 zone 블록에 allow-update { none; }; 강제.
#
# Rocky 8/9/10: BIND 9 기반, /etc/named.conf 의 각 zone 블록에
#   allow-update { none; }; 미설정이면 취약.
#   bind 미설치 시 해당없음(N/A).
#
# 조치 전략:
#   1) bind 미설치 → N/A
#   2) allow-update { any; }; 또는 미설정인 zone 블록이 있으면 취약
#   3) options 블록에 전역 allow-update { none; }; 삽입/교체
#   4) named-checkconf 검증 → 실패 시 restore_file
#   5) named restart 큐잉
#
# 롤백 전략: /etc/named.conf restore_file + named restart

h_U_51_meta() {
    cat <<'JSON'
{
  "code": "U-51",
  "title": "DNS 서비스의 취약한 동적 업데이트 설정 금지",
  "severity": "중",
  "category": "서비스 관리",
  "purpose": "DNS 서비스의 동적 업데이트를 비활성화함으로써 신뢰할 수 없는 원본으로부터 업데이트를 받아들이는 위험을 차단하기 위함",
  "threat": "DNS 서버에서 동적 업데이트를 사용할 경우, 악의적인 사용자에 의해 신뢰할 수 없는 데이터가 받아들여질 위험이 존재함",
  "criterion_good": "DNS 서비스의 동적 업데이트 기능이 비활성화되었거나, 활성화 시 적절한 접근통제를 수행하고 있는 경우",
  "criterion_bad": "DNS 서비스의 동적 업데이트 기능이 활성화 중이며 적절한 접근통제를 수행하고 있지 않은 경우",
  "action_method": "- DNS 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 - DNS 서비스 사용 시 일반적으로 동적 업데이트 기능이 필요 없으나 확인 필요함",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "DNS 서비스의 취약한 동적 업데이트 설정 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-51 (2026 ver.)"
  ]
}
JSON
}

_u_51_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: bind 설치 여부 + named.conf 의 allow-update 설정 확인"
        echo "## rpm -q bind"
        rpm -q bind 2>&1 || true
        echo
        echo "## named 서비스 상태"
        echo "is-enabled named: $(systemctl is-enabled named 2>&1)"
        echo "is-active  named: $(systemctl is-active  named 2>&1)"
        echo
        echo "## allow-update 설정 추출"
        if [[ -r /etc/named.conf ]]; then
            grep -nE 'allow-update' /etc/named.conf 2>/dev/null || echo "(설정 없음 — KISA 기준상 취약)"
        else
            echo "(/etc/named.conf 읽기 불가)"
        fi
    } | _evidence_capture "$label"
}


_u51_named_conf() { printf '/etc/named.conf'; }

_u51_bind_installed() {
    rpm -q bind >/dev/null 2>&1
}

# allow-update 현황: 0=취약(any 또는 미설정), 1=양호(none 또는 제한된 IP)
_u51_is_ok() {
    local cf; cf="$(_u51_named_conf)"
    [[ -r "$cf" ]] || return 1

    # allow-update 가 아예 없으면 취약 (기본값은 모든 업데이트 허용은 아니지만
    # KISA 기준상 명시 필요)
    if ! grep -q 'allow-update' "$cf"; then
        return 1
    fi

    # allow-update { any; } 가 있으면 취약
    if grep -qE 'allow-update[[:space:]]*\{[[:space:]]*any[[:space:]]*\}' "$cf"; then
        return 1
    fi

    return 0
}

h_U_51_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_51_capture_state "$KISA_PHASE"
    fi

    if ! _u51_bind_installed; then
        printf '양호 — bind 패키지 미설치(DNS 서비스 없음, 취약점 해당없음)'
        return 0
    fi

    local cf; cf="$(_u51_named_conf)"
    if [[ ! -r "$cf" ]]; then
        printf 'named.conf 읽기 실패: %s' "$cf"
        return 2
    fi

    if ! grep -q 'allow-update' "$cf"; then
        printf '취약 — allow-update 미설정, 동적 업데이트 제한 없음'
        return 1
    fi

    if grep -qE 'allow-update[[:space:]]*\{[[:space:]]*any[[:space:]]*\}' "$cf"; then
        printf '취약 — allow-update { any; } 설정, 동적 업데이트 전체 허용'
        return 1
    fi

    printf '양호 — allow-update 설정됨 (none 또는 제한된 접근)'
    return 0
}

h_U_51_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        if ! _u51_bind_installed; then
            printf '(dry-run) bind 미설치, 조치 불필요(N/A)'
            return 0
        fi
        printf '(dry-run) named.conf options 블록에 allow-update { none; } 설정 예정; named-checkconf 검증; named restart 지연'
        return 0
    fi

    if ! _u51_bind_installed; then
        printf '해당없음 — bind 패키지 미설치(DNS 서비스 없음)'
        return 3
    fi

    local rc; h_U_51_check >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then
        printf '양호 — 이미 allow-update 제한이 적용된 상태'
        return 0
    fi
    if (( rc == 2 )); then
        printf '조치 실패 — named.conf 읽기 실패'
        return 1
    fi

    local cf; cf="$(_u51_named_conf)"
    backup_file "$cf"

    local tmp; tmp="${KISA_TMP_DIR}/tmp/u51.$$.${RANDOM}"
    mkdir -p "${KISA_TMP_DIR}/tmp"

    if grep -q 'allow-update' "$cf"; then
        # 기존 allow-update { any; } → allow-update { none; }
        awk '
            /allow-update[[:space:]]*\{[[:space:]]*any[[:space:]]*\}/ {
                sub(/allow-update[[:space:]]*\{[[:space:]]*any[[:space:]]*\}/, \
                    "allow-update { none; }")
            }
            { print }
        ' "$cf" > "$tmp"
    else
        # options 블록에 allow-update { none; }; 삽입
        awk '
            !inserted && /^options[[:space:]]*\{/ {
                print
                print "\tallow-update { none; };"
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
            printf '조치 실패 — named-checkconf 검증 실패, 변경 원복 완료'
            return 1
        fi
    fi

    _queue_service_op restart named
    _queue_rollback   systemctl_restart named

    printf '조치 완료 — allow-update { none; } 설정, named restart 지연'
    return 0
}
