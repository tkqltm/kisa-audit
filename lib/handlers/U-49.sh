#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-49: DNS 보안 버전 패치 (중요도: 상)
# KISA 가이드: BIND 최신 버전 사용 및 주기적 보안 패치 여부 확인.
#
# Rocky 8/9/10: bind 패키지 버전 출력. 버전 점검은 수동(ISC 홈페이지 비교).
#   bind 패치는 운영자 수동 안내 (audit.conf 자동 패치 변수 없음).
#   bind 미설치 시 해당없음(N/A).
#
# 조치 전략:
#   check: bind 패키지 설치 여부 + 버전 출력 (취약 판정 — 수동 버전 비교 필요)
#   apply:
#     apply 는 항상 수동 안내 (return 2)
#     기타            → manual (버전 비교·패치 계획 문서화는 관리자 몫)
#
# 롤백 전략: dnf update 는 롤백 불가 (필요 시 dnf downgrade 수동).

h_U_49_meta() {
    cat <<'JSON'
{
  "code": "U-49",
  "title": "DNS 보안 버전 패치",
  "severity": "상",
  "category": "서비스 관리",
  "purpose": "취약점이 발표되지 않은 BIND 버전을 사용하여 시스템 보안성을 높이기 위함",
  "threat": "취약점이 내포된 BIND 버전을 사용할 경우, DoS 공격, 버퍼 오버플로우(Buffer Overflow) 및 DNS 서버 원격 침입 등의 위험이 존재함",
  "criterion_good": "주기적으로 패치를 관리하는 경우",
  "criterion_bad": "주기적으로 패치를 관리하고 있지 않은 경우",
  "action_method": "- DNS 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 - DNS 서비스 사용 시 패치 관리 정책 수립 및 주기적으로 패치 적용 설정 ※ DNS 서비스의 경우 대부분의 버전에서 취약점이 보고되고 있으므로 OS 관리자, 서비스 개발자가 패치 적용에 따른 서비스 영향 정도를 정확히 파악하여 주기적인 패치 적용 정책 수리 후 적용",
  "action_impact": "패치 적용 시 시스템 및 서비스 영향 정도를 충분히 고려해야 함",
  "method": [
    "BIND 최신 버전 사용 유무 및 주기적 보안 패치 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-49 (2026 ver.)"
  ]
}
JSON
}

_u_49_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: bind 패키지 설치/버전 확인"
        echo "## rpm -q bind"
        rpm -q bind 2>&1 || true
        echo
        echo "## rpm -q bind-utils"
        rpm -q bind-utils 2>&1 || true
        echo
        echo "# named 서비스 상태"
        echo "is-enabled named: $(systemctl is-enabled named 2>&1)"
        echo "is-active  named: $(systemctl is-active  named 2>&1)"
        echo
        echo "# /etc/named.conf 존재 여부"
        if [[ -f /etc/named.conf ]]; then
            ls -l /etc/named.conf 2>&1
        else
            echo "(/etc/named.conf 없음)"
        fi
        echo
        echo "## 패치 정책: 운영자 수동 조치 (audit.conf 자동 패치 변수 없음)"
    } | _evidence_capture "$label"
}


_u49_bind_installed() {
    rpm -q bind >/dev/null 2>&1
}

# named(BIND) 실제 사용(active) 여부 — 설치돼 있어도 비활성이면 DNS 미사용으로 판단.
_u49_bind_active() {
    systemctl is-active --quiet named        2>/dev/null && return 0
    systemctl is-active --quiet named-chroot 2>/dev/null && return 0
    return 1
}

_u49_bind_version() {
    rpm -q bind --queryformat '%{VERSION}-%{RELEASE}' 2>/dev/null || printf 'unknown'
}

h_U_49_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_49_capture_state "$KISA_PHASE"
    fi

    if ! _u49_bind_installed; then
        printf '양호 — bind 패키지 미설치(DNS 서비스 없음, 취약점 해당없음)'
        return 0
    fi

    # 설치돼 있어도 named 비활성(미사용)이면 버전 점검 대상 아님 → 양호.
    if ! _u49_bind_active; then
        printf '양호 — bind 설치됐으나 named 비활성(DNS 미사용) — 버전 점검 대상 아님'
        return 0
    fi

    local ver; ver="$(_u49_bind_version)"
    printf '취약 — bind 버전 %s, ISC 홈페이지(https://kb.isc.org/v1/docs/en/aa-00913)에서 최신 패치 여부 수동 확인 필요' "$ver"
    return 1
}

h_U_49_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        if ! _u49_bind_installed; then
            printf '(dry-run) bind 미설치, 조치 불필요(N/A)'
        else
            printf '(dry-run) bind 패치는 수동 안내 — 운영자가 dnf update 직접 수행'
        fi
        return 0
    fi

    if ! _u49_bind_installed; then
        printf '해당없음 — bind 미설치(DNS 서비스 없음)'
        return 3
    fi

    local ver; ver="$(_u49_bind_version)"
    printf '수동 조치 필요 — bind 현재 버전 %s, ISC https://kb.isc.org/v1/docs/en/aa-00913 에서 최신 보안 패치 버전 확인 후 "dnf update bind bind-utils" 실행 및 패치 이력 문서화' "$ver"
    return 2
}
