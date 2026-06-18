#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-11: 사용자 shell 점검 (중요도: 하)
# KISA 가이드: 로그인이 불필요한 계정에 /bin/false 또는 /sbin/nologin 쉘 부여 여부
#
# 자동 조치 불가 사유:
#   - 점검 대상 계정이 실제로 로그인이 필요한지는 운영자가 판단해야 함
#   - 자동 shell 변경 시 서비스 계정의 cron/스크립트 실행에 영향 가능
#   - 일부 서비스는 nologin 계정으로 SSH 키 기반 접속을 요구하기도 함
#   → apply 는 return 2 (manual) 처리
#
# KISA 점검 대상 계정 (가이드 원문 기준):
#   daemon, bin, sys, adm, listen, nobody, nobody4, noaccess, diag, operator, games, gopher
#
# Rocky 8/9/10 공통:
#   - 위 계정 목록 + UID 1~999 시스템 계정(nologin/false 아닌 것) 함께 표시
#   - /bin/false, /sbin/nologin, /usr/sbin/nologin 을 모두 안전한 shell 로 인정

h_U_11_meta() {
    cat <<'JSON'
{
  "code": "U-11",
  "title": "사용자 shell 점검",
  "severity": "하",
  "category": "계정 관리",
  "purpose": "로그인이 불필요한 계정에 부여된 쉘을 제거하여, 로그인이 필요하지 않은 계정을 통한 시스템 명령어를 실행하지 못하게 하기 위함",
  "threat": "로그인이 불필요한 계정에 쉘이 부여될 경우, 비인가자가 해당 기본 계정으로 시스템에 접근 위험이 존재함",
  "criterion_good": "로그인이 필요하지 않은 계정에 /bin/false(/sbin/nologin) 쉘이 부여된 경우",
  "criterion_bad": "로그인이 필요하지 않은 계정에 /bin/false(/sbin/nologin) 쉘이 부여되지 않은 경우",
  "action_method": "로그인이 필요하지 않은 계정에 대해 /bin/false(/sbin/nologin) 쉘 부여 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "로그인이 불필요한 계정(adm, sys, daemon 등)에 쉘 부여 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-11 (2026 ver.)"
  ]
}
JSON
}

_u_11_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: 시스템 계정(daemon/bin/sys/adm/...) 의 shell 필드 검사"
        echo
        echo "# 결과: KISA 기준 취약 shell 시스템 계정"
        local _vuln
        _vuln=$(_u11_vuln_target_accounts 2>/dev/null || true)
        if [[ -z "$_vuln" ]]; then
            echo "(없음 — 모든 시스템 계정이 nologin/false shell)"
        else
            printf '%s\n' "$_vuln"
        fi
    } | _evidence_capture "$label"
}


_u11_passwd() { printf '/etc/passwd'; }

# KISA 가이드 기준 점검 대상 계정명 배열
_U11_TARGET_ACCOUNTS=(daemon bin sys adm listen nobody nobody4 noaccess diag operator games gopher)

# 안전한 shell 목록
_u11_is_safe_shell() {
    local shell="$1"
    case "$shell" in
        /bin/false|/sbin/nologin|/usr/sbin/nologin|/bin/nologin) return 0 ;;
        *) return 1 ;;
    esac
}

# KISA 기준 대상 계정 중 shell 이 안전하지 않은 계정 반환 (계정:shell 형식)
_u11_vuln_target_accounts() {
    local passwd_f; passwd_f="$(_u11_passwd)"
    local acct
    for acct in "${_U11_TARGET_ACCOUNTS[@]}"; do
        local entry shell
        entry=$(grep -E "^${acct}:" "$passwd_f" 2>/dev/null | head -1)
        [[ -z "$entry" ]] && continue
        shell=$(printf '%s' "$entry" | awk -F: '{print $7}')
        if ! _u11_is_safe_shell "$shell"; then
            printf '%s:%s\n' "$acct" "${shell:-없음}"
        fi
    done
}

# UID 1~999 시스템 계정 중 shell 이 안전하지 않은 계정 (KISA 목록 외 추가 탐지용)
_u11_vuln_sys_accounts() {
    awk -F: '($3>=1 && $3<1000 && $7!="" && $7!="/sbin/nologin" && $7!="/bin/false" && $7!="/usr/sbin/nologin" && $7!="/bin/nologin") \
             {print $1 ":" $3 ":" $7}' "$(_u11_passwd)" 2>/dev/null
}

h_U_11_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_11_capture_state "$KISA_PHASE"
    fi

    local passwd_f; passwd_f="$(_u11_passwd)"
    if [[ ! -r "$passwd_f" ]]; then
        printf '/etc/passwd 읽기 실패'
        return 2
    fi

    local vuln_target
    vuln_target=$(_u11_vuln_target_accounts)

    if [[ -z "$vuln_target" ]]; then
        printf '양호 — KISA 기준 점검 대상 계정 모두 nologin/false shell'
        return 0
    fi

    local cnt
    cnt=$(printf '%s\n' "$vuln_target" | grep -c '.')
    printf '취약 — KISA 기준 취약 shell 계정 %s개: %s' \
           "$cnt" "$(printf '%s' "$vuln_target" | tr '\n' ',')"
    return 1
}

h_U_11_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        printf '(dry-run) [MANUAL] 취약 shell 계정 확인 후 usermod -s /sbin/nologin 수동 수행 필요'
        return 0
    fi

    local vuln_target
    vuln_target=$(_u11_vuln_target_accounts)
    local vuln_sys
    vuln_sys=$(_u11_vuln_sys_accounts)

    if [[ -z "$vuln_target" ]]; then
        printf '양호 — 이미 모든 대상 계정이 nologin/false shell, 조치 불필요'
        return 0
    fi

    printf '수동 조치 필요 — KISA 기준 취약 shell 계정 (운영자 판단 후 nologin/false 부여):\n'
    printf '%s\n' "$vuln_target" | while IFS=: read -r acct shell; do
        [[ -z "$acct" ]] && continue
        printf '  계정: %-20s 현재 shell: %s\n' "$acct" "${shell:-없음}"
    done

    printf '\n조치 방법:\n'
    printf '  # usermod -s /sbin/nologin <계정명>   -- 로그인 차단 (메시지 출력)\n'
    printf '  # usermod -s /bin/false <계정명>       -- 로그인 차단 (메시지 없음)\n'

    if [[ -n "$vuln_sys" ]]; then
        printf '\n참고) UID 1~999 시스템 계정 중 추가 확인 권장:\n'
        printf '%s\n' "$vuln_sys" | while IFS=: read -r acct uid shell; do
            [[ -z "$acct" ]] && continue
            printf '  계정: %-20s UID: %-6s shell: %s\n' "$acct" "$uid" "$shell"
        done
    fi
    return 2
}
