#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-27: $HOME/.rhosts, hosts.equiv 사용 금지 (중요도: 상)
# KISA 가이드: r-command 인증 우회 파일 제거
#
# 점검 기준:
#   양호: /etc/hosts.equiv 및 모든 사용자 홈의 .rhosts 파일 미존재
#         또는 소유자 적절, 권한 600 이하, "+" 설정 없음
#   취약: 위 조건 중 하나 이상 미충족
#
# 조치 전략:
#   - /etc/hosts.equiv: backup_file 후 삭제
#   - 각 홈 디렉터리 .rhosts: backup_file 후 삭제
#   - "+" 포함 파일도 동일하게 삭제
#   - 자동 삭제 가능 (Rocky에서 r-command 기본 미설치)
#
# Rocky 8/9/10 공통: rsh-server 기본 미설치

h_U_27_meta() {
    cat <<'JSON'
{
  "code": "U-27",
  "title": "$HOME/.rhosts, hosts.equiv 사용 금지",
  "severity": "상",
  "category": "파일 및 디렉토리 관리",
  "purpose": "r-command를 통한 별도의 인증 없는 관리자 권한 원격 접속을 차단하기 위함",
  "threat": "- r-command(rlogin, rsh 등)에 보안 설정이 적용되지 않을 경우, 원격지의 공격자가 관리자 권한으로 목표 시스템상 임의의 명령을 수행시킬 수 있으며, 명령어 원격실행을 통해 중요 정보유출 및 시스템 장애를 유발 또는 공격자의 백도어 등으로도 활용될 수 있는 위험이 존재함 - 해당 파일은 r-command 서비스의 접근통제에 관련된 파일이며, 권한 설정이 부적절한 경우 r-command 서비스 사용 권한을 임의로 등록하여 무단 사용 위험이 존재함",
  "criterion_good": "rlogin, rsh, rexec 서비스를 사용하지 않거나, 사용 시 아래와 같은 설정이 적용된 경우 1. /etc/hosts.equiv 및 $HOME/.rhosts 파일 소유자가 root 또는 해당 계정인 경우 2. /etc/hosts.equiv 및 $HOME/.rhosts 파일 권한이 600 이하인 경우 3. /etc/hosts.equiv 및 $HOME/.rhosts 파일 설정에 “+” 설정이 없는 경우",
  "criterion_bad": "rlogin, rsh, rexec 서비스를 사용하며 아래와 같은 설정이 적용되지 않은 경우 1. /etc/hosts.equiv 및 $HOME/.rhosts 파일 소유자가 root 또는 해당 계정이 아닌 경우 2. /etc/hosts.equiv 및 $HOME/.rhosts 파일 권한이 600을 초과한 경우 3. /etc/hosts.equiv 및 $HOME/.rhosts 파일 설정에 “+” 설정이 존재하는 경우",
  "action_method": "/etc/hosts.equiv, $HOME/.rhosts 파일 소유자 및 권한 변경, 허용 호스트 및 계정 등록 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "$HOME/.rhosts 및 /etc/hosts.equiv 파일에 대해 적절한 소유자 및 접근 권한 설정 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-27 (2026 ver.)"
  ]
}
JSON
}

_u_27_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: /etc/hosts.equiv 존재 여부 + 홈 디렉터리 .rhosts 탐색"
        echo
        echo "## /etc/hosts.equiv"
        if [[ -e /etc/hosts.equiv ]]; then
            ls -l /etc/hosts.equiv 2>&1
            echo "--- 내용 ---"
            cat /etc/hosts.equiv 2>/dev/null || true
        else
            echo "(없음)"
        fi
        echo
        echo "## 사용자 홈 .rhosts 파일"
        local _rhosts
        _rhosts=$(_u27_find_rhosts 2>/dev/null || true)
        if [[ -z "$_rhosts" ]]; then
            echo "(없음 — .rhosts 파일 없음)"
        else
            local _f
            while IFS= read -r _f; do
                [[ -z "$_f" ]] && continue
                echo "### $_f"
                ls -l "$_f" 2>&1
                echo "--- 내용 ---"
                cat "$_f" 2>/dev/null || true
            done <<< "$_rhosts"
        fi
    } | _evidence_capture "$label"
}


_u27_hosts_equiv() { printf '/etc/hosts.equiv'; }

# 모든 사용자 홈 디렉터리의 .rhosts 파일 목록
_u27_find_rhosts() {
    while IFS=: read -r _ _ _ _ _ homedir _; do
        [[ -n "$homedir" && -f "${homedir}/.rhosts" ]] && printf '%s/.rhosts\n' "$homedir"
    done < /etc/passwd
}

# 파일의 취약 여부 판정: 1=취약 (존재 자체가 취약), 0=양호
_u27_is_vulnerable() {
    local f="$1" owner="$2"
    # 존재하면 무조건 취약 (r-command 사용 금지가 원칙)
    [[ -f "$f" ]] && return 1
    return 0
}

h_U_27_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_27_capture_state "$KISA_PHASE"
    fi

    local issues=0 found_list=()
    local he; he="$(_u27_hosts_equiv)"

    [[ -f "$he" ]] && { found_list+=("$he"); (( issues++ )); }

    while IFS= read -r rh; do
        [[ -f "$rh" ]] && { found_list+=("$rh"); (( issues++ )); }
    done < <(_u27_find_rhosts)

    if (( issues == 0 )); then
        printf '양호 — .rhosts·hosts.equiv 파일 미존재'
        return 0
    fi

    printf '취약 — .rhosts·hosts.equiv 파일 %d개 발견 (예: %s)' "$issues" "${found_list[0]}"
    return 1
}

h_U_27_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        local cnt=0
        local he; he="$(_u27_hosts_equiv)"
        [[ -f "$he" ]] && (( cnt++ ))
        while IFS= read -r rh; do [[ -f "$rh" ]] && (( cnt++ )); done < <(_u27_find_rhosts)
        printf '(dry-run) .rhosts·hosts.equiv 파일 %d개 backup 후 삭제 예정' "$cnt"
        return 0
    fi

    local removed=0 failed=0
    local he; he="$(_u27_hosts_equiv)"

    # /etc/hosts.equiv 처리
    if [[ -f "$he" ]]; then
        backup_file "$he"
        if rm -f "$he" 2>/dev/null; then
            (( removed++ ))
        else
            log_error "U-27: $he 삭제 실패"
            (( failed++ ))
        fi
    fi

    # 각 사용자 .rhosts 처리
    while IFS= read -r rh; do
        [[ -f "$rh" ]] || continue
        backup_file "$rh"
        if rm -f "$rh" 2>/dev/null; then
            (( removed++ ))
        else
            log_error "U-27: $rh 삭제 실패"
            (( failed++ ))
        fi
    done < <(_u27_find_rhosts)

    if (( removed == 0 && failed == 0 )); then
        printf '양호 — 이미 .rhosts·hosts.equiv 파일 없음 (조치 불필요)'
        return 0
    fi

    if (( failed > 0 )); then
        printf '조치 실패 — .rhosts·hosts.equiv 삭제 %d개 완료, %d개 실패' "$removed" "$failed"
        return 1
    fi

    printf '조치 완료 — .rhosts·hosts.equiv 파일 %d개 삭제 (backup 보관)' "$removed"
    return 0
}
