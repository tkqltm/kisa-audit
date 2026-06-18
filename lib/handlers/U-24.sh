#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-24: 사용자, 시스템 환경변수 파일 소유자 및 권한 설정 (중요도: 상)
# KISA 가이드: 시스템 공용 환경파일 및 각 사용자 홈 디렉터리 내 환경변수 파일의
#             소유자 및 other 쓰기 권한 점검
#
# 점검 기준:
#   양호: 소유자가 root 또는 해당 계정, other(o) 쓰기 권한 없음
#   취약: 소유자 부적절 또는 other 쓰기 권한 있음
#
# 점검 대상 파일:
#   시스템: /etc/profile, /etc/bashrc, /etc/csh.cshrc, /etc/csh.login
#   사용자홈: .profile .bash_profile .bashrc .bash_login .bash_logout
#             .kshrc .cshrc .login .exrc .netrc
#
# 조치 전략:
#   - 소유자 불일치: chown <계정 또는 root>
#   - other 쓰기 권한: chmod o-w
#   - backup_file 후 자동 조치, idempotent
#
# Rocky 8/9/10 공통

h_U_24_meta() {
    cat <<'JSON'
{
  "code": "U-24",
  "title": "사용자, 시스템 환경변수 파일 소유자 및 권한 설정",
  "severity": "상",
  "category": "파일 및 디렉토리 관리",
  "purpose": "비인가자의 환경변수 조작으로 인한 보안 위험이 존재함",
  "threat": "홈 디렉터리 내의 사용자 파일 및 사용자별 시스템 시작 파일 등과 같은 환경변수 파일의 접근 권한 설정이 적절하지 않을 경우, 비인가자가 환경변수 파일을 변조하여 정상 사용 중인 사용자의 서비스가 제한될 수 있는 위험이 존재함",
  "criterion_good": "홈 디렉터리 환경변수 파일 소유자가 root 또는 해당 계정으로 지정되어 있고, 홈 디렉터리 환경변수 파일에 root 계정과 소유자만 쓰기 권한이 부여된 경우",
  "criterion_bad": "홈 디렉터리 환경변수 파일 소유자가 root 또는 해당 계정으로 지정되지 않거나, 홈 디렉터리 환경변수 파일에 root 계정과 소유자 외에 쓰기 권한이 부여된 경우",
  "action_method": "환경변수 파일의 일반 사용자 쓰기 권한 제거하도록 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "홈 디렉터리 내의 환경변수 파일에 대한 소유자 및 접근 권한이 관리자 또는 해당 계정으로 설정 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-24 (2026 ver.)"
  ]
}
JSON
}

_u_24_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: 환경변수 파일 소유자/권한 검증"
        echo
        echo "## 시스템 공용 환경파일 ls -l"
        for _f in /etc/profile /etc/bashrc /etc/csh.cshrc /etc/csh.login; do
            [[ -f "$_f" ]] && ls -l "$_f" 2>&1
        done
        echo
        echo "## /etc/profile.d/*.sh 권한 검증"
        if [[ -d /etc/profile.d ]]; then
            ls -l /etc/profile.d/ 2>&1 | head -20
        fi
        echo
        echo "## 비-root 소유 또는 other 쓰기 권한 보유 시스템 환경파일"
        for _f in /etc/profile /etc/bashrc /etc/csh.cshrc /etc/csh.login; do
            [[ -f "$_f" ]] || continue
            find "$_f" \( \! -uid 0 -o -perm /002 \) 2>/dev/null
        done
        echo
        echo "## 일반 사용자 홈 디렉터리 환경파일 (UID>=1000)"
        local _u _h
        while IFS=: read -r _u _ _uid _ _ _h _; do
            (( _uid >= 1000 )) || continue
            [[ -d "$_h" ]] || continue
            for _ef in .bashrc .bash_profile .profile .cshrc .login; do
                [[ -f "$_h/$_ef" ]] && ls -l "$_h/$_ef" 2>&1
            done
        done < /etc/passwd | head -30
    } | _evidence_capture "$label"
}


# 시스템 공용 환경파일 — 소유자 root, other 쓰기 없어야 함
_u24_system_files() {
    printf '/etc/profile\n/etc/bashrc\n/etc/csh.cshrc\n/etc/csh.login\n'
}

# 사용자 홈 내 환경파일 이름 목록
_u24_user_env_names() {
    printf '.profile .bash_profile .bashrc .bash_login .bash_logout .kshrc .cshrc .login .exrc .netrc'
}

# 점검 대상 (user, uid, homedir) 목록 — /etc/passwd 파싱
_u24_user_list() {
    while IFS=: read -r user _ uid _ _ homedir _; do
        [[ -n "$homedir" && -d "$homedir" ]] || continue
        printf '%s %s %s\n' "$user" "$uid" "$homedir"
    done < /etc/passwd
}

# 파일의 취약 여부: (bad_owner, bad_perm) 출력
# expected_owner: 소유자로 허용할 계정 (빈 문자열이면 root 만 허용)
_u24_check_file() {
    local fp="$1" expected_owner="$2"
    local fowner fmode
    fowner=$(stat -c '%U' "$fp" 2>/dev/null || true)
    fmode=$(stat -c '%a'  "$fp" 2>/dev/null || true)

    local bad_owner=0 bad_perm=0
    if [[ -n "$expected_owner" ]]; then
        [[ "$fowner" != "root" && "$fowner" != "$expected_owner" ]] && bad_owner=1
    else
        [[ "$fowner" != "root" ]] && bad_owner=1
    fi
    (( (8#${fmode:-0} & 8#002) != 0 )) && bad_perm=1

    printf '%d %d' "$bad_owner" "$bad_perm"
}

h_U_24_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_24_capture_state "$KISA_PHASE"
    fi

    local issues=0

    # 1) 시스템 공용 환경파일 점검
    local sf
    while IFS= read -r sf; do
        [[ -f "$sf" ]] || continue
        local result
        result=$(_u24_check_file "$sf" "")
        local bo bp
        read -r bo bp <<< "$result"
        (( bo || bp )) && (( issues++ ))
    done < <(_u24_system_files)

    # 2) 사용자 홈 환경파일 점검
    local -a env_names
    IFS=' ' read -r -a env_names <<< "$(_u24_user_env_names)"

    while IFS=' ' read -r user uid homedir; do
        local ef
        for ef in "${env_names[@]}"; do
            local fp="${homedir}/${ef}"
            [[ -f "$fp" ]] || continue
            local result
            result=$(_u24_check_file "$fp" "$user")
            local bo bp
            read -r bo bp <<< "$result"
            (( bo || bp )) && (( issues++ ))
        done
    done < <(_u24_user_list)

    if (( issues == 0 )); then
        printf '양호 — 모든 환경변수 파일 소유자·권한 정상'
        return 0
    fi
    printf '취약 — 환경변수 파일 소유자 또는 other 쓰기 권한 문제 %d건' "$issues"
    return 1
}

h_U_24_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        printf '(dry-run) 시스템·사용자홈 환경변수 파일 소유자 chown + chmod o-w 적용 예정'
        return 0
    fi

    local fixed=0 failed=0

    # 공통 처리 함수
    _u24_fix_file() {
        local fp="$1" target_owner="$2"
        local fowner fmode
        fowner=$(stat -c '%U' "$fp" 2>/dev/null || true)
        fmode=$(stat -c '%a'  "$fp" 2>/dev/null || true)

        local bad_owner=0 bad_perm=0
        if [[ -n "$target_owner" && "$target_owner" != "root" ]]; then
            [[ "$fowner" != "root" && "$fowner" != "$target_owner" ]] && bad_owner=1
        else
            [[ "$fowner" != "root" ]] && bad_owner=1
        fi
        (( (8#${fmode:-0} & 8#002) != 0 )) && bad_perm=1

        (( bad_owner || bad_perm )) || return 0

        backup_file "$fp"

        if (( bad_owner )); then
            local co="${target_owner:-root}"
            chown "$co" "$fp" 2>/dev/null && (( fixed++ )) || { log_warn "U-24: chown $co $fp 실패"; (( failed++ )); }
        fi
        if (( bad_perm )); then
            chmod o-w "$fp" 2>/dev/null && (( fixed++ )) || { log_warn "U-24: chmod o-w $fp 실패"; (( failed++ )); }
        fi
    }

    # 1) 시스템 공용 환경파일
    local sf
    while IFS= read -r sf; do
        [[ -f "$sf" ]] || continue
        _u24_fix_file "$sf" "root"
    done < <(_u24_system_files)

    # 2) 사용자 홈 환경파일
    local -a env_names
    IFS=' ' read -r -a env_names <<< "$(_u24_user_env_names)"

    while IFS=' ' read -r user uid homedir; do
        local ef
        for ef in "${env_names[@]}"; do
            local fp="${homedir}/${ef}"
            [[ -f "$fp" ]] || continue
            local to
            [[ "$uid" == "0" ]] && to="root" || to="$user"
            _u24_fix_file "$fp" "$to"
        done
    done < <(_u24_user_list)

    if (( failed > 0 )); then
        printf '조치 실패 — 환경변수 파일 %d건 조치, %d건 실패' "$fixed" "$failed"
        return 1
    fi
    if (( fixed == 0 )); then
        printf '양호 — 이미 환경변수 파일 소유자·권한 정상 (조치 대상 없음)'
        return 0
    fi
    printf '조치 완료 — 환경변수 파일 소유자·권한 %d건 정정 (시스템+사용자홈)' "$fixed"
    return 0
}
