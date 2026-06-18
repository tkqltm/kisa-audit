#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-31: 홈 디렉토리 소유자 및 권한 설정 (중요도: 중)
# KISA 가이드: 홈 디렉터리 소유자가 해당 계정이고, other 쓰기 권한 제거
#
# 점검 기준:
#   양호: 소유자가 해당 계정, other(o) 쓰기 권한 없음
#   취약: 소유자 불일치 또는 other 쓰기 권한 존재
#
# 점검 대상:
#   - /etc/passwd 의 모든 계정 홈 디렉터리 (로그인 불가 계정 포함)
#   - 존재하는 디렉터리만 점검
#
# 조치 전략:
#   - 소유자 불일치: chown <계정>
#   - other 쓰기 권한: chmod o-w
#   - backup_file 은 디렉터리 메타만 기록 (파일 백업 아님)
#   - idempotent
#
# Rocky 8/9/10 공통

h_U_31_meta() {
    cat <<'JSON'
{
  "code": "U-31",
  "title": "홈디렉토리 소유자 및 권한 설정",
  "severity": "중",
  "category": "파일 및 디렉토리 관리",
  "purpose": "사용자 홈 디렉토리 내 설정 파일이 비인가자에 의한 변조를 방지하기 위함",
  "threat": "홈 디렉토리 내 설정 파일 변조 시 정상적인 서비스 이용이 제한될 위험이 존재함",
  "criterion_good": "홈 디렉토리 소유자가 해당 계정이고, 타 사용자 쓰기 권한이 제거된 경우",
  "criterion_bad": "홈 디렉토리 소유자가 해당 계정이 아니거나, 타 사용자 쓰기 권한이 부여된 경우",
  "action_method": "사용자별 홈 디렉토리 소유주를 해당 계정으로 변경하고, 타 사용자의 쓰기 권한 제거하도록 설정 (/etc/passwd 파일에서 홈 디렉토리 확인, 사용자 홈 디렉토리 외 개별적으로 만들어 사용하는 사용자 디렉토리 존재 여부 확인하여 점검)",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "홈 디렉토리의 소유자 외 타 사용자가 해당 홈 디렉토리를 수정할 수 없도록 제한 설정 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-31 (2026 ver.)"
  ]
}
JSON
}

_u_31_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: 일반 사용자(UID>=1000) 홈 디렉터리에 대해 ls -ld"
        echo
        echo "# 결과:"
        local _users
        _users=$(_u31_user_home_list 2>/dev/null || true)
        if [[ -z "$_users" ]]; then
            echo "(일반 사용자 없음)"
        else
            while IFS=' ' read -r _u _id _h; do
                [[ -z "$_u" ]] && continue
                ls -ld "$_h" 2>&1
            done <<< "$_users"
        fi
    } | _evidence_capture "$label"
}


# (user, uid, homedir) 목록 — 일반 사용자(UID >= 1000)의 홈만.
# 시스템 계정(UID<1000)은 sshd→/var/empty/sshd (root 소유 필수, sshd 권한분리),
# tcpdump→/, nobody→/ 등 owner 가 의도적으로 root 인 경우가 많아 chown 시 데몬 파괴.
_u31_user_home_list() {
    while IFS=: read -r user _ uid _ _ homedir _; do
        [[ -n "$homedir" && -d "$homedir" ]] || continue
        [[ "$homedir" == "/" ]] && continue
        (( uid >= 1000 )) || continue
        printf '%s %s %s\n' "$user" "$uid" "$homedir"
    done < /etc/passwd
}

h_U_31_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_31_capture_state "$KISA_PHASE"
    fi

    local issues=0

    while IFS=' ' read -r user uid homedir; do
        local downer dperm
        downer=$(stat -c '%U' "$homedir" 2>/dev/null || true)
        dperm=$(stat -c '%a'  "$homedir" 2>/dev/null || true)

        # 소유자 점검
        if [[ "$downer" != "$user" ]]; then
            (( issues++ ))
            continue
        fi

        # other 쓰기 권한 점검
        if (( (8#${dperm:-0} & 8#002) != 0 )); then
            (( issues++ ))
        fi
    done < <(_u31_user_home_list)

    if (( issues == 0 )); then
        printf '양호 — 모든 홈 디렉터리 소유자·권한 정상'
        return 0
    fi

    printf '취약 — 홈 디렉터리 소유자 또는 other 쓰기 권한 문제 %d건' "$issues"
    return 1
}

h_U_31_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        local cnt=0
        while IFS=' ' read -r user uid homedir; do
            local downer dperm
            downer=$(stat -c '%U' "$homedir" 2>/dev/null || true)
            dperm=$(stat -c '%a'  "$homedir" 2>/dev/null || true)
            if [[ "$downer" != "$user" ]] || (( (8#${dperm:-0} & 8#002) != 0 )); then
                (( cnt++ ))
            fi
        done < <(_u31_user_home_list)
        printf '(dry-run) 홈 디렉터리 %d개 chown + chmod o-w 적용 예정' "$cnt"
        return 0
    fi

    local fixed=0 failed=0

    while IFS=' ' read -r user uid homedir; do
        local downer dperm
        downer=$(stat -c '%U' "$homedir" 2>/dev/null || true)
        dperm=$(stat -c '%a'  "$homedir" 2>/dev/null || true)

        local bad_owner=0 bad_perm=0
        [[ "$downer" != "$user" ]] && bad_owner=1
        (( (8#${dperm:-0} & 8#002) != 0 )) && bad_perm=1

        (( bad_owner || bad_perm )) || continue

        # backup_file 은 파일만 지원하므로 디렉터리 메타(owner/mode) 수동 저장 후 rollback 에 chown/chmod 등록
        local meta_dir="$KISA_TMP_DIR/backup/_u31_dirmeta"
        mkdir -p "$meta_dir"
        local sanitized="${homedir//\//_}"
        printf '%s %s %s\n' "$downer" "${dperm:-700}" "$homedir" > "$meta_dir/$sanitized"
        _queue_rollback "exec" "chown $downer $homedir; chmod ${dperm:-700} $homedir"

        if (( bad_owner )); then
            if chown "$user" "$homedir" 2>/dev/null; then
                (( fixed++ ))
            else
                log_warn "U-31: $homedir chown $user 실패"
                (( failed++ ))
                continue
            fi
        fi

        if (( bad_perm )); then
            if chmod o-w "$homedir" 2>/dev/null; then
                (( fixed++ ))
            else
                log_warn "U-31: $homedir chmod o-w 실패"
                (( failed++ ))
            fi
        fi
    done < <(_u31_user_home_list)

    if (( fixed == 0 && failed == 0 )); then
        printf '양호 — 이미 모든 홈 디렉터리 소유자·권한 정상 (조치 대상 없음)'
        return 0
    fi

    if (( failed > 0 )); then
        printf '조치 실패 — 홈 디렉터리 조치 완료 %d건, 실패 %d건' "$fixed" "$failed"
        return 1
    fi

    printf '조치 완료 — 홈 디렉터리 소유자·권한 %d건 조치 (chown + chmod o-w)' "$fixed"
    return 0
}
