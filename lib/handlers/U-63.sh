#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-63: sudo 명령어 접근 관리 (중요도: 중)
# KISA 가이드: /etc/sudoers 소유자 root, 권한 640 이하.
#   /etc/sudoers.d/00-kisa-sudo drop-in 으로 wheel 그룹(또는 SUDOERS_ADMIN_GROUP)에
#   sudo 권한 부여.
#
# Rocky 8/9/10: /etc/sudoers 기본 권한 440(r--r-----).
#   440 도 양호(640 이하), 소유자 root 여야 함.
#   Other 권한(o+r, o+w, o+x) 있으면 취약.
#   SUDOERS_ADMIN_GROUP(기본: wheel) 그룹에 sudo 허용 drop-in 생성.
#
# 조치 전략:
#   1) /etc/sudoers 소유자 root 확인, 아니면 chown root
#   2) other 권한 있으면 chmod o-rwx
#   3) /etc/sudoers.d/00-kisa-sudo 생성: %<SUDOERS_ADMIN_GROUP> ALL=(ALL) ALL
#   4) visudo -cf 검증 → 실패 시 restore_file
#
# 롤백 전략: /etc/sudoers restore_file, drop-in restore_file

h_U_63_meta() {
    cat <<'JSON'
{
  "code": "U-63",
  "title": "sudo 명령어 접근 관리",
  "severity": "중",
  "category": "서비스 관리",
  "purpose": "비인가자가 관리자 권한을 남용하여 시스템 손상, 악성 코드 실행, 민감한 데이터 유출 등의 보안 위협을 방지하기 위함",
  "threat": "sudo 명령어 접근을 제한하지 않을 경우, 비인가자가 관리자 권한으로 허가되지 않은 명령어를 사용하여 루트 권한 오용, 악성 코드 실행, 데이터 유출 등의 시도를 할 위험이 존재함",
  "criterion_good": "/etc/sudoers 파일 소유자가 root이고, 파일 권한이 640인 경우",
  "criterion_bad": "/etc/sudoers 파일 소유자가 root가 아니거나, 파일 권한이 640을 초과하는 경우",
  "action_method": "/etc/sudoers 파일 소유자 및 권한 변경 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "/etc/sudoers 파일 권한 적절성 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-63 (2026 ver.)"
  ]
}
JSON
}

_u_63_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: ls -l /etc/sudoers, ls -ld /etc/sudoers.d"
        echo
        echo "## /etc/sudoers (소유자 root + 권한 640 이하)"
        ls -l /etc/sudoers 2>&1 || true
        echo
        echo "## /etc/sudoers 활성 라인 (주석/빈줄 제외)"
        grep -nvE '^[[:space:]]*(#|$)' /etc/sudoers 2>/dev/null || echo "(활성 항목 없음)"
        echo
        echo "## /etc/sudoers.d/ 권한 + 활성 라인"
        if [[ -d /etc/sudoers.d ]]; then
            ls -ld /etc/sudoers.d 2>&1
            ls -l /etc/sudoers.d/ 2>&1 || true
            local _f
            for _f in /etc/sudoers.d/*; do
                [[ -f "$_f" ]] || continue
                echo "### $_f"
                grep -nvE '^[[:space:]]*(#|$)' "$_f" 2>/dev/null || echo "(활성 항목 없음)"
            done
        else
            echo "(/etc/sudoers.d 디렉터리 없음)"
        fi
        echo
        echo "## visudo -c 검증 결과"
        if command -v visudo >/dev/null 2>&1; then
            visudo -c 2>&1 || true
        else
            echo "(visudo 명령 없음)"
        fi
        echo
        echo "## 환경변수: SUDOERS_ADMIN_GROUP=${SUDOERS_ADMIN_GROUP:-wheel(기본)}"
    } | _evidence_capture "$label"
}


_u63_sudoers()       { printf '/etc/sudoers'; }
_u63_sudoers_drop()  { printf '/etc/sudoers.d/00-kisa-sudo'; }

_u63_sudoers_owner_ok() {
    local f; f="$(_u63_sudoers)"
    [[ -r "$f" ]] || return 1
    local owner; owner="$(stat -c '%U' "$f" 2>/dev/null)"
    [[ "$owner" == "root" ]]
}

_u63_sudoers_perm_ok() {
    local f; f="$(_u63_sudoers)"
    [[ -r "$f" ]] || return 1
    local perm; perm="$(stat -c '%a' "$f" 2>/dev/null)"
    # other 권한 없어야 함: 마지막 자리 0
    local other=$(( 8#$perm & 7 ))
    (( other == 0 ))
}

_u63_has_sudoers_include() {
    local main; main="$(_u63_sudoers)"
    [[ -r "$main" ]] || return 1
    grep -qE '^[[:space:]]*([@#]includedir[[:space:]]+.*sudoers\.d|[@#]include[[:space:]]+.*sudoers\.d)' "$main"
}

_u63_drop_ok() {
    local drop; drop="$(_u63_sudoers_drop)"
    local main; main="$(_u63_sudoers)"
    local grp; grp="${SUDOERS_ADMIN_GROUP:-wheel}"
    local pattern="^%${grp}[[:space:]]+ALL=\(ALL\)[[:space:]]+ALL"
    if [[ -f "$drop" ]]; then
        grep -qE "$pattern" "$drop" && return 0
    fi
    if [[ -f "$main" ]]; then
        grep -qE "$pattern" "$main" && return 0
    fi
    return 1
}

h_U_63_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_63_capture_state "$KISA_PHASE"
    fi

    local f; f="$(_u63_sudoers)"
    if [[ ! -r "$f" ]]; then
        printf '점검 불가 — /etc/sudoers 읽기 실패'
        return 2
    fi

    local owner perm
    owner="$(stat -c '%U' "$f" 2>/dev/null)"
    perm="$(stat -c '%a' "$f" 2>/dev/null)"
    local other=$(( 8#$perm & 7 ))

    if [[ "$owner" != "root" ]]; then
        printf '취약 — /etc/sudoers 소유자=%s (root 아님)' "$owner"
        return 1
    fi

    if (( other != 0 )); then
        printf '취약 — /etc/sudoers 권한=%s, Other 권한 존재' "$perm"
        return 1
    fi

    if ! _u63_drop_ok; then
        local grp; grp="${SUDOERS_ADMIN_GROUP:-wheel}"
        printf '취약 — /etc/sudoers 권한 OK(%s)이나 %%%s sudo 허용 미적용' "$perm" "$grp"
        return 1
    fi

    local grp; grp="${SUDOERS_ADMIN_GROUP:-wheel}"
    printf '양호 — /etc/sudoers 소유자=root 권한=%s, %%%s sudo 허용 적용됨' "$perm" "$grp"
    return 0
}

h_U_63_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        local rc; h_U_63_check >/dev/null 2>&1; rc=$?
        if (( rc == 0 )); then
            printf '(dry-run) 이미 양호, 조치 불필요'
        else
            local grp; grp="${SUDOERS_ADMIN_GROUP:-wheel}"
            printf '(dry-run) /etc/sudoers chown root + chmod o-rwx, sudoers.d/00-kisa-sudo %%%s ALL=(ALL) ALL 생성, visudo -cf 검증 예정' "$grp"
        fi
        return 0
    fi

    local rc; h_U_63_check >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then
        printf '양호 — 이미 양호 상태, 조치 불필요'
        return 0
    fi

    local f; f="$(_u63_sudoers)"
    if [[ ! -f "$f" ]]; then
        printf '조치 실패 — /etc/sudoers 없음'
        return 1
    fi

    local modified=()

    # --- /etc/sudoers 권한/소유자 수정 ---
    if ! _u63_sudoers_owner_ok || ! _u63_sudoers_perm_ok; then
        backup_file "$f"
        modified+=("$f")
        chown root:root "$f" 2>/dev/null || true
        # 현재 권한에서 other 비트 제거
        local cur_perm; cur_perm="$(stat -c '%a' "$f" 2>/dev/null || printf '440')"
        local new_perm=$(( 8#$cur_perm & ~7 ))
        # 최소 0440, 최대 0640
        (( new_perm < 8#440 )) && new_perm=8#440
        (( new_perm > 8#640 )) && new_perm=8#640
        chmod "$(printf '%04o' "$new_perm")" "$f" 2>/dev/null || true
    fi

    # --- drop-in 생성 ---
    local drop; drop="$(_u63_sudoers_drop)"
    local grp; grp="${SUDOERS_ADMIN_GROUP:-wheel}"

    local use_dropin=0
    if _u63_has_sudoers_include && [[ -d /etc/sudoers.d ]]; then
        local _other_confs
        _other_confs=$(find /etc/sudoers.d -maxdepth 1 -type f \
                           ! -name '00-kisa-sudo' 2>/dev/null | wc -l)
        (( _other_confs > 0 )) && use_dropin=1
    fi

    if ! _u63_drop_ok; then
        if (( use_dropin )); then
            backup_file "$drop"
            modified+=("$drop")
            mkdir -p /etc/sudoers.d
            # drop-in 파일 생성
            printf '# Managed by KISA U-63 (kisa-audit). Do not edit manually.\n%%%s ALL=(ALL) ALL\n' "$grp" > "$drop"
            chmod 0440 "$drop"
            chown root:root "$drop" 2>/dev/null || true
            command -v restorecon >/dev/null 2>&1 && restorecon "$drop" 2>/dev/null || true
        else
            backup_file "$f"
            modified+=("$f")
            printf '\n# [KISA U-63]\n%%%s ALL=(ALL) ALL\n' "$grp" >> "$f"
        fi
    fi

    # --- visudo -cf 검증 ---
    if command -v visudo >/dev/null 2>&1; then
        local check_target="$f"
        if (( use_dropin )); then
            check_target="$drop"
        fi
        if ! visudo -cf "$check_target" 2>/dev/null; then
            local m
            for m in "${modified[@]}"; do restore_file "$m" || true; done
            printf '조치 실패 — visudo -cf 검증 실패, 모든 변경 원복 완료'
            return 1
        fi
    fi

    local new_perm_out; new_perm_out="$(stat -c '%a' "$f" 2>/dev/null)"
    printf '조치 완료 — /etc/sudoers 소유자=root 권한=%s, sudoers.d/00-kisa-sudo %%%s ALL=(ALL) ALL 생성' \
           "$new_perm_out" "$grp"
    return 0
}
