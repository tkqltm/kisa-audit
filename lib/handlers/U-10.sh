#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-10: 동일한 UID 금지 (중요도: 중)
# KISA 가이드: /etc/passwd 에서 동일한 UID 를 사용하는 계정이 없어야 함
#
# 자동 조치 불가 사유:
#   - 어떤 계정의 UID 를 어떤 값으로 바꿀지는 운영자가 결정해야 함
#   - UID 변경 시 해당 계정 소유 파일 권한이 깨질 수 있음
#   - 잘못된 UID 변경은 서비스 장애 유발 가능
#   → apply 는 return 2 (manual) 처리
#
# Rocky 8/9/10 공통:
#   - awk -F: '{print $3}' /etc/passwd | sort | uniq -d 로 중복 UID 탐지
#   - 중복 UID 를 가진 계정 목록 상세 출력

h_U_10_meta() {
    cat <<'JSON'
{
  "code": "U-10",
  "title": "동일한 UID 금지",
  "severity": "중",
  "category": "계정 관리",
  "purpose": "UID가 동일한 사용자 계정을 점검함으로써 타 사용자 계정 소유의 파일 및 디렉터리로의 악의적 접근 예방 및 침해사고 시 명확한 감사 추적을 하기 위함",
  "threat": "중복된 UID가 존재할 경우, 시스템은 동일한 사용자로 인식하여 소유자의 권한이 중복되어 불필요한 권한이 부여되며 시스템 로그를 이용한 감사 추적 시 사용자가 구분되지 않는 위험이 존재함",
  "criterion_good": "동일한 UID로 설정된 사용자 계정이 존재하지 않는 경우",
  "criterion_bad": "동일한 UID로 설정된 사용자 계정이 존재하는 경우",
  "action_method": "동일한 UID를 가진 사용자 계정의 UID를 중복되지 않도록 변경하도록 설정",
  "action_impact": "운영 목적으로 동일한 UID 값을 부여하였다면 해당 계정이 사용하고 있는 파일 및 디렉터리를 검토하여 권한이 제거되어도 서비스 영향이 없는지 확인 필요",
  "method": [
    "/etc/passwd 파일 내 UID가 동일한 사용자 계정 존재 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-10 (2026 ver.)"
  ]
}
JSON
}

_u_10_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: awk -F: '{print \$3}' /etc/passwd | sort | uniq -d"
        echo
        echo "# 결과: 중복 UID"
        local _dups
        _dups=$(_u10_dup_uids 2>/dev/null || true)
        if [[ -z "$_dups" ]]; then
            echo "(없음 — 중복 UID 없음)"
        else
            local _uid
            while IFS= read -r _uid; do
                [[ -z "$_uid" ]] && continue
                local _accts
                _accts=$(awk -F: -v u="$_uid" '($3==u){printf "%s ",$1}' /etc/passwd 2>/dev/null)
                printf 'UID=%s : %s\n' "$_uid" "$_accts"
            done <<< "$_dups"
        fi
    } | _evidence_capture "$label"
}


_u10_passwd() { printf '/etc/passwd'; }

# 중복 UID 목록 반환 (UID 값)
_u10_dup_uids() {
    awk -F: '{print $3}' "$(_u10_passwd)" 2>/dev/null | sort | uniq -d
}

# 특정 UID 를 사용하는 계정 목록
_u10_accounts_by_uid() {
    local uid="$1"
    awk -F: -v u="$uid" '($3==u){print $1}' "$(_u10_passwd)" 2>/dev/null
}

h_U_10_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_10_capture_state "$KISA_PHASE"
    fi

    local passwd_f; passwd_f="$(_u10_passwd)"
    if [[ ! -r "$passwd_f" ]]; then
        printf '/etc/passwd 읽기 실패'
        return 2
    fi

    local dup_uids
    dup_uids=$(_u10_dup_uids)

    if [[ -z "$dup_uids" ]]; then
        printf '양호 — 중복 UID 없음'
        return 0
    fi

    local cnt
    cnt=$(printf '%s\n' "$dup_uids" | grep -c '.')
    local detail=""
    while IFS= read -r uid; do
        [[ -z "$uid" ]] && continue
        local accts
        accts=$(awk -F: -v u="$uid" '($3==u){printf "%s ",$1}' "$passwd_f" 2>/dev/null)
        detail+="UID=${uid}:[${accts}] "
    done <<< "$dup_uids"

    printf '취약 — 중복 UID %s개: %s' "$cnt" "$detail"
    return 1
}

h_U_10_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        printf '(dry-run) [MANUAL] 중복 UID 계정 확인 후 usermod -u 로 UID 재지정 (수동 조치 예정)'
        return 0
    fi

    local dup_uids
    dup_uids=$(_u10_dup_uids)

    if [[ -z "$dup_uids" ]]; then
        printf '양호 — 이미 중복 UID 없음 (조치 불필요)'
        return 0
    fi

    local passwd_f; passwd_f="$(_u10_passwd)"
    printf '수동 조치 필요 — 중복 UID 계정의 UID 재지정 필요\n조치: 아래 계정 목록 확인 후 usermod -u 로 변경\n'
    while IFS= read -r uid; do
        [[ -z "$uid" ]] && continue
        local accts
        accts=$(awk -F: -v u="$uid" '($3==u){print $1}' "$passwd_f" 2>/dev/null | tr '\n' ' ')
        printf '  UID %-6s: %s\n' "$uid" "$accts"
    done <<< "$dup_uids"

    printf '\n조치 방법:\n'
    printf '  # usermod -u <새UID> <계정명>   -- 고유 UID 로 변경\n'
    printf '  ※ 변경 후 해당 계정 소유 파일 권한 재확인:\n'
    printf '    find / -user <이전UID> -exec chown <새UID> {} \;\n'
    printf '  ※ UID 1000 미만은 시스템 계정이므로 신중하게 판단\n'
    printf '  ※ 현재 사용 중인 계정은 /etc/passwd 직접 수정 후 재로그인 필요\n'
    return 2
}
