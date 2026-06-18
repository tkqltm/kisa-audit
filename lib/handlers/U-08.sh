#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-08: 관리자 그룹에 최소한의 계정 포함 (중요도: 중)
# KISA 가이드: root 그룹(GID=0)에 불필요한 계정이 없어야 함
#
# 자동 조치 불가 사유:
#   - 어떤 계정이 관리자 그룹에 포함되어야 하는지는 운영 정책에 따라 다름
#   - gpasswd -d 잘못 수행 시 관리자 권한 박탈로 운영 장애 가능
#   → apply 는 return 2 (manual) 처리
#
# Rocky 8/9/10 공통:
#   - /etc/group 에서 root 그룹(GID=0) 의 멤버 목록 확인
#   - root 그룹 네 번째 필드(멤버)가 비어있거나 root 만 있으면 양호
#   - wheel 그룹 멤버도 참고로 표시 (Linux 에서 sudo 권한 그룹이므로)

h_U_08_meta() {
    cat <<'JSON'
{
  "code": "U-08",
  "title": "관리자 그룹에 최소한의 계정 포함",
  "severity": "중",
  "category": "계정 관리",
  "purpose": "관리자 그룹에 최소한의 필요 계정만 존재하는지 확인하여 불필요한 권한 남용을 점검하기 위함",
  "threat": "시스템을 관리하는 root 계정이 속한 그룹은 시스템 운영 파일에 대한 접근 권한이 부여되어 있으므로 해당 관리자 그룹에 속한 계정이 비인가자에게 유출될 경우, 관리자 권한으로 시스템에 접근하여 계정정보 유출, 환경설정 파일 및 디렉터리 변조 등의 위험이 존재함",
  "criterion_good": "관리자 그룹에 불필요한 계정이 등록되어 있지 않은 경우",
  "criterion_bad": "관리자 그룹에 불필요한 계정이 등록된 경우",
  "action_method": "관리자 그룹에 등록된 계정 확인 후 불필요한 계정 제거하도록 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "시스템 관리자 그룹에 최소한(root 계정과 시스템 관리에 허용된 계정)의 계정만 존재 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-08 (2026 ver.)"
  ]
}
JSON
}

_u_08_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: getent group root, awk -F: '\$1==\"root\"||\$3==\"0\"' /etc/group"
        echo
        echo "# 결과: root 그룹(GID=0) 명시적 멤버"
        local _members
        _members=$(_u08_root_group_members 2>/dev/null || true)
        if [[ -z "$_members" ]]; then
            echo "(없음 — root 그룹 명시적 멤버 없음)"
        else
            printf '%s\n' "$_members"
        fi
        echo
        echo "# wheel 그룹 멤버 (참고)"
        getent group wheel 2>&1 || true
    } | _evidence_capture "$label"
}


_u08_group_file() { printf '/etc/group'; }

# root 그룹(GID=0) 의 명시적 멤버 목록 반환 (비어있을 수 있음)
_u08_root_group_members() {
    awk -F: '($1=="root" || $3=="0") {print $4; exit}' "$(_u08_group_file)" 2>/dev/null \
        | tr ',' '\n' | grep -v '^$' || true
}

# wheel 그룹 멤버 목록
_u08_wheel_members() {
    awk -F: '$1=="wheel"{print $4}' "$(_u08_group_file)" 2>/dev/null \
        | tr ',' '\n' | grep -v '^$' || true
}

h_U_08_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_08_capture_state "$KISA_PHASE"
    fi

    local group_f; group_f="$(_u08_group_file)"
    if [[ ! -r "$group_f" ]]; then
        printf '점검 불가 — /etc/group 파일을 읽을 수 없음'
        return 2
    fi

    local members
    members=$(_u08_root_group_members)

    if [[ -z "$members" ]]; then
        printf '양호 — root 그룹(GID=0)에 명시적 멤버 없음'
        return 0
    fi

    local cnt
    cnt=$(printf '%s\n' "$members" | grep -c '.')
    printf '취약 — root 그룹에 계정 %s개 등록됨: %s (담당자 확인 필요)' \
           "$cnt" "$(printf '%s' "$members" | tr '\n' ',')"
    return 1
}

h_U_08_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        printf '(dry-run) [MANUAL] root 그룹 멤버 목록 확인 후 gpasswd -d 수동 수행 필요'
        return 0
    fi

    local members
    members=$(_u08_root_group_members)

    if [[ -z "$members" ]]; then
        printf '양호 — 이미 root 그룹에 불필요한 멤버 없음 (조치 불필요)'
        return 0
    fi

    printf '수동 조치 필요 — root 그룹 멤버 검토 후 불필요 계정 제거:\n'
    printf '%s\n' "$members" | while IFS= read -r acct; do
        [[ -z "$acct" ]] && continue
        printf '  계정: %s\n' "$acct"
    done
    printf '\n조치 방법:\n'
    printf '  # grep "^root" /etc/group   -- root 그룹 확인\n'
    printf '  # gpasswd -d <계정명> root  -- 불필요 계정 제거\n'
    printf '  ※ 관리자와 협의 후 제거 여부 결정\n'

    # wheel 그룹 멤버도 안내
    local wheel_members
    wheel_members=$(_u08_wheel_members)
    if [[ -n "$wheel_members" ]]; then
        printf '\n참고) wheel(sudo) 그룹 멤버: %s\n' "$(printf '%s' "$wheel_members" | tr '\n' ',')"
    fi
    return 2
}
