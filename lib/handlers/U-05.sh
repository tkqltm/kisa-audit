#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-05: root 이외의 UID=0 금지 (중요도: 상)
# KISA 가이드: /etc/passwd 에서 UID=0 계정이 root 외에 존재하면 취약
#
# 자동 조치 불가 사유:
#   - UID 변경(usermod -u) 시 해당 계정 소유 파일 권한이 깨질 수 있음
#   - 운영 목적으로 의도적으로 설정된 경우 서비스 장애 유발 가능
#   - userdel 은 홈 디렉터리·메일 스풀 삭제 등 부작용 위험
#   → apply 는 return 2 (manual) 처리
#
# Rocky 8/9/10 공통:
#   - awk -F: '($3==0){print}' /etc/passwd 로 점검
#   - root 외 UID=0 계정 발견 시 취약 판정

h_U_05_meta() {
    cat <<'JSON'
{
  "code": "U-05",
  "title": "root 이외의 UID가 ‘0’ 금지",
  "severity": "상",
  "category": "계정 관리",
  "purpose": "root 계정과 동일한 UID가 존재하는지 점검하여 root 권한이 일반 사용자 계정이나 비인가자의 접근 위협에 안전하게 보호되고 있는지 확인하기 위함",
  "threat": "- root 계정과 동일한 UID가 설정되어 있는 일반 사용자 계정도 root 권한을 부여받아 관리자가 실행할 수 있는 모든 작업이 가능한 위험이 존재함(서비스 시작, 중지, 재부팅, root 권한 파일 편집 등) - root 계정과 동일한 UID를 사용하므로 사용자 감사 추적 시 어려움 발생 위험이 존재함",
  "criterion_good": "root 계정과 동일한 UID를 갖는 계정이 존재하지 않는 경우",
  "criterion_bad": "root 계정과 동일한 UID를 갖는 계정이 존재하는 경우",
  "action_method": "- UID가 0으로 설정된 계정을 0 이외의 중복되지 않은 UID로 변경 또는 불필요한 계정인 경우 제거하도록 설정 - (사용 중인 계정인 경우 명령어를 통한 조치가 적용되지 않을 수 있으므로 /etc/passwd 파일을 통해 변경)",
  "action_impact": "해당 계정에 관리자 권한이 필요하지 않으면 일반적으로 영향 없음",
  "method": [
    "사용자 계정 정보가 저장된 파일(/etc/passwd, /etc/shadow 등)에 root(UID=0) 계정과 동일한 UID를 가진 계정이 존재 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-05 (2026 ver.)"
  ]
}
JSON
}

_u_05_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: awk -F: '\$3==0' /etc/passwd"
        echo
        echo "# 결과: UID=0 계정 (root 외)"
        local _uid0
        _uid0=$(_u05_uid0_non_root 2>/dev/null || true)
        if [[ -z "$_uid0" ]]; then
            echo "(없음 — UID=0 계정은 root 만 존재)"
        else
            printf '%s\n' "$_uid0"
        fi
        echo
        echo "# /etc/passwd 의 UID=0 라인"
        awk -F: '($3==0) {printf "%s\n", $0}' /etc/passwd 2>/dev/null || true
    } | _evidence_capture "$label"
}


_u05_passwd() { printf '/etc/passwd'; }

# UID=0 계정 목록 (root 제외)
_u05_uid0_non_root() {
    awk -F: '($3 == 0 && $1 != "root") {print $1}' "$(_u05_passwd)" 2>/dev/null
}

h_U_05_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_05_capture_state "$KISA_PHASE"
    fi

    local passwd_f; passwd_f="$(_u05_passwd)"
    if [[ ! -r "$passwd_f" ]]; then
        printf '/etc/passwd 읽기 실패'
        return 2
    fi

    local bad
    bad=$(_u05_uid0_non_root)

    if [[ -z "$bad" ]]; then
        printf '양호 — root 외 UID=0 계정 없음'
        return 0
    fi

    local cnt
    cnt=$(printf '%s\n' "$bad" | grep -c '.')
    printf '취약 — root 외 UID=0 계정 %s개 발견: %s' "$cnt" "$(printf '%s' "$bad" | tr '\n' ',')"
    return 1
}

h_U_05_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        printf '(dry-run) [MANUAL] root 외 UID=0 계정 확인 및 usermod/userdel 수동 조치 필요'
        return 0
    fi

    local bad
    bad=$(_u05_uid0_non_root)
    if [[ -z "$bad" ]]; then
        printf '양호 — 이미 root 외 UID=0 계정 없음 (조치 불필요)'
        return 0
    fi

    printf '수동 조치 필요 — root 외 UID=0 계정: %s\n' "$(printf '%s' "$bad" | tr '\n' ',')"
    printf '조치 방법:\n'
    local acct
    while IFS= read -r acct; do
        [[ -z "$acct" ]] && continue
        printf '  1) 불필요 계정이면: userdel %s\n' "$acct"
        printf '  2) 필요 계정이면 : usermod -u <새UID> %s  (겹치지 않는 UID 선택)\n' "$acct"
    done <<< "$bad"
    printf '  ※ UID 변경 후 해당 계정 소유 파일 권한 재확인 필요\n'
    return 2
}
