#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-04: 비밀번호 파일 보호 (중요도: 상)
# KISA 가이드: /etc/passwd 두 번째 필드가 'x' (shadow 비밀번호 사용)
#
# Rocky 8/9/10 공통:
#   - 현대 Linux 는 기본으로 shadow 를 사용. /etc/passwd 두 번째 필드가 'x' 이면 양호.
#   - 취약한 경우(필드에 해시 직접 저장): pwconv 명령으로 shadow 전환.
#   - /etc/shadow 파일 존재 여부도 확인.
#
# 조치 전략:
#   1) /etc/passwd 에서 두 번째 필드가 'x' 가 아닌 계정 탐지
#   2) 취약하면 pwconv 실행
#   3) /etc/shadow 파일 퍼미션 확인 (000 또는 root 소유)
#
# 롤백 전략:
#   - backup_file /etc/passwd /etc/shadow
#   - pwunconv (shadow → passwd 직접 기록으로 되돌림; 비권장)

h_U_04_meta() {
    cat <<'JSON'
{
  "code": "U-04",
  "title": "비밀번호 파일 보호",
  "severity": "상",
  "category": "계정 관리",
  "purpose": "일부 오래된 시스템의 경우 /etc/passwd 파일에 비밀번호가 평문으로 저장되므로 사용자 계정 비밀번호가 암호화되어 저장되어 있는지 점검하여 비인가자의 비밀번호 파일 접근 시에도 사용자 계정 비밀번호가 안전하게 관리되고 있는지 확인하기 위함",
  "threat": "사용자 계정 비밀번호가 저장된 파일이 유출 또는 탈취 시 평문으로 저장된 비밀번호 정보가 노출 위험이 존재함",
  "criterion_good": "쉐도우 비밀번호를 사용하거나, 비밀번호를 암호화하여 저장하는 경우",
  "criterion_bad": "쉐도우 비밀번호를 사용하지 않고, 비밀번호를 암호화하여 저장하지 않는 경우",
  "action_method": "비밀번호 암호화 저장·관리 설정",
  "action_impact": "HP-UX 경우 Trusted Mode로 전환 시 파일 시스템 구조가 변경되어 운영 중인 서비스에 문제가 발생할 수 있으므로 충분한 테스트를 거친 후 Trusted Mode로의 전환이 필요함",
  "method": [
    "시스템의 사용자 계정(root, 일반 사용자) 정보가 저장된 파일(/etc/passwd, /etc/shadow 등)에 사용자 계정 비밀번호가 암호화 저장 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-04 (2026 ver.)"
  ]
}
JSON
}

_u_04_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: /etc/passwd shadow 사용 여부 + /etc/shadow 권한"
        echo
        echo "## /etc/passwd, /etc/shadow ls -l"
        ls -l /etc/passwd /etc/shadow 2>&1 || true
        echo
        echo "## /etc/passwd 두 번째 필드(shadow 미사용) 검사"
        echo "(shadow 미사용 계정만 출력 - 'x'/'!'/'*' 외 값)"
        awk -F: '($2 != "x" && $2 != "!" && $2 != "*" && $2 != "!!" && $2 != "") {print "  ! " $1 " : " $2}' /etc/passwd 2>/dev/null \
            | head -20 || echo "(모두 shadow 사용 또는 잠금)"
        echo
        echo "## /etc/passwd 전체 라인 수 / 비-x 라인 수"
        printf 'total=%s\n' "$(wc -l < /etc/passwd 2>/dev/null)"
        printf 'non-shadow=%s\n' "$(awk -F: '($2 != "x" && $2 != "!" && $2 != "*" && $2 != "!!" && $2 != "") {c++} END{print c+0}' /etc/passwd 2>/dev/null)"
        echo
        echo "## pwck 결과(요약, 처음 30줄)"
        if command -v pwck >/dev/null 2>&1; then
            pwck -r 2>&1 | head -30 || true
        fi
        echo
        echo "## /etc/shadow 빈 패스워드 계정 검사"
        if [[ -r /etc/shadow ]]; then
            awk -F: '($2 == "") {print "  ! " $1 " : 빈 패스워드"}' /etc/shadow 2>/dev/null \
                | head -20 || echo "(빈 패스워드 없음)"
        else
            echo "(/etc/shadow 읽기 권한 없음)"
        fi
    } | _evidence_capture "$label"
}


_u04_passwd()  { printf '/etc/passwd'; }
_u04_shadow()  { printf '/etc/shadow'; }

# passwd 에서 shadow 미사용 계정 목록 반환 (두 번째 필드가 'x' 또는 '!' 또는 '*' 이 아닌 계정)
_u04_non_shadow_accounts() {
    awk -F: '($2 != "x" && $2 != "!" && $2 != "*" && $2 != "!!" && $2 != "") {print $1}' \
        "$(_u04_passwd)" 2>/dev/null
}

h_U_04_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_04_capture_state "$KISA_PHASE"
    fi

    local passwd_f; passwd_f="$(_u04_passwd)"
    local shadow_f; shadow_f="$(_u04_shadow)"

    if [[ ! -r "$passwd_f" ]]; then
        printf '/etc/passwd 읽기 실패'
        return 2
    fi

    # shadow 파일 존재 확인
    if [[ ! -f "$shadow_f" ]]; then
        printf '취약 — /etc/shadow 파일 없음, shadow 비밀번호 미사용'
        return 1
    fi

    local bad
    bad=$(_u04_non_shadow_accounts)
    if [[ -n "$bad" ]]; then
        local cnt
        cnt=$(printf '%s\n' "$bad" | wc -l | tr -d ' ')
        printf '취약 — 비shadow 계정 %s개: %s' "$cnt" "$(printf '%s' "$bad" | tr '\n' ',')"
        return 1
    fi

    printf '양호 — shadow 비밀번호 사용 중, /etc/passwd 두 번째 필드 모두 x'
    return 0
}

h_U_04_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        printf '(dry-run) pwconv 로 shadow 비밀번호 전환 예정; /etc/passwd /etc/shadow 백업'
        return 0
    fi

    local passwd_f; passwd_f="$(_u04_passwd)"
    local shadow_f; shadow_f="$(_u04_shadow)"

    local bad
    bad=$(_u04_non_shadow_accounts)

    if [[ -z "$bad" ]] && [[ -f "$shadow_f" ]]; then
        printf '양호 — 이미 shadow 비밀번호 사용 중, 조치 불필요'
        return 0
    fi

    backup_file "$passwd_f"
    backup_file "$shadow_f"

    if ! command -v pwconv >/dev/null 2>&1; then
        printf '조치 실패 — pwconv 명령 없음, 수동 조치 필요'
        return 1
    fi

    if ! pwconv 2>/dev/null; then
        restore_file "$passwd_f"
        restore_file "$shadow_f"
        printf '조치 실패 — pwconv 실패, 원복 완료'
        return 1
    fi

    # 조치 후 재확인
    bad=$(_u04_non_shadow_accounts)
    if [[ -n "$bad" ]]; then
        printf '조치 실패 — pwconv 후에도 비shadow 계정 잔존: %s' "$(printf '%s' "$bad" | tr '\n' ',')"
        return 1
    fi

    printf '조치 완료 — pwconv 로 shadow 비밀번호 전환 성공'
}
