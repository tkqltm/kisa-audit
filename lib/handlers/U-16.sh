#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-16: /etc/passwd 파일 소유자 및 권한 설정 (중요도: 상)
# 카테고리: 파일 및 디렉토리 관리
#
# 점검 내용: /etc/passwd 파일 소유자(root), 권한(644 이하) 적절성
# 판단 기준:
#   양호: 소유자 root, 권한 644 이하 (other 쓰기·실행 없음, group 쓰기·실행 없음)
#   취약: 소유자 root 아님, 또는 권한 644 초과 (group/other 쓰기 또는 실행 있음)
#
# 조치 전략 (자동):
#   1) backup_file /etc/passwd
#   2) chown root:root /etc/passwd
#   3) chmod 644 /etc/passwd
#   4) restorecon 으로 SELinux 컨텍스트 복원
#
# 롤백 전략:
#   - backup_file 이 stat 포함 기록 → restore_file 로 자동 원복
#
# Rocky 8/9/10 특이사항:
#   - 기본 설치 시 root:root 644. SELinux 컨텍스트: system_u:object_r:passwd_file_t:s0

h_U_16_meta() {
    cat <<'JSON'
{
  "code": "U-16",
  "title": "/etc/passwd 파일 소유자 및 권한 설정",
  "severity": "상",
  "category": "파일 및 디렉토리 관리",
  "purpose": "/etc/passwd 파일을 관리자만 제어할 수 있게 하여 비인가자들의 임의적인 파일 변조를 방지하기 위함",
  "threat": "비인가자가 /etc/passwd 파일의 사용자 정보를 변조하여 Shell 변경, 사용자 추가/제거 등 root 계정을 포함한 사용자 권한 획득 위험이 존재함",
  "criterion_good": "/etc/passwd 파일의 소유자가 root이고, 권한이 644 이하인 경우",
  "criterion_bad": "/etc/passwd 파일의 소유자가 root가 아니거나, 권한이 644 이하가 아닌 경우",
  "action_method": "/etc/passwd 파일 소유자 및 권한 변경 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "/etc/passwd 파일 권한 적절성 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-16 (2026 ver.)"
  ]
}
JSON
}

_u_16_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: /etc/passwd 소유자(root) + 권한(644 이하) 검증"
        echo
        echo "## ls -l /etc/passwd"
        ls -l /etc/passwd 2>&1 || true
        echo
        echo "## SELinux 컨텍스트"
        ls -lZ /etc/passwd 2>&1 || true
        echo
        echo "## 권한 비트 검증 (mode & 0133 == 0 이어야 양호)"
        if [[ -f /etc/passwd ]]; then
            local _m _u
            _m=$(stat -c '%a' /etc/passwd 2>/dev/null)
            _u=$(stat -c '%U' /etc/passwd 2>/dev/null)
            printf 'owner=%s mode=%s\n' "$_u" "$_m"
            printf 'mode & 0133 = %o (0이어야 양호)\n' "$(( 8#$_m & 8#133 ))"
        fi
    } | _evidence_capture "$label"
}


_u16_target_path() { printf '/etc/passwd'; }

# 권한 숫자가 644 이하인지 확인 (group/other 쓰기·실행 없음)
# 644 이하 = other 에 w·x 없음, group 에 w·x 없음
# 정확히는: bit-AND(mode, 0133) == 0
_u16_perm_ok() {
    local mode="$1"   # octal string, e.g. "644"
    # 양호: group w·x 없음 + other w·x 없음  → mask = 0o033
    (( (8#${mode:-0} & 8#033) == 0 ))
}

h_U_16_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_16_capture_state "$KISA_PHASE"
    fi

    local tgt; tgt="$(_u16_target_path)"
    if [[ ! -e "$tgt" ]]; then
        printf '해당없음 — %s 파일이 존재하지 않음' "$tgt"
        return 3
    fi

    local owner mode
    owner=$(stat -c '%U' "$tgt" 2>/dev/null)
    mode=$(stat -c '%a' "$tgt" 2>/dev/null)

    local issues=()
    [[ "$owner" != "root" ]] && issues+=("소유자=${owner}(root 아님)")
    _u16_perm_ok "$mode" || issues+=("권한=${mode}(644 초과)")

    if [[ ${#issues[@]} -eq 0 ]]; then
        printf '양호 — 소유자=root, 권한=%s (644 이하)' "$mode"
        return 0
    fi

    printf '취약 — %s' "$(IFS=', '; printf '%s' "${issues[*]}")"
    return 1
}

h_U_16_apply() {
    local tgt; tgt="$(_u16_target_path)"

    if [[ "${1:-}" == "--dry-run" ]]; then
        printf '(dry-run) chown root:root %s && chmod 644 %s 예정' "$tgt" "$tgt"
        return 0
    fi

    if [[ ! -e "$tgt" ]]; then
        printf '조치 실패 — %s 파일이 존재하지 않음' "$tgt"
        return 1
    fi

    local owner mode
    owner=$(stat -c '%U' "$tgt" 2>/dev/null)
    mode=$(stat -c '%a' "$tgt" 2>/dev/null)

    # 이미 양호한 경우 idempotent
    if [[ "$owner" == "root" ]] && _u16_perm_ok "$mode"; then
        printf '양호 — 이미 소유자=root, 권한=%s (변경 불필요)' "$mode"
        return 0
    fi

    backup_file "$tgt"

    if [[ "$owner" != "root" ]]; then
        chown root:root "$tgt"
    fi

    if ! _u16_perm_ok "$mode"; then
        chmod 644 "$tgt"
    fi

    command -v restorecon >/dev/null 2>&1 && restorecon "$tgt" 2>/dev/null || true

    local new_mode; new_mode=$(stat -c '%a' "$tgt" 2>/dev/null)
    local new_owner; new_owner=$(stat -c '%U' "$tgt" 2>/dev/null)
    printf '조치 완료 — /etc/passwd 소유자=%s, 권한=%s 로 설정' "$new_owner" "$new_mode"
    return 0
}
