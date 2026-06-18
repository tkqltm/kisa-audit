#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-22: /etc/services 파일 소유자 및 권한 설정 (중요도: 상)
# 카테고리: 파일 및 디렉토리 관리
#
# 점검 내용: /etc/services 파일 소유자(root), 권한(644 이하) 적절성
# 판단 기준:
#   양호: 소유자 root(또는 bin, sys), 권한 644 이하
#   취약: 소유자 root/bin/sys 아님, 또는 권한 644 초과
#
# 조치 전략 (자동):
#   1) backup_file /etc/services
#   2) chown root:root /etc/services
#   3) chmod 644 /etc/services
#   4) restorecon
#
# 롤백 전략:
#   - backup_file 기록으로 restore_file 자동 원복
#
# Rocky 8/9/10 특이사항:
#   - 기본값 root:root 644

h_U_22_meta() {
    cat <<'JSON'
{
  "code": "U-22",
  "title": "/etc/services 파일 소유자 및 권한 설정",
  "severity": "상",
  "category": "파일 및 디렉토리 관리",
  "purpose": "/etc/services 파일을 관리자만 제어할 수 있게 하여 비인가자들의 임의적인 파일 변조를 방지하기 위함",
  "threat": "/etc/services 파일의 접근 권한이 적절하지 않을 경우, 비인가 사용자가 운영 포트 번호를 변경하여 정상적인 서비스를 제한하거나 허용되지 않은 포트를 오픈하여 악성 서비스를 의도적으로 실행할 수 있는 위험이 존재함",
  "criterion_good": "/etc/services 파일의 소유자가 root(또는 bin, sys)이고, 권한이 644 이하인 경우",
  "criterion_bad": "/etc/services 파일의 소유자가 root(또는 bin, sys)가 아니거나, 권한이 644 이하가 아닌 경우",
  "action_method": "/etc/ services 파일 소유자 및 권한 변경 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "/etc/services 파일 권한 적절성 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-22 (2026 ver.)"
  ]
}
JSON
}

_u_22_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: /etc/services 소유자(root/bin/sys) + 권한(644 이하) 검증"
        echo
        echo "## ls -l /etc/services"
        ls -l /etc/services 2>&1 || true
        echo
        echo "## SELinux 컨텍스트"
        ls -lZ /etc/services 2>&1 || true
        echo
        echo "## 권한 비트 + 소유자 검증"
        if [[ -f /etc/services ]]; then
            local _m _u
            _m=$(stat -c '%a' /etc/services 2>/dev/null)
            _u=$(stat -c '%U' /etc/services 2>/dev/null)
            printf 'owner=%s mode=%s\n' "$_u" "$_m"
            printf 'mode & 0133 = %o (0이어야 양호)\n' "$(( 8#$_m & 8#133 ))"
        fi
    } | _evidence_capture "$label"
}


_u22_target_path() { printf '/etc/services'; }

# 소유자 허용 목록: root, bin, sys
_u22_owner_ok() {
    local owner="$1"
    case "$owner" in
        root|bin|sys) return 0 ;;
        *) return 1 ;;
    esac
}

# 644 이하: group w·x, other w·x 없음
_u22_perm_ok() {
    local mode="$1"
    (( (8#${mode:-0} & 8#033) == 0 ))
}

h_U_22_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_22_capture_state "$KISA_PHASE"
    fi

    local tgt; tgt="$(_u22_target_path)"
    if [[ ! -e "$tgt" ]]; then
        printf '%s 파일 없음' "$tgt"
        return 2
    fi

    local owner mode
    owner=$(stat -c '%U' "$tgt" 2>/dev/null)
    mode=$(stat -c '%a' "$tgt" 2>/dev/null)

    local issues=()
    _u22_owner_ok "$owner" || issues+=("소유자=${owner}(root/bin/sys 아님)")
    _u22_perm_ok "$mode"   || issues+=("권한=${mode}(644 초과)")

    if [[ ${#issues[@]} -eq 0 ]]; then
        printf '양호 — 소유자=%s, 권한=%s' "$owner" "$mode"
        return 0
    fi

    printf '취약 — %s' "$(IFS=', '; printf '%s' "${issues[*]}")"
    return 1
}

h_U_22_apply() {
    local tgt; tgt="$(_u22_target_path)"

    if [[ "${1:-}" == "--dry-run" ]]; then
        printf '(dry-run) chown root:root %s && chmod 644 %s' "$tgt" "$tgt"
        return 0
    fi

    if [[ ! -e "$tgt" ]]; then
        printf '조치 실패 — %s 파일 없음' "$tgt"
        return 1
    fi

    local owner mode
    owner=$(stat -c '%U' "$tgt" 2>/dev/null)
    mode=$(stat -c '%a' "$tgt" 2>/dev/null)

    if _u22_owner_ok "$owner" && _u22_perm_ok "$mode"; then
        printf '양호 — 이미 소유자=%s, 권한=%s (변경 불필요)' "$owner" "$mode"
        return 0
    fi

    backup_file "$tgt"

    _u22_owner_ok "$owner" || chown root:root "$tgt"
    _u22_perm_ok "$mode"   || chmod 644 "$tgt"

    command -v restorecon >/dev/null 2>&1 && restorecon "$tgt" 2>/dev/null || true

    local new_mode; new_mode=$(stat -c '%a' "$tgt" 2>/dev/null)
    local new_owner; new_owner=$(stat -c '%U' "$tgt" 2>/dev/null)
    printf '조치 완료 — /etc/services 소유자=%s, 권한=%s 로 설정' "$new_owner" "$new_mode"
    return 0
}
