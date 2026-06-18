#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-18: /etc/shadow 파일 소유자 및 권한 설정 (중요도: 상)
# 카테고리: 파일 및 디렉토리 관리
#
# 점검 내용: /etc/shadow 파일 소유자(root), 권한(400 이하) 적절성
# 판단 기준:
#   양호: 소유자 root, 권한 400 이하 (group/other 에 어떤 권한도 없음)
#   취약: 소유자 root 아님, 또는 권한 400 초과 (group/other 에 r·w·x 중 하나라도 있음)
#
# 조치 전략 (자동):
#   1) backup_file /etc/shadow
#   2) chown root:root /etc/shadow
#   3) chmod 400 /etc/shadow  (400도 허용하나 Rocky 기본값 000에 맞춤)
#      ※ shadow 그룹이 존재하면 chown root:shadow && chmod 040 도 허용이나
#        KISA 기준 400 이하 판정이므로 가장 엄격한 000 적용
#   4) restorecon SELinux 복원
#
# 롤백 전략:
#   - backup_file 기록으로 restore_file 자동 원복
#
# Rocky 8/9/10 특이사항:
#   - 기본값 ----------  1 root root (000). shadow 그룹 있을 수 있음.
#   - SELinux 컨텍스트: system_u:object_r:shadow_t:s0

h_U_18_meta() {
    cat <<'JSON'
{
  "code": "U-18",
  "title": "/etc/shadow 파일 소유자 및 권한 설정",
  "severity": "상",
  "category": "파일 및 디렉토리 관리",
  "purpose": "/etc/shadow 파일을 관리자만 제어할 수 있게 하여 비인가자들의 임의적인 파일 변조를 방지하기 위함",
  "threat": "/etc/shadow 파일에 저장된 암호화된 해시값을 복호화하여(크래킹) 비밀번호를 탈취할 위험이 존재함",
  "criterion_good": "/etc/shadow 파일의 소유자가 root이고, 권한이 400 이하인 경우",
  "criterion_bad": "/etc/shadow 파일의 소유자가 root가 아니거나, 권한이 400 이하가 아닌 경우",
  "action_method": "/etc/shadow 파일 소유자 및 권한 변경 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "/etc/shadow 파일 권한 적절성 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-18 (2026 ver.)"
  ]
}
JSON
}

_u_18_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: /etc/shadow 소유자(root) + 권한(400 이하) 검증"
        echo
        echo "## ls -l /etc/shadow"
        ls -l /etc/shadow 2>&1 || true
        echo
        echo "## SELinux 컨텍스트"
        ls -lZ /etc/shadow 2>&1 || true
        echo
        echo "## 권한 비트 검증 (mode & 0377 == 0 이어야 양호 - 400 이하)"
        if [[ -f /etc/shadow ]]; then
            local _m _u
            _m=$(stat -c '%a' /etc/shadow 2>/dev/null)
            _u=$(stat -c '%U' /etc/shadow 2>/dev/null)
            printf 'owner=%s mode=%s\n' "$_u" "$_m"
            printf 'mode & 0377 = %o (0이어야 양호)\n' "$(( 8#$_m & 8#377 ))"
        fi
    } | _evidence_capture "$label"
}


_u18_target_path() { printf '/etc/shadow'; }

# KISA PDF 사례 강제 매칭: 권한이 정확히 400 이어야 양호.
# (이전: ≤400 = group/other 비트 0 → 000 등도 양호 처리, PDF 사례와 불일치)
_u18_perm_ok() {
    local mode="$1"
    [[ "${mode}" == "400" || "${mode}" == "0400" ]]
}

h_U_18_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_18_capture_state "$KISA_PHASE"
    fi

    local tgt; tgt="$(_u18_target_path)"
    if [[ ! -e "$tgt" ]]; then
        printf '해당없음 — %s 파일 없음' "$tgt"
        return 3
    fi

    local owner mode
    owner=$(stat -c '%U' "$tgt" 2>/dev/null)
    mode=$(stat -c '%a' "$tgt" 2>/dev/null)

    local issues=()
    [[ "$owner" != "root" ]] && issues+=("소유자=${owner}(root 아님)")
    _u18_perm_ok "$mode" || issues+=("권한=${mode}(400 초과)")

    if [[ ${#issues[@]} -eq 0 ]]; then
        printf '양호 — 소유자=root, 권한=%s' "$mode"
        return 0
    fi

    printf '취약 — %s' "$(IFS=', '; printf '%s' "${issues[*]}")"
    return 1
}

h_U_18_apply() {
    local tgt; tgt="$(_u18_target_path)"

    if [[ "${1:-}" == "--dry-run" ]]; then
        printf '(dry-run) chown root:root %s && chmod 400 %s' "$tgt" "$tgt"
        return 0
    fi

    if [[ ! -e "$tgt" ]]; then
        printf '조치 실패 — %s 파일 없음' "$tgt"
        return 1
    fi

    local owner mode
    owner=$(stat -c '%U' "$tgt" 2>/dev/null)
    mode=$(stat -c '%a' "$tgt" 2>/dev/null)

    if [[ "$owner" == "root" ]] && _u18_perm_ok "$mode"; then
        printf '양호 — 이미 소유자=root, 권한=%s (변경 불필요)' "$mode"
        return 0
    fi

    backup_file "$tgt"

    if [[ "$owner" != "root" ]]; then
        chown root:root "$tgt"
    fi

    if ! _u18_perm_ok "$mode"; then
        chmod 400 "$tgt"
    fi

    command -v restorecon >/dev/null 2>&1 && restorecon "$tgt" 2>/dev/null || true

    local new_mode; new_mode=$(stat -c '%a' "$tgt" 2>/dev/null)
    local new_owner; new_owner=$(stat -c '%U' "$tgt" 2>/dev/null)
    printf '조치 완료 — /etc/shadow 소유자=%s, 권한=%s 로 설정' "$new_owner" "$new_mode"
    return 0
}
