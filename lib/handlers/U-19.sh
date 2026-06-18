#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-19: /etc/hosts 파일 소유자 및 권한 설정 (중요도: 상)
# 카테고리: 파일 및 디렉토리 관리
#
# 점검 내용: /etc/hosts 파일 소유자(root), 권한(644 이하) 적절성
# 판단 기준:
#   양호: 소유자 root, 권한 644 이하 (other 쓰기·실행 없음, group 쓰기·실행 없음)
#   취약: 소유자 root 아님, 또는 권한 644 초과
#
# 조치 전략 (자동):
#   1) backup_file /etc/hosts
#   2) chown root:root /etc/hosts
#   3) chmod 644 /etc/hosts
#   4) restorecon SELinux 복원
#
# 롤백 전략:
#   - backup_file 기록으로 restore_file 자동 원복
#
# Rocky 8/9/10 특이사항:
#   - 기본값 root:root 644. 내용 변경 없이 권한만 조치.
#   - SELinux 컨텍스트: system_u:object_r:net_conf_t:s0

h_U_19_meta() {
    cat <<'JSON'
{
  "code": "U-19",
  "title": "/etc/hosts 파일 소유자 및 권한 설정",
  "severity": "상",
  "category": "파일 및 디렉토리 관리",
  "purpose": "/etc/hosts 파일을 관리자만 제어할 수 있게 하여 비인가자들의 임의적인 파일 변조를 방지하기 위함",
  "threat": "- /etc/hosts 파일에 비인가자가 쓰기 권한이 부여된 경우, 공격자는 /etc/hosts 파일에 악의적인 시스템을 등록하여, 이를 통해 정상적인 DNS를 우회하여 악성 사이트로의 접속을 유도하는 파밍(Pharming) 공격 등에 악용될 수 있는 위험이 존재함 - /etc/hosts 파일에 소유자의 쓰기 권한이 부여된 경우, 일반 사용자 권한으로 /etc/hosts 파일에 변조된 IP주소를 등록하여 정상적인 DNS를 방해하고 악성 사이트로의 접속을 유도하는 파밍(Pharming) 공격 등에 악용될 수 있는 위험이 존재함",
  "criterion_good": "/etc/hosts 파일의 소유자가 root이고, 권한이 644 이하인 경우",
  "criterion_bad": "/etc/hosts 파일의 소유자가 root가 아니거나, 권한이 644 이하가 아닌 경우",
  "action_method": "/etc/hosts 파일 소유자 및 권한 변경 설정",
  "action_impact": "/etc/hosts 파일에 시스템 정보가 설정된 경우 해당 파일을 참조하는 서비스에 영향을 미칠 수 있음",
  "method": [
    "/etc/hosts 파일의 권한 적절성 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-19 (2026 ver.)"
  ]
}
JSON
}

_u_19_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: /etc/hosts 소유자(root) + 권한(644 이하) 검증"
        echo
        echo "## ls -l /etc/hosts"
        ls -l /etc/hosts 2>&1 || true
        echo
        echo "## /etc/hosts 내용"
        cat /etc/hosts 2>&1 | head -30 || true
        echo
        echo "## 권한 비트 검증"
        if [[ -f /etc/hosts ]]; then
            local _m _u
            _m=$(stat -c '%a' /etc/hosts 2>/dev/null)
            _u=$(stat -c '%U' /etc/hosts 2>/dev/null)
            printf 'owner=%s mode=%s\n' "$_u" "$_m"
        fi
    } | _evidence_capture "$label"
}


_u19_target_path() { printf '/etc/hosts'; }

# 644 이하: group w·x, other w·x 없음
_u19_perm_ok() {
    local mode="$1"
    (( (8#${mode:-0} & 8#033) == 0 ))
}

h_U_19_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_19_capture_state "$KISA_PHASE"
    fi

    local tgt; tgt="$(_u19_target_path)"
    if [[ ! -e "$tgt" ]]; then
        printf '%s 파일 없음' "$tgt"
        return 2
    fi

    local owner mode
    owner=$(stat -c '%U' "$tgt" 2>/dev/null)
    mode=$(stat -c '%a' "$tgt" 2>/dev/null)

    local issues=()
    [[ "$owner" != "root" ]] && issues+=("소유자=${owner}(root 아님)")
    _u19_perm_ok "$mode" || issues+=("권한=${mode}(644 초과)")

    if [[ ${#issues[@]} -eq 0 ]]; then
        printf '양호 — 소유자=root, 권한=%s (644 이하)' "$mode"
        return 0
    fi

    printf '취약 — %s' "$(IFS=', '; printf '%s' "${issues[*]}")"
    return 1
}

h_U_19_apply() {
    local tgt; tgt="$(_u19_target_path)"

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

    if [[ "$owner" == "root" ]] && _u19_perm_ok "$mode"; then
        printf '양호 — 이미 소유자=root, 권한=%s (변경 불필요)' "$mode"
        return 0
    fi

    backup_file "$tgt"

    if [[ "$owner" != "root" ]]; then
        chown root:root "$tgt"
    fi

    if ! _u19_perm_ok "$mode"; then
        chmod 644 "$tgt"
    fi

    command -v restorecon >/dev/null 2>&1 && restorecon "$tgt" 2>/dev/null || true

    local new_mode; new_mode=$(stat -c '%a' "$tgt" 2>/dev/null)
    local new_owner; new_owner=$(stat -c '%U' "$tgt" 2>/dev/null)
    printf '조치 완료 — /etc/hosts 소유자=%s, 권한=%s 로 설정' "$new_owner" "$new_mode"
    return 0
}
