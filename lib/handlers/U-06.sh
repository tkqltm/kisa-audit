#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-06: 사용자 계정 su 기능 제한 (중요도: 상)
# KISA 가이드: su 명령어를 wheel 그룹에 속한 사용자만 사용하도록 제한
#
# Rocky 8/9/10 공통 전략 (PAM 방식 우선):
#   - /etc/pam.d/su 에 'auth required pam_wheel.so use_uid' 라인 존재 여부 확인
#   - 없으면 해당 라인 삽입 (기존 주석 처리된 라인 활성화 또는 신규 삽입)
#   - wheel 그룹에 root 이 포함되어 있는지 확인 (/etc/group)
#   - /usr/bin/su 의 그룹이 wheel, 권한 4750 이면 추가 양호 지표(선택)
#
# PAM 방식과 파일 권한 방식 중 어느 한 쪽만 설정되어도 KISA 기준 양호.
# 본 핸들러는 PAM 방식(pam_wheel.so) 을 우선 적용.
#
# 롤백 전략:
#   - restore_file /etc/pam.d/su
#   - /usr/bin/su 원래 권한 복원 (backup_file 로 stat 저장)

h_U_06_meta() {
    cat <<'JSON'
{
  "code": "U-06",
  "title": "사용자 계정 su 기능 제한",
  "severity": "상",
  "category": "계정 관리",
  "purpose": "su 관련 그룹만 su 명령어 사용 권한이 부여되어 있는지 점검하여 su 그룹에 포함되지 않은 일반 사용자의 su 명령 사용을 원천적으로 차단하는지 확인하기 위함",
  "threat": "무분별한 사용자 변경으로 타 사용자 소유의 파일을 변경할 수 있으며 root 계정으로 변경하는 경우 관리자 권한을 획득할 수 있는 위험이 존재함",
  "criterion_good": "su 명령어를 특정 그룹에 속한 사용자만 사용하도록 제한된 경우 ※ 일반 사용자 계정 없이 root 계정만 사용하는 경우 su 명령어 사용 제한 불필요",
  "criterion_bad": "su 명령어를 모든 사용자가 사용하도록 설정된 경우",
  "action_method": "PAM 모듈 설정 또는 su 명령어 허용 그룹 생성 후 su 명령어 일반 사용자 권한 제거하도록 설정",
  "action_impact": "그룹에 추가된 계정들은 모든 Session 종료 후 재 로그인 시 su 명령어 사용 가능",
  "method": [
    "su 명령어 사용을 허용하는 사용자를 지정한 그룹이 설정 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-06 (2026 ver.)"
  ]
}
JSON
}

_u_06_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: su 명령어 wheel 그룹 제한 + pam_wheel 설정"
        echo
        echo "## /etc/pam.d/su 의 pam_wheel 라인"
        if [[ -f /etc/pam.d/su ]]; then
            grep -nE 'pam_wheel' /etc/pam.d/su 2>/dev/null \
                || echo "(pam_wheel 라인 없음 — 누구나 su 가능, 취약)"
            echo
            echo "### /etc/pam.d/su 활성 라인 (주석 제외)"
            grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/pam.d/su 2>/dev/null
        else
            echo "(/etc/pam.d/su 없음)"
        fi
        echo
        echo "## /etc/login.defs SU_WHEEL_ONLY"
        grep -nE '^[[:space:]]*SU_WHEEL_ONLY' /etc/login.defs 2>/dev/null || echo "(설정 없음)"
        echo
        echo "## wheel 그룹 멤버"
        getent group wheel 2>&1 || echo "(wheel 그룹 없음)"
        echo
        echo "## /usr/bin/su SUID 권한"
        ls -l /usr/bin/su 2>&1 || true
    } | _evidence_capture "$label"
}


_u06_pam_su()    { printf '/etc/pam.d/su'; }
_u06_su_bin()    { printf '/usr/bin/su'; }
_u06_group_file(){ printf '/etc/group'; }

# /etc/pam.d/su 에 pam_wheel.so use_uid 또는 group=wheel 가 활성화되어 있는가?
_u06_pam_wheel_active() {
    grep -qE '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so' "$(_u06_pam_su)" 2>/dev/null
}

# /usr/bin/su 의 그룹이 wheel 이고 권한 4750 인가?
_u06_su_bin_restricted() {
    local su; su="$(_u06_su_bin)"
    [[ -f "$su" ]] || return 1
    local grp perm
    grp=$(stat -c '%G' "$su" 2>/dev/null)
    perm=$(stat -c '%a' "$su" 2>/dev/null)
    [[ "$grp" == "wheel" && "$perm" == "4750" ]]
}

# wheel 그룹이 /etc/group 에 존재하는가?
_u06_wheel_exists() {
    grep -qE '^wheel:' "$(_u06_group_file)" 2>/dev/null
}

h_U_06_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_06_capture_state "$KISA_PHASE"
    fi

    local pam_ok=0 bin_ok=0

    _u06_pam_wheel_active && pam_ok=1
    _u06_su_bin_restricted && bin_ok=1

    # pam_wheel.so use_uid 가 동작하려면 wheel 그룹에 root 멤버 필수
    local wheel_has_root=0
    getent group wheel 2>/dev/null | awk -F: '{print $4}' | tr ',' '\n' | grep -qx root && wheel_has_root=1

    if (( pam_ok )) && (( wheel_has_root )); then
        printf '양호 — su 제한됨(pam_wheel.so use_uid 활성, wheel 에 root 포함)'
        return 0
    fi
    if (( pam_ok )) && (( ! wheel_has_root )); then
        printf '취약 — pam_wheel.so 활성이나 wheel 그룹에 root 멤버 없음(su 차단 위험)'
        return 1
    fi
    if (( bin_ok )); then
        printf '양호 — su 제한됨(/usr/bin/su 그룹=wheel, 권한=4750)'
        return 0
    fi

    # 일반 사용자 계정 존재 여부 확인 (UID 1000+)
    # KISA 가이드: 일반 사용자 계정 없이 root 계정만 사용하는 경우 su 명령어 사용 제한 불필요 → 양호.
    local user_count
    user_count=$(awk -F: '($3>=1000 && $1!="nobody"){print $1}' /etc/passwd 2>/dev/null | wc -l | tr -d ' ')
    if (( user_count == 0 )); then
        printf '양호 — 일반 계정 없음(root 단일 운영), su 제한 불필요'
        return 0
    fi

    printf '취약 — su 제한 미설정(pam_wheel.so 비활성)'
    return 1
}

h_U_06_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        printf '(dry-run) /etc/pam.d/su 에 pam_wheel.so use_uid 삽입 예정; wheel 그룹 미존재 시 생성'
        return 0
    fi

    # wheel 그룹 생성 + root 멤버 보장 — pam_wheel 활성 여부와 무관하게 항상 적용
    if ! _u06_wheel_exists; then
        groupadd wheel 2>/dev/null || true
    fi
    if ! getent group wheel 2>/dev/null | awk -F: '{print $4}' | tr ',' '\n' | grep -qx root; then
        gpasswd -a root wheel >/dev/null 2>&1 || true
    fi

    # pam_wheel 이미 활성이고 wheel 에 root 있으면 추가 작업 불필요
    if _u06_pam_wheel_active && getent group wheel 2>/dev/null | awk -F: '{print $4}' | tr ',' '\n' | grep -qx root; then
        printf '양호 — 이미 pam_wheel.so use_uid 설정 + wheel 그룹 root 멤버 보장됨'
        return 0
    fi

    local pam_su; pam_su="$(_u06_pam_su)"

    if [[ ! -f "$pam_su" ]]; then
        printf '조치 실패 — /etc/pam.d/su 파일 없음'
        return 1
    fi

    backup_file "$pam_su"

    # 주석 처리된 pam_wheel.so 라인이 있으면 활성화, 없으면 auth 섹션 첫 줄 앞에 삽입
    local tmp
    tmp="$KISA_TMP_DIR/tmp/u06.$$.$RANDOM"
    local inserted=0

    while IFS= read -r line; do
        # 주석 처리된 pam_wheel 라인 → 활성화
        if printf '%s' "$line" | grep -qE '^[[:space:]]*#[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so'; then
            if (( ! inserted )); then
                printf 'auth\t\trequired\tpam_wheel.so use_uid\n' >> "$tmp"
                inserted=1
            fi
            printf '%s\n' "$line" >> "$tmp"
            continue
        fi
        # auth 섹션의 첫 번째 실제 줄 앞에 삽입
        if (( ! inserted )) && printf '%s' "$line" | grep -qE '^[[:space:]]*auth'; then
            printf 'auth\t\trequired\tpam_wheel.so use_uid\n' >> "$tmp"
            inserted=1
        fi
        printf '%s\n' "$line" >> "$tmp"
    done < "$pam_su"

    # 한 번도 삽입 못 한 경우 끝에 추가
    if (( ! inserted )); then
        printf 'auth\t\trequired\tpam_wheel.so use_uid\n' >> "$tmp"
    fi

    local om ou og
    om=$(stat -c '%a' "$pam_su" 2>/dev/null); ou=$(stat -c '%u' "$pam_su" 2>/dev/null); og=$(stat -c '%g' "$pam_su" 2>/dev/null)
    mv -f "$tmp" "$pam_su"
    [[ -n "$om" ]] && chmod "$om" "$pam_su" 2>/dev/null || true
    [[ -n "$ou" && -n "$og" ]] && chown "$ou:$og" "$pam_su" 2>/dev/null || true
    command -v restorecon >/dev/null 2>&1 && restorecon "$pam_su" 2>/dev/null || true

    if _u06_pam_wheel_active; then
        printf '조치 완료 — pam_wheel.so use_uid 삽입 및 wheel 그룹 확인'
        return 0
    else
        restore_file "$pam_su"
        printf '조치 실패 — pam_wheel.so 삽입 검증 실패, 원복 완료'
        return 1
    fi
}
