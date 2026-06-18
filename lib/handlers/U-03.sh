#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-03: 계정 잠금 임계값 설정 (중요도: 상)
# KISA 가이드: 로그인 실패 N회(≤10) 이후 계정 잠금, 잠금 해제 대기 시간 설정
#
# Rocky 8/9/10 공통 전략:
#   - /etc/security/faillock.conf 에 deny, unlock_time, silent 설정
#     (authselect with-faillock 기능이 활성화되어 있으면 이 파일이 직접 적용됨)
#   - authselect current 확인 → with-faillock feature 가 없으면 enable-feature 실행
#   - faillock.conf 가 반영되는지 검증: grep deny /etc/security/faillock.conf
#
# Rocky 8 차이점:
#   - authselect select sssd --force 또는 authselect current 가 'minimal' 일 수 있음
#   - pam_faillock.so 가 /etc/pam.d/system-auth 에 직접 삽입되어 있는 경우도 처리
#
# Rocky 10 차이점:
#   - authselect 2.x; 'with-faillock' feature 이름은 동일
#
# 조치 전략:
#   1) /etc/security/faillock.conf 를 backup 후 deny/unlock_time/silent 설정
#   2) authselect 로 with-faillock feature 활성화 (없으면 enable)
#   3) PAM 설정 변경이므로 서비스 재시작 불필요
#
# 롤백 전략:
#   - restore_file /etc/security/faillock.conf
#   - authselect apply-changes (authselect 가 관리하므로 pam.d 는 자동 복원)

h_U_03_meta() {
    cat <<'JSON'
{
  "code": "U-03",
  "title": "계정 잠금 임계값 설정",
  "severity": "상",
  "category": "계정 관리",
  "purpose": "계정 탈취 목적의 무차별 대입 공격 시 해당 계정을 잠금으로써 인증 요청에 응답하는 리소스 낭비를 차단하고 대입 공격으로 인한 비밀번호 노출 공격을 무력화하기 위함",
  "threat": "계정 잠금 임계값이 설정되어 있지 않을 경우, 비밀번호 탈취 공격(무차별 대입 공격, 사전 대입 공격, 추측 공격 등)의 인증 요청에 대해 설정된 비밀번호가 일치할 때까지 지속적으로 응답하여 해당 계정의 비밀번호가 유출될 위험이 존재함",
  "criterion_good": "계정 잠금 임계값이 10회 이하의 값으로 설정된 경우",
  "criterion_bad": "계정 잠금 임계값이 설정되어 있지 않거나, 10회 이하의 값으로 설정되지 않은 경우",
  "action_method": "계정 잠금 임계값을 10회 이하로 설정",
  "action_impact": "- HP-UX: Trusted Mode로 전환 시 파일 시스템 구조가 변경되어 운영 중인 서비스에 문제가 발생할 수 있으므로 충분한 테스트를 거친 후 Trusted Mode로의 전환이 필요함 - LINUX: /etc/pam.d/system-auth 파일 설정 시 라이브러리(/lib/security/pam_tally.so)가 해당 경로에 존재하는지 확인 필요 (존재하지 않는 파일의 경로로 설정하는 경우 시스템 로그인에 장애가 발생할 수 있음) - PAM 모듈을 이용하여 설정할 때 해당 순서를 지키지 않을 경우, 로그인 실패 또는 인증 실패 등 예기치 못한 상황이 발생할 수 있으므로 반드시 순서에 맞게 설정해야 함",
  "method": [
    "사용자 계정 로그인 실패 시 계정 잠금 임계값이 설정 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-03 (2026 ver.)"
  ]
}
JSON
}

_u_03_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: 로그인 실패 N회(≤10) 잠금 + 잠금 해제 대기 시간"
        echo
        echo "## /etc/security/faillock.conf 핵심 값"
        if [[ -f /etc/security/faillock.conf ]]; then
            grep -nE '^[[:space:]]*(deny|unlock_time|fail_interval|even_deny_root|root_unlock_time)' \
                /etc/security/faillock.conf 2>/dev/null \
                || echo "(설정 없음 — 기본값 사용)"
        else
            echo "(/etc/security/faillock.conf 없음 - Rocky 8 이전 환경?)"
        fi
        echo
        echo "## /etc/pam.d/system-auth 의 pam_faillock 라인"
        if [[ -f /etc/pam.d/system-auth ]]; then
            grep -nE 'pam_faillock|pam_tally2' /etc/pam.d/system-auth 2>/dev/null \
                || echo "(pam_faillock 라인 없음)"
        fi
        echo
        echo "## /etc/pam.d/password-auth 의 pam_faillock 라인"
        if [[ -f /etc/pam.d/password-auth ]]; then
            grep -nE 'pam_faillock|pam_tally2' /etc/pam.d/password-auth 2>/dev/null \
                || echo "(pam_faillock 라인 없음)"
        fi
        echo
        echo "## authselect 현재 프로파일"
        if command -v authselect >/dev/null 2>&1; then
            authselect current 2>&1 || true
        fi
        echo
        echo "## faillock 현재 상태 (있다면)"
        if command -v faillock >/dev/null 2>&1; then
            faillock 2>&1 | head -20 || true
        fi
    } | _evidence_capture "$label"
}


_u03_faillock_conf() { printf '/etc/security/faillock.conf'; }
_u03_system_auth()   { printf '/etc/pam.d/system-auth'; }
_u03_password_auth() { printf '/etc/pam.d/password-auth'; }

# faillock.conf 또는 pam.d/system-auth 에서 유효 deny 값 반환
_u03_effective_deny() {
    local fconf; fconf="$(_u03_faillock_conf)"
    local v=""
    if [[ -f "$fconf" ]]; then
        v=$(awk -F'[= \t]+' '/^[[:space:]]*deny[[:space:]]*=/{print $2; exit}' "$fconf" 2>/dev/null)
    fi
    if [[ -z "$v" ]]; then
        # fallback: pam.d/system-auth 에서 deny= 인자 확인
        v=$(grep -E 'pam_faillock\.so|pam_tally2?\.so' "$(_u03_system_auth)" 2>/dev/null \
            | grep -oE 'deny=[0-9]+' | head -1 | cut -d= -f2)
    fi
    printf '%s' "${v:-0}"
}

# authselect 로 with-faillock 이 활성화되어 있는지 확인
_u03_faillock_feature_active() {
    command -v authselect >/dev/null 2>&1 || return 1
    authselect current 2>/dev/null | grep -q 'with-faillock'
}

h_U_03_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_03_capture_state "$KISA_PHASE"
    fi

    local deny; deny="$(_u03_effective_deny)"
    local max_retry="${LOGIN_MAX_RETRY:-5}"

    if [[ "$deny" == "0" ]] || [[ -z "$deny" ]]; then
        printf '취약 — 계정 잠금 임계값 미설정(deny=0 또는 설정 없음)'
        return 1
    fi

    if (( deny > 10 )); then
        printf '취약 — 계정 잠금 임계값 초과(deny=%s,기준≤10)' "$deny"
        return 1
    fi

    # KISA 권고: faillock.conf 에 audit 옵션 (이벤트 로그 기록)
    local fconf; fconf="$(_u03_faillock_conf)"
    if [[ -f "$fconf" ]] && ! grep -qE '^[[:space:]]*audit([[:space:]]|$)' "$fconf"; then
        printf '취약 — 계정 잠금 audit 옵션 미설정 (faillock.conf)'
        return 1
    fi

    printf '양호 — 계정 잠금 임계값 적정(deny=%s,unlock_time=%s,audit ok)' \
           "$deny" "$(awk -F'[= \t]+' '/^[[:space:]]*unlock_time[[:space:]]*=/{print $2; exit}' "$fconf" 2>/dev/null)"
    return 0
}

h_U_03_apply() {
    local max_retry="${LOGIN_MAX_RETRY:-5}"
    local lock_time="${LOGIN_LOCK_TIME:-120}"
    local fconf; fconf="$(_u03_faillock_conf)"

    if [[ "${1:-}" == "--dry-run" ]]; then
        printf '(dry-run) faillock.conf 에 deny=%s, unlock_time=%s 적용 예정' "$max_retry" "$lock_time"
        return 0
    fi

    # 1) /etc/security/faillock.conf 생성/수정
    backup_file "$fconf"
    if [[ -f "$fconf" ]]; then
        set_kv "$fconf" 'deny'        "deny = ${max_retry}"
        set_kv "$fconf" 'unlock_time' "unlock_time = ${lock_time}"
        # silent / audit 줄 없으면 추가
        if ! grep -qE '^[[:space:]]*silent' "$fconf"; then
            printf '\nsilent\n' >> "$fconf"
        fi
        if ! grep -qE '^[[:space:]]*audit' "$fconf"; then
            printf 'audit\n' >> "$fconf"
        fi
    else
        atomic_write "$fconf" 0644 root root <<EOF
# Managed by KISA U-03 (kisa-audit). Do not edit manually.
silent
audit
deny = ${max_retry}
unlock_time = ${lock_time}
EOF
    fi

    # 2) authselect: with-faillock feature 활성화 (현재 비활성 시에만 enable + rollback 예약)
    if command -v authselect >/dev/null 2>&1; then
        local cur_profile
        cur_profile=$(authselect current 2>/dev/null | awk '/^Profile ID:/{print $NF}')
        if [[ -n "$cur_profile" ]]; then
            if ! _u03_faillock_feature_active; then
                if authselect enable-feature with-faillock 2>/dev/null; then
                    # rollback: 이 핸들러가 켠 feature 만 끄기. 원래 켜져있던 경우엔 등록 안 함.
                    _queue_rollback exec "authselect disable-feature with-faillock 2>/dev/null || true; authselect apply-changes 2>/dev/null || true"
                fi
            fi
        fi
    fi

    printf '조치 완료 — 계정 잠금 임계값 설정(deny=%s,unlock_time=%s,faillock.conf)' \
           "$max_retry" "$lock_time"
}
