#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-48: SMTP expn·vrfy 명령어 제한 (중요도: 중)
# KISA 가이드: SMTP 서비스의 expn, vrfy 명령어를 통한 계정 정보 노출 방지.
#
# Rocky 8/9/10: 기본 MTA는 postfix. /etc/postfix/main.cf 에
#   disable_vrfy_command = yes 설정으로 vrfy 차단 (postfix 는 expn 미지원).
#   sendmail 설치 시 /etc/mail/sendmail.cf 의 PrivacyOptions 에
#   noexpn, novrfy (또는 goaway) 포함 여부도 확인.
#
# 조치 전략:
#   1) postfix 설치/활성 여부 확인
#   2) disable_vrfy_command = yes 설정
#   3) postfix check 검증 → 실패 시 restore_file
#   4) postfix reload 큐잉
#   5) sendmail 설치 시 PrivacyOptions 확인·조치 (manual 안내)
#
# 롤백 전략: /etc/postfix/main.cf restore_file + postfix reload

h_U_48_meta() {
    cat <<'JSON'
{
  "code": "U-48",
  "title": "expn, vrfy 명령어 제한",
  "severity": "중",
  "category": "서비스 관리",
  "purpose": "SMTP 서비스의 expn, vrfy 명령을 통한 정보 유출을 방지하기 위함",
  "threat": "expn, vrfy 명령어를 통하여 특정 사용자 계정의 존재 여부를 알 수 있고, 사용자의 정보를 외부로 유출할 수 있는 위험이 존재함",
  "criterion_good": "noexpn, novrfy 옵션이 설정된 경우",
  "criterion_bad": "noexpn, novrfy 옵션이 설정되어 있지 않은 경우",
  "action_method": "- 메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 - 메일 서비스 사용 시 메일 서비스 설정 파일에 noexpn, novrfy 또는 goaway 옵션 추가 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "SMTP 서비스 사용 시 expn, vrfy 명령어 사용 금지 설정 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-48 (2026 ver.)"
  ]
}
JSON
}

_u_48_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령:"
        echo "## Postfix disable_vrfy_command 설정"
        if command -v postconf >/dev/null 2>&1; then
            echo "disable_vrfy_command = $(postconf -h disable_vrfy_command 2>&1)"
        else
            echo "(postconf 명령 없음 — postfix 미설치)"
        fi
        echo
        echo "## Sendmail PrivacyOptions (novrfy/noexpn/goaway 포함 여부)"
        if [[ -f /etc/mail/sendmail.cf ]]; then
            grep -iE '^O[[:space:]]+PrivacyOptions' /etc/mail/sendmail.cf 2>&1 || echo "(PrivacyOptions 라인 없음)"
        else
            echo "(/etc/mail/sendmail.cf 없음 — sendmail 미설치)"
        fi
        echo
        echo "## 패키지 설치 상태"
        echo "postfix : $(rpm -q postfix 2>&1)"
        echo "sendmail: $(rpm -q sendmail 2>&1)"
        echo
        echo "## 서비스 상태"
        for svc in postfix sendmail; do
            printf '%-10s is-enabled=%s   is-active=%s\n' \
                "$svc" \
                "$(systemctl is-enabled "$svc" 2>&1)" \
                "$(systemctl is-active  "$svc" 2>&1)"
        done
    } | _evidence_capture "$label"
}


_u48_postfix_cf()  { printf '/etc/postfix/main.cf'; }
_u48_sendmail_cf() { printf '/etc/mail/sendmail.cf'; }
_u48_exim_cf()     { printf '/etc/exim/exim.conf'; }

_u48_postfix_installed() {
    rpm -q postfix >/dev/null 2>&1
}

_u48_sendmail_installed() {
    rpm -q sendmail >/dev/null 2>&1
}

_u48_exim_installed() {
    rpm -q exim >/dev/null 2>&1
}

# postfix 에서 vrfy 차단 여부
_u48_postfix_ok() {
    local cf; cf="$(_u48_postfix_cf)"
    [[ -r "$cf" ]] || return 1
    grep -qE '^[[:space:]]*disable_vrfy_command[[:space:]]*=[[:space:]]*yes' "$cf"
}

# sendmail PrivacyOptions 에 novrfy/noexpn/goaway 포함 여부
_u48_sendmail_ok() {
    local cf; cf="$(_u48_sendmail_cf)"
    [[ -r "$cf" ]] || return 1
    grep -qE '^O[[:space:]]+PrivacyOptions[[:space:]]*=.*\b(novrfy|noexpn|goaway)\b' "$cf"
}

# exim 에서 vrfy/expn ACL 이 'accept' 만 사용하지 않도록 설정
_u48_exim_ok() {
    local cf; cf="$(_u48_exim_cf)"
    [[ -r "$cf" ]] || return 1
    # acl_smtp_vrfy 와 acl_smtp_expn 가 모두 'accept' 단독으로 설정되어 있지 않아야 양호
    ! grep -qE '^[[:space:]]*(acl_smtp_vrfy|acl_smtp_expn)[[:space:]]*=[[:space:]]*accept[[:space:]]*$' "$cf"
}

h_U_48_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_48_capture_state "$KISA_PHASE"
    fi

    local pf_inst=0 sm_inst=0 ex_inst=0
    _u48_postfix_installed  && pf_inst=1
    _u48_sendmail_installed && sm_inst=1
    _u48_exim_installed     && ex_inst=1

    if (( pf_inst == 0 )) && (( sm_inst == 0 )) && (( ex_inst == 0 )); then
        printf '양호 — postfix/sendmail/exim 미설치(SMTP 취약점 해당없음)'
        return 0
    fi

    local pf_ok=0 sm_ok=0 ex_ok=0
    (( pf_inst )) && _u48_postfix_ok  && pf_ok=1
    (( sm_inst )) && _u48_sendmail_ok && sm_ok=1
    (( ex_inst )) && _u48_exim_ok     && ex_ok=1

    if (( pf_inst )) && (( pf_ok == 0 )); then
        printf '취약 — postfix disable_vrfy_command 미설정'
        return 1
    fi
    if (( sm_inst )) && (( sm_ok == 0 )); then
        printf '취약 — sendmail PrivacyOptions novrfy/noexpn/goaway 미설정'
        return 1
    fi
    if (( ex_inst )) && (( ex_ok == 0 )); then
        printf '취약 — exim acl_smtp_vrfy/expn 가 accept 단독 설정(수동 조치 필요)'
        return 1
    fi

    local msg=""
    (( pf_inst )) && msg="${msg}postfix disable_vrfy_command=yes "
    (( sm_inst )) && msg="${msg}sendmail PrivacyOptions OK "
    (( ex_inst )) && msg="${msg}exim ACL OK"
    printf '양호 — %s' "${msg% }"
    return 0
}

h_U_48_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        local rc; h_U_48_check >/dev/null 2>&1; rc=$?
        case $rc in
            0) printf '(dry-run) 이미 양호, 조치 불필요' ;;
            3) printf '(dry-run) SMTP 서비스 미설치, 조치 불필요(N/A)' ;;
            *) printf '(dry-run) postfix main.cf disable_vrfy_command=yes 설정 예정; postfix reload 지연' ;;
        esac
        return 0
    fi

    local rc; h_U_48_check >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then
        printf '양호 — 이미 expn/vrfy 제한 설정됨, 조치 불필요'
        return 0
    fi
    if (( rc == 3 )); then
        printf '해당없음 — SMTP 서비스 미설치'
        return 3
    fi

    local manual_needed=0

    # --- postfix 조치 ---
    if _u48_postfix_installed && ! _u48_postfix_ok; then
        local cf; cf="$(_u48_postfix_cf)"
        if [[ ! -f "$cf" ]]; then
            printf '조치 실패 — postfix main.cf 없음: %s' "$cf"
            return 1
        fi
        backup_file "$cf"
        set_kv "$cf" 'disable_vrfy_command' 'disable_vrfy_command = yes'

        # postfix check 검증
        if ! postfix check 2>/dev/null; then
            restore_file "$cf"
            printf '조치 실패 — postfix check 실패로 변경 원복 완료'
            return 1
        fi

        _queue_service_op reload postfix
        _queue_rollback   systemctl_reload postfix
    fi

    # --- sendmail 조치 (manual 안내) ---
    if _u48_sendmail_installed && ! _u48_sendmail_ok; then
        log_warn 'sendmail PrivacyOptions 수동 조치 필요: /etc/mail/sendmail.cf 에 PrivacyOptions=authwarnings,novrfy,noexpn,restrictqrun 설정 후 sendmail 재시작'
        manual_needed=1
    fi

    # --- exim 조치 (manual 안내) ---
    if _u48_exim_installed && ! _u48_exim_ok; then
        log_warn 'exim 수동 조치 필요: /etc/exim/exim.conf 의 acl_smtp_vrfy / acl_smtp_expn = accept 라인을 주석 처리하거나 deny 정책으로 변경 후 exim 재시작'
        manual_needed=1
    fi

    if (( manual_needed )); then
        printf '수동 조치 필요 — postfix disable_vrfy_command=yes 적용 완료, sendmail/exim 설정 파일 직접 조치 필요'
        return 2
    fi

    printf '조치 완료 — postfix disable_vrfy_command=yes 적용, postfix reload 지연'
    return 0
}
