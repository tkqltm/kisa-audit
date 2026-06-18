#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-47: 스팸 메일 릴레이 제한 (중요도: 상)
# KISA 가이드: SMTP 서버의 릴레이 기능 제한.
#
# Rocky 8/9/10 — Postfix 기준:
#   /etc/postfix/main.cf 에 smtpd_relay_restrictions 설정:
#     smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination
#   또는 smtpd_recipient_restrictions 에 reject_unauth_destination 포함.
#   postfix check 로 검증 후 _queue_service_op restart postfix.
#
# Sendmail: promiscuous_relay 없음 + Sendmail 8.9+ 기본 릴레이 제한.
# Exim: relay_from_hosts 허용 범위 확인.
#
# 조치 전략:
#   Postfix: set_kv smtpd_relay_restrictions + postfix check + restart
#   Sendmail: promiscuous_relay 라인 확인 (없으면 양호)
#   Exim: relay_from_hosts 수동 안내
#
# 롤백: backup_file main.cf + _queue_rollback systemctl_restart postfix

h_U_47_meta() {
    cat <<'JSON'
{
  "code": "U-47",
  "title": "스팸 메일 릴레이 제한",
  "severity": "상",
  "category": "서비스 관리",
  "purpose": "스팸 메일 서버로의 악용 방지 및 서버 과부하를 방지하기 위함",
  "threat": "SMTP 서버의 릴레이 기능을 제한하지 않을 경우, 악의적인 사용 목적을 가진 사용자들이 스팸 메일 서버로 사용하거나 DoS 공격의 위험이 존재함",
  "criterion_good": "릴레이 제한이 설정된 경우",
  "criterion_bad": "릴레이 제한이 설정되어 있지 않은 경우",
  "action_method": "- 메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 - 메일 서비스 사용 시 릴레이 방지 설정 또는 릴레이 대상 접근 제어 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "SMTP 서버의 릴레이 기능 제한 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-47 (2026 ver.)"
  ]
}
JSON
}

_u_47_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령:"
        echo "## Postfix smtpd_relay_restrictions / smtpd_recipient_restrictions"
        if command -v postconf >/dev/null 2>&1; then
            echo "smtpd_relay_restrictions     = $(postconf -h smtpd_relay_restrictions 2>&1)"
            echo "smtpd_recipient_restrictions = $(postconf -h smtpd_recipient_restrictions 2>&1)"
            echo "mynetworks                   = $(postconf -h mynetworks 2>&1)"
            echo "inet_interfaces              = $(postconf -h inet_interfaces 2>&1)"
        else
            echo "(postconf 명령 없음 — postfix 미설치)"
        fi
        echo
        echo "## Sendmail promiscuous_relay 설정"
        if [[ -f /etc/mail/sendmail.mc ]]; then
            grep -iE "FEATURE.*promiscuous_relay" /etc/mail/sendmail.mc 2>&1 || echo "(sendmail.mc: promiscuous_relay 라인 없음 — 양호)"
        else
            echo "(/etc/mail/sendmail.mc 없음)"
        fi
        if [[ -f /etc/mail/sendmail.cf ]]; then
            grep -iE 'promiscuous_relay' /etc/mail/sendmail.cf 2>&1 || echo "(sendmail.cf: promiscuous_relay 라인 없음 — 양호)"
        else
            echo "(/etc/mail/sendmail.cf 없음)"
        fi
        echo
        echo "## 서비스 상태"
        for svc in postfix sendmail exim; do
            printf '%-10s is-enabled=%s   is-active=%s\n' \
                "$svc" \
                "$(systemctl is-enabled "$svc" 2>&1)" \
                "$(systemctl is-active  "$svc" 2>&1)"
        done
    } | _evidence_capture "$label"
}


_u47_main_cf() { printf '/etc/postfix/main.cf'; }
_u47_sendmail_mc() { printf '/etc/mail/sendmail.mc'; }
_u47_sendmail_cf() { printf '/etc/mail/sendmail.cf'; }

_u47_postfix_installed() { command -v postconf >/dev/null 2>&1; }
_u47_sendmail_installed() { [[ -f "$(_u47_sendmail_cf)" ]] || command -v sendmail >/dev/null 2>&1; }
_u47_exim_installed() { command -v exim >/dev/null 2>&1; }

_u47_mail_installed() {
    _u47_postfix_installed && return 0
    _u47_sendmail_installed && return 0
    _u47_exim_installed && return 0
    return 1
}

# Postfix: smtpd_relay_restrictions 또는 smtpd_recipient_restrictions 에 릴레이 제한 있는지
_u47_postfix_relay_restricted() {
    command -v postconf >/dev/null 2>&1 || return 1
    local relay_restr
    relay_restr=$(postconf -h smtpd_relay_restrictions 2>/dev/null || true)
    if echo "$relay_restr" | grep -q 'reject_unauth_destination'; then
        return 0
    fi
    # 구버전 호환: smtpd_recipient_restrictions
    local recip_restr
    recip_restr=$(postconf -h smtpd_recipient_restrictions 2>/dev/null || true)
    if echo "$recip_restr" | grep -q 'reject_unauth_destination'; then
        return 0
    fi
    return 1
}

# Sendmail: promiscuous_relay 설정 존재 시 릴레이 허용(취약)
_u47_sendmail_relay_open() {
    local mc; mc="$(_u47_sendmail_mc)"
    local cf; cf="$(_u47_sendmail_cf)"
    if [[ -f "$mc" ]]; then
        grep -qiE "^[^#]*FEATURE.*promiscuous_relay" "$mc" 2>/dev/null && return 0
    fi
    if [[ -f "$cf" ]]; then
        grep -qiE '^[^#]*promiscuous_relay' "$cf" 2>/dev/null && return 0
    fi
    return 1
}

h_U_47_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_47_capture_state "$KISA_PHASE"
    fi

    if ! _u47_mail_installed; then
        printf '양호 — 메일 서비스 미설치로 릴레이 점검 대상 아님'
        return 0
    fi

    local issues=()

    # Postfix
    if _u47_postfix_installed; then
        if ! _u47_postfix_relay_restricted; then
            issues+=("postfix: smtpd_relay_restrictions 미설정(reject_unauth_destination 없음)")
        fi
    fi

    # Sendmail
    if _u47_sendmail_installed; then
        if _u47_sendmail_relay_open; then
            issues+=("sendmail: promiscuous_relay 설정됨 — 릴레이 허용 상태")
        fi
    fi

    # Exim: 정보 제공 수준 (자동 판단 어려움)
    if _u47_exim_installed && ! _u47_postfix_installed; then
        log_info "U-47: Exim relay_from_hosts 수동 확인 권고" >&2
    fi

    if (( ${#issues[@]} == 0 )); then
        printf '양호 — SMTP 릴레이 제한 설정됨(reject_unauth_destination 적용)'
        return 0
    fi

    printf '취약 — 릴레이 제한 미흡: %s' "${issues[*]}"
    return 1
}

h_U_47_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        local rc; h_U_47_check >/dev/null 2>&1; rc=$?
        case $rc in
            0) printf '(dry-run) 릴레이 제한 이미 양호 — 조치 예정 없음' ;;
            3) printf '(dry-run) 메일 서비스 미설치, 조치 불필요(N/A)' ;;
            *) printf '(dry-run) postfix smtpd_relay_restrictions 릴레이 제한 설정 예정' ;;
        esac
        return 0
    fi

    local rc; h_U_47_check >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then printf '양호 — 이미 릴레이 제한이 설정되어 조치 불필요'; return 0; fi
    if (( rc == 3 )); then printf '해당없음 — 메일 서비스 미설치'; return 3; fi

    local changed=0 failed=0

    # Postfix 조치
    if _u47_postfix_installed && ! _u47_postfix_relay_restricted; then
        local mcf; mcf="$(_u47_main_cf)"
        [[ -f "$mcf" ]] || { printf '조치 실패 — postfix main.cf 파일 없음'; return 1; }

        backup_file "$mcf"
        # smtpd_relay_restrictions 설정
        set_kv "$mcf" 'smtpd_relay_restrictions' \
            'smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination'

        # postfix check 검증
        if ! postfix check 2>/dev/null; then
            restore_file "$mcf"
            printf '조치 실패 — postfix check 검증 실패로 main.cf 원복 완료'
            return 1
        fi

        _queue_service_op restart postfix
        _queue_rollback systemctl_restart postfix
        changed=1
    fi

    # Sendmail 조치: promiscuous_relay 라인 주석 처리
    if _u47_sendmail_installed && _u47_sendmail_relay_open; then
        local mc; mc="$(_u47_sendmail_mc)"
        local cf; cf="$(_u47_sendmail_cf)"

        if [[ -f "$mc" ]]; then
            backup_file "$mc"
            local tmp="$KISA_TMP_DIR/tmp/u47.sendmail.mc.$$.$RANDOM"
            mkdir -p "$(dirname "$tmp")"
            local om ou og
            om=$(stat -c '%a' "$mc" 2>/dev/null || true)
            ou=$(stat -c '%u' "$mc" 2>/dev/null || true)
            og=$(stat -c '%g' "$mc" 2>/dev/null || true)
            awk '/FEATURE.*promiscuous_relay/ {
                printf "dnl # [KISA U-47] %s\n", $0; next
            }
            { print }' "$mc" > "$tmp"
            mv -f "$tmp" "$mc"
            [[ -n "$om" ]] && chmod "$om" "$mc" 2>/dev/null || true
            [[ -n "$ou" && -n "$og" ]] && chown "$ou:$og" "$mc" 2>/dev/null || true
            command -v restorecon >/dev/null 2>&1 && restorecon "$mc" 2>/dev/null || true
            log_warn "U-47: sendmail.mc 수정. m4 /etc/mail/sendmail.mc > /etc/mail/sendmail.cf 후 sendmail 재시작 필요(수동)"
            failed=1  # sendmail.cf 재생성은 수동
        fi
        changed=1
    fi

    # Exim
    if _u47_exim_installed && ! _u47_postfix_installed; then
        log_warn "U-47: Exim relay_from_hosts 수동 확인·조치 필요"
        printf '수동 조치 필요 — Exim relay_from_hosts 릴레이 설정 점검\n조치: /etc/exim 설정에서 relay_from_hosts 허용 범위 확인'
        return 2
    fi

    if (( changed == 0 )); then
        printf '양호 — 이미 릴레이 제한이 설정되어 변경 없음'
        return 0
    fi

    if (( failed == 1 )); then
        printf '수동 조치 필요 — sendmail.mc promiscuous_relay 주석 처리 완료, sendmail.cf 재생성 수동 필요\n조치: m4 /etc/mail/sendmail.mc > /etc/mail/sendmail.cf 후 sendmail 재시작'
        return 2
    fi

    printf '조치 완료 — postfix smtpd_relay_restrictions 릴레이 제한 설정(postfix restart 지연 적용)'
    return 0
}
