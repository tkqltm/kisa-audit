#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-46: 일반 사용자의 메일 서비스 실행 방지 (중요도: 상)
# KISA 가이드: SMTP 서비스에서 일반 사용자의 큐 조작·설정 조회 방지.
#
# Rocky 8/9/10 — Postfix 기준:
#   /usr/sbin/postsuper 의 others 실행 권한 제거 (o-x).
#   또는 main.cf 에 authorized_submit_users 설정.
#
# Sendmail: PrivacyOptions 에 restrictqrun 포함 확인.
# Postfix:  /usr/sbin/postsuper others 실행권한 없어야 함.
# Exim:     /usr/sbin/exiqgrep others 실행권한 없어야 함.
#
# 조치 전략:
#   Postfix: chmod o-x /usr/sbin/postsuper
#   Sendmail: /etc/mail/sendmail.cf PrivacyOptions 에 restrictqrun 추가 + sendmail restart
#   Exim: chmod o-x /usr/sbin/exiqgrep
#
# 롤백: backup_file (stat 기록) + sendmail restart는 _queue_rollback

h_U_46_meta() {
    cat <<'JSON'
{
  "code": "U-46",
  "title": "일반 사용자의 메일 서비스 실행 방지",
  "severity": "상",
  "category": "서비스 관리",
  "purpose": "일반 사용자의 q 옵션을 제한하여 메일 서비스 설정 및 메일 큐를 강제적으로 drop 시킬 수 없게 하여 비인가자에 의한 SMTP 서비스 오류 방지하기 위함",
  "threat": "일반 사용자가 q 옵션을 이용해서 메일 큐, 메일 서비스 설정을 보거나 메일 큐를 강제적으로 drop 시킬 수 있어 악의적으로 SMTP 서버의 오류를 발생시킬 위험이 존재함",
  "criterion_good": "일반 사용자의 메일 서비스 실행 방지가 설정된 경우",
  "criterion_bad": "일반 사용자의 메일 서비스 실행 방지가 설정되어 있지 않은 경우",
  "action_method": "- 메일 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 - 메일 서비스 사용 시 메일 서비스의 q 옵션 제한 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "SMTP 서비스 사용 시 일반 사용자의 q 옵션 제한 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-46 (2026 ver.)"
  ]
}
JSON
}

_u_46_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령:"
        echo "## /usr/sbin/postsuper others 실행권한 (Postfix 큐 조작 도구)"
        if [[ -f /usr/sbin/postsuper ]]; then
            ls -l /usr/sbin/postsuper 2>&1
        else
            echo "(/usr/sbin/postsuper 없음 — postfix 미설치)"
        fi
        echo
        echo "## /etc/mail/sendmail.cf PrivacyOptions (sendmail 큐 제한)"
        if [[ -f /etc/mail/sendmail.cf ]]; then
            grep -i '^O PrivacyOptions' /etc/mail/sendmail.cf 2>&1 || echo "(PrivacyOptions 라인 없음)"
        else
            echo "(/etc/mail/sendmail.cf 없음 — sendmail 미설치)"
        fi
        echo
        echo "## /usr/sbin/exiqgrep others 실행권한 (Exim 큐 조회 도구)"
        if [[ -f /usr/sbin/exiqgrep ]]; then
            ls -l /usr/sbin/exiqgrep 2>&1
        else
            echo "(/usr/sbin/exiqgrep 없음 — exim 미설치)"
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


_u46_postsuper() { printf '/usr/sbin/postsuper'; }
_u46_sendmail_cf() { printf '/etc/mail/sendmail.cf'; }
_u46_exiqgrep() { printf '/usr/sbin/exiqgrep'; }

# others execute 권한 있는지 (0=있음, 1=없음)
_u46_others_exec() {
    local f="$1"
    [[ -f "$f" ]] || return 1
    local perm; perm=$(stat -c '%a' "$f" 2>/dev/null)
    # 8진수 마지막 자리 & 1
    (( 8#$perm & 1 )) && return 0
    return 1
}

_u46_mail_installed() {
    command -v postconf >/dev/null 2>&1 && return 0
    [[ -f "$(_u46_sendmail_cf)" ]] && return 0
    command -v exim >/dev/null 2>&1 && return 0
    return 1
}

h_U_46_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_46_capture_state "$KISA_PHASE"
    fi

    if ! _u46_mail_installed; then
        printf '양호 — 메일 서비스 미설치(취약점 해당없음)'
        return 0
    fi

    local issues=()

    # Postfix
    local ps; ps="$(_u46_postsuper)"
    if [[ -f "$ps" ]]; then
        if _u46_others_exec "$ps"; then
            local p; p=$(stat -c '%a' "$ps" 2>/dev/null)
            issues+=("$ps others 실행권한 있음($p)")
        fi
    fi

    # Sendmail
    local sf; sf="$(_u46_sendmail_cf)"
    if [[ -f "$sf" ]]; then
        local po
        po=$(grep -i '^O PrivacyOptions' "$sf" 2>/dev/null | head -1)
        if [[ -n "$po" ]]; then
            if ! echo "$po" | grep -qi 'restrictqrun'; then
                issues+=("sendmail.cf PrivacyOptions 에 restrictqrun 없음")
            fi
        else
            issues+=("sendmail.cf PrivacyOptions 설정 없음")
        fi
    fi

    # Exim
    local eg; eg="$(_u46_exiqgrep)"
    if [[ -f "$eg" ]]; then
        if _u46_others_exec "$eg"; then
            local p; p=$(stat -c '%a' "$eg" 2>/dev/null)
            issues+=("$eg others 실행권한 있음($p)")
        fi
    fi

    if (( ${#issues[@]} == 0 )); then
        printf '양호 — 일반 사용자 메일 서비스 실행 방지 설정됨(postsuper/exiqgrep others 실행권한 없음, sendmail restrictqrun)'
        return 0
    fi

    printf '취약 — %s' "${issues[*]}"
    return 1
}

h_U_46_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        local rc; h_U_46_check >/dev/null 2>&1; rc=$?
        case $rc in
            0) printf '(dry-run) 이미 양호, 조치 불필요' ;;
            3) printf '(dry-run) 메일 서비스 미설치, 조치 불필요(N/A)' ;;
            *) printf '(dry-run) postsuper/exiqgrep o-x, sendmail restrictqrun 예정' ;;
        esac
        return 0
    fi

    local rc; h_U_46_check >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then printf '양호 — 이미 일반 사용자 메일 서비스 실행 방지 설정됨'; return 0; fi
    if (( rc == 3 )); then printf '해당없음 — 메일 서비스 미설치'; return 3; fi

    local changed=0

    # Postfix: postsuper o-x
    local ps; ps="$(_u46_postsuper)"
    if [[ -f "$ps" ]] && _u46_others_exec "$ps"; then
        backup_file "$ps"
        chmod o-x "$ps"
        changed=1
    fi

    # Sendmail: PrivacyOptions restrictqrun 추가
    local sf; sf="$(_u46_sendmail_cf)"
    if [[ -f "$sf" ]]; then
        local po
        po=$(grep -i '^O PrivacyOptions' "$sf" 2>/dev/null | head -1)
        local need_change=0
        if [[ -n "$po" ]]; then
            echo "$po" | grep -qi 'restrictqrun' || need_change=1
        else
            need_change=1
        fi
        if (( need_change == 1 )); then
            backup_file "$sf"
            if [[ -n "$po" ]]; then
                # 기존 라인에 restrictqrun 추가
                local tmp="$KISA_TMP_DIR/tmp/u46.sendmail.$$.$RANDOM"
                mkdir -p "$(dirname "$tmp")"
                local om ou og
                om=$(stat -c '%a' "$sf" 2>/dev/null || true)
                ou=$(stat -c '%u' "$sf" 2>/dev/null || true)
                og=$(stat -c '%g' "$sf" 2>/dev/null || true)
                awk '/^O PrivacyOptions/ {
                    if (index($0, "restrictqrun") == 0) {
                        sub(/,$/, "")
                        printf "%s,restrictqrun\n", $0
                    } else { print }
                    next
                }
                { print }' "$sf" > "$tmp"
                mv -f "$tmp" "$sf"
                [[ -n "$om" ]] && chmod "$om" "$sf" 2>/dev/null || true
                [[ -n "$ou" && -n "$og" ]] && chown "$ou:$og" "$sf" 2>/dev/null || true
                command -v restorecon >/dev/null 2>&1 && restorecon "$sf" 2>/dev/null || true
            else
                printf '\nO PrivacyOptions=authwarnings,novrfy,noexpn,restrictqrun\n' >> "$sf"
            fi
            # sendmail restart
            if systemctl is-active sendmail >/dev/null 2>&1; then
                _queue_service_op restart sendmail
                _queue_rollback systemctl_restart sendmail
            fi
            changed=1
        fi
    fi

    # Exim: exiqgrep o-x
    local eg; eg="$(_u46_exiqgrep)"
    if [[ -f "$eg" ]] && _u46_others_exec "$eg"; then
        backup_file "$eg"
        chmod o-x "$eg"
        changed=1
    fi

    if (( changed == 0 )); then
        printf '양호 — 이미 일반 사용자 메일 서비스 실행 방지 설정됨'
        return 0
    fi

    printf '조치 완료 — postsuper/exiqgrep others 실행권한 제거 및 sendmail restrictqrun 적용'
    return 0
}
