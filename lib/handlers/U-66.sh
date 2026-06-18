#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-66: 정책에 따른 시스템 로깅 설정 (중요도: 중)
# KISA 가이드: rsyslog 서비스 활성화 + 필수 로그 규칙 6개 존재 확인.
#
# 필수 규칙 (KISA 가이드 권고 — 6개 모두 존재해야 양호):
#   1) *.info;mail.none;authpriv.none;cron.none    /var/log/messages
#   2) authpriv.*                                   /var/log/secure
#   3) mail.*                                       /var/log/maillog
#   4) cron.*                                       /var/log/cron
#   5) *.alert                                      /dev/console
#   6) *.emerg                                      *  (또는 :omusrmsg:*)
#
# Rocky 8/9/10 기본 rsyslog.conf 에 위 규칙이 포함되나, Rocky 10 일부 환경에서 누락 가능.
#
# 조치 전략 (drop-in 방식 — authselect/vendor 원본 훼손 없음):
#   - 누락 규칙은 /etc/rsyslog.d/00-kisa.conf 에 추가
#   - rsyslogd -N1 검증 실패 시 즉시 restore_file 로 원복
#   - rsyslog restart 는 _queue_service_op 로 지연
#
# 롤백 전략:
#   backup_file /etc/rsyslog.d/00-kisa.conf → restore_file
#   _queue_rollback systemctl_restart rsyslog

h_U_66_meta() {
    cat <<'JSON'
{
  "code": "U-66",
  "title": "정책에 따른 시스템 로깅 설정",
  "severity": "중",
  "category": "로그 관리",
  "purpose": "보안 사고 발생 시 원인 파악 및 각종 침해 사실 확인을 하기 위함",
  "threat": "로깅 설정이 되어 있지 않을 경우, 원인 규명이 어려우며 법적 대응을 위한 충분한 증거로 사용할 수 없는 위험이 존재함",
  "criterion_good": "로그 기록 정책이 보안 정책에 따라 설정되어 수립되어 있으며, 로그를 남기고 있는 경우",
  "criterion_bad": "로그 기록 정책 미수립 또는 정책에 따라 설정되어 있지 않거나, 로그를 남기고 있지 않은 경우",
  "action_method": "로그 기록 정책을 수립하고, 정책에 따라 (r)syslog.conf 파일을 설정",
  "action_impact": "아래 제시한 모든 로그를 설정할 경우, 시스템 성능과 로그 저장에 따른 서버 용량 부족 문제가 발생할 수 있으므로 시스템 운영 환경과 특성을 고려하여 적용",
  "method": [
    "내부 정책에 따른 시스템 로깅 설정 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-66 (2026 ver.)"
  ]
}
JSON
}

_u_66_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: rsyslog 활성화 + 필수 로그 규칙 6개 검증"
        echo
        echo "## rsyslog 서비스 상태"
        echo "is-enabled: $(systemctl is-enabled rsyslog 2>&1)"
        echo "is-active : $(systemctl is-active  rsyslog 2>&1)"
        echo
        echo "## /etc/rsyslog.conf 핵심 facility 규칙"
        if [[ -f /etc/rsyslog.conf ]]; then
            grep -nE '^(\*\.info|\*\.\*|authpriv|cron|mail|uucp|kern|local|news|spool|boot)' /etc/rsyslog.conf 2>/dev/null \
                | head -30 || echo "(매칭 라인 없음)"
        fi
        echo
        echo "## /etc/rsyslog.d/*.conf"
        if [[ -d /etc/rsyslog.d ]]; then
            ls -l /etc/rsyslog.d/ 2>&1
            for _f in /etc/rsyslog.d/*.conf; do
                [[ -f "$_f" ]] || continue
                echo "### $_f"
                grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$_f" 2>/dev/null | head -15
            done
        fi
        echo
        echo "## 핵심 로그 파일 ls -l (boot.log, cron, messages, secure, spooler, maillog)"
        for _lf in /var/log/boot.log /var/log/cron /var/log/messages /var/log/secure /var/log/spooler /var/log/maillog; do
            ls -l "$_lf" 2>&1
        done
        echo
        echo "## logrotate 설정"
        if [[ -f /etc/logrotate.conf ]]; then
            ls -l /etc/logrotate.conf 2>&1 || true
        fi
    } | _evidence_capture "$label"
}


_u66_main_conf()   { printf '/etc/rsyslog.conf'; }
_u66_dropin()      { printf '/etc/rsyslog.d/00-kisa.conf'; }
_u66_dropin_dir()  { printf '/etc/rsyslog.d'; }
_u66_has_rsyslog_include() {
    local main; main="$(_u66_main_conf)"
    [[ -r "$main" ]] || return 1
    grep -qE '^[[:space:]]*(\$IncludeConfig|include\(.*rsyslog\.d)' "$main"
}
_u66_svc()         { printf 'rsyslog'; }

# KISA U-66 권고 6개 필수 규칙 (rule_key: 검색 패턴 / rule_line: 추가할 실제 라인)
# 배열 인덱스 짝: _U66_KEYS[i] / _U66_LINES[i]
_U66_KEYS=(
    '^\*\.info;mail\.none;authpriv\.none;cron\.none'
    '^authpriv\.\*'
    '^mail\.\*'
    '^cron\.\*'
    '^\*\.alert'
    '^\*\.emerg'
)
_U66_LINES=(
    '*.info;mail.none;authpriv.none;cron.none                 /var/log/messages'
    'authpriv.*                                                /var/log/secure'
    'mail.*                                                    /var/log/maillog'
    'cron.*                                                    /var/log/cron'
    '*.alert                                                   /dev/console'
    '*.emerg                                                   :omusrmsg:*'
)

# RSYSLOG_REMOTE_SERVER 값을 정규화된 rsyslog target ("@@host:port" 또는 "@host:port") 으로 변환
# - 입력 예: "10.0.0.10"           -> "@@10.0.0.10:514"
#            "10.0.0.10:514"       -> "@@10.0.0.10:514"
#            "@10.0.0.10:514"      -> "@10.0.0.10:514"
#            "@@10.0.0.10:514"     -> "@@10.0.0.10:514"
_u66_normalize_remote() {
    local raw="$1"
    [[ -z "$raw" ]] && return 0
    raw="${raw//[[:space:]]/}"
    case "$raw" in
        @@*) printf '%s' "$raw"; return 0 ;;
        @*)  printf '%s' "$raw"; return 0 ;;
    esac
    case "$raw" in
        *:*) printf '@@%s' "$raw" ;;
        *)   printf '@@%s:514' "$raw" ;;
    esac
}

# rsyslog 설정 전체(main + dropin_dir 내 모든 .conf)에서 패턴 검색
# 주석 라인(^#) 제외
_u66_rule_exists() {
    local pattern="$1"
    local search_dirs=("$(_u66_main_conf)" "$(_u66_dropin_dir)")

    # main conf
    if [[ -r "$(_u66_main_conf)" ]]; then
        if grep -qE "^[[:space:]]*${pattern}" "$(_u66_main_conf)" 2>/dev/null; then
            return 0
        fi
    fi

    # dropin dir
    local f
    while IFS= read -r f; do
        [[ -r "$f" ]] || continue
        if grep -qE "^[[:space:]]*${pattern}" "$f" 2>/dev/null; then
            return 0
        fi
    done < <(find "$(_u66_dropin_dir)" -maxdepth 1 -name '*.conf' -type f 2>/dev/null | sort)

    return 1
}

h_U_66_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_66_capture_state "$KISA_PHASE"
    fi

    local main_f; main_f="$(_u66_main_conf)"

    if ! command -v rsyslogd >/dev/null 2>&1; then
        printf '취약 — rsyslog 패키지 미설치'
        return 1
    fi

    # rsyslog 서비스 상태
    local svc_status
    svc_status=$(systemctl is-active rsyslog 2>/dev/null || printf 'inactive')
    if [[ "$svc_status" != "active" ]]; then
        printf '취약 — rsyslog 서비스 비활성(%s)' "$svc_status"
        return 1
    fi

    # 필수 규칙 누락 여부 확인
    local missing=()
    local i
    for (( i=0; i<${#_U66_KEYS[@]}; i++ )); do
        _u66_rule_exists "${_U66_KEYS[$i]}" || missing+=("${_U66_LINES[$i]%%[[:space:]]*}")
    done

    # KISA PDF 표기 정확 매칭 — mail.* 선행 '-' 만 위반으로 판정
    # (*.emerg ':omusrmsg:*' 는 rsyslog 8 정식 표기 = PDF '*' 와 의미 동등, 호환성 위해 양호)
    local main_f; main_f="$(_u66_main_conf)"
    if [[ -f "$main_f" ]]; then
        if grep -qE '^[[:space:]]*mail\.\*[[:space:]]+-/var/log/maillog' "$main_f"; then
            missing+=('mail.*-prefix')
        fi
    fi

    # 원격 전송 정책 확인 (RSYSLOG_REMOTE_SERVER 가 설정된 경우)
    local remote_target remote_missing=0
    remote_target="$(_u66_normalize_remote "${RSYSLOG_REMOTE_SERVER:-}")"
    if [[ -n "$remote_target" ]]; then
        local pattern
        pattern="^\\*\\.\\*[[:space:]]+$(printf '%s' "$remote_target" | sed 's/[][\\.*^$/]/\\&/g')\$"
        _u66_rule_exists "$pattern" || remote_missing=1
    fi

    if (( ${#missing[@]} == 0 )) && (( ! remote_missing )); then
        if [[ -n "$remote_target" ]]; then
            printf '양호 — rsyslog 활성, 필수 규칙 6개 + 원격 전송(%s) 모두 존재' "$remote_target"
        else
            printf '양호 — rsyslog 활성, 필수 로그 규칙 6개 모두 존재'
        fi
        return 0
    fi

    local issues=()
    (( ${#missing[@]} > 0 )) && issues+=("규칙누락: $(IFS=','; printf '%s' "${missing[*]}")")
    (( remote_missing )) && issues+=("원격전송 미설정($remote_target)")
    printf '취약 — rsyslog 활성이나 %s' "$(IFS='; '; printf '%s' "${issues[*]}")"
    return 1
}

h_U_66_apply() {
    local dropin; dropin="$(_u66_dropin)"
    local dropin_dir; dropin_dir="$(_u66_dropin_dir)"
    local svc; svc="$(_u66_svc)"

    local remote_target
    remote_target="$(_u66_normalize_remote "${RSYSLOG_REMOTE_SERVER:-}")"

    if [[ "${1:-}" == "--dry-run" ]]; then
        local missing=()
        local i
        for (( i=0; i<${#_U66_KEYS[@]}; i++ )); do
            _u66_rule_exists "${_U66_KEYS[$i]}" || missing+=("${_U66_LINES[$i]}")
        done
        local rmsg=""
        if [[ -n "$remote_target" ]]; then
            local rpat
            rpat="^\\*\\.\\*[[:space:]]+$(printf '%s' "$remote_target" | sed 's/[][\\.*^$/]/\\&/g')\$"
            _u66_rule_exists "$rpat" || rmsg=" + 원격전송 라인($remote_target) 추가"
        fi
        if (( ${#missing[@]} == 0 )) && [[ -z "$rmsg" ]]; then
            printf '(dry-run) 누락 규칙 없음 — 변경 불필요'
        else
            printf '(dry-run) 누락 규칙 %d개를 %s 에 추가 예정%s' "${#missing[@]}" "$dropin" "$rmsg"
        fi
        return 0
    fi

    # rsyslog 확인
    if ! command -v rsyslogd >/dev/null 2>&1; then
        printf '수동 조치 필요 — rsyslog 패키지 미설치\n조치: "dnf install -y rsyslog" 후 재실행'
        return 2
    fi

    # 누락 규칙 수집
    local missing_lines=()
    local i
    for (( i=0; i<${#_U66_KEYS[@]}; i++ )); do
        _u66_rule_exists "${_U66_KEYS[$i]}" || missing_lines+=("${_U66_LINES[$i]}")
    done

    # 원격 전송 라인 누락 확인
    local remote_line=""
    if [[ -n "$remote_target" ]]; then
        local rpat
        rpat="^\\*\\.\\*[[:space:]]+$(printf '%s' "$remote_target" | sed 's/[][\\.*^$/]/\\&/g')\$"
        if ! _u66_rule_exists "$rpat"; then
            remote_line="*.* $remote_target"
        fi
    fi

    # KISA PDF 표기 강제 매칭: mail.* 선행 '-' 제거.
    # 주의: PDF 의 '*.emerg *' 표기는 rsyslog 8 이 sysklogd 호환 모드로 거부 (exit 1).
    #       Rocky 8/9/10 에서는 ':omusrmsg:*' 신문법이 표준 (PDF '*' 와 의미 동등).
    local main_f; main_f="$(_u66_main_conf)"
    local vendor_changed=0
    if [[ -f "$main_f" ]]; then
        if grep -qE '^[[:space:]]*mail\.\*[[:space:]]+-/var/log/maillog' "$main_f"; then
            backup_file "$main_f"
            sed -i 's|^\([[:space:]]*mail\.\*[[:space:]]\+\)-\(/var/log/maillog\)|\1 \2|' "$main_f"
            vendor_changed=1
        fi
    fi

    if (( ${#missing_lines[@]} == 0 )) && [[ -z "$remote_line" ]] && (( vendor_changed == 0 )); then
        printf '양호 — 이미 필수 규칙 모두 존재, 변경 불필요'
        return 0
    fi

    local use_dropin=0
    if _u66_has_rsyslog_include && [[ -d "$dropin_dir" ]]; then
        local _other_confs
        _other_confs=$(find "$dropin_dir" -maxdepth 1 -name '*.conf' -type f \
                           ! -name '00-kisa.conf' 2>/dev/null | wc -l)
        (( _other_confs > 0 )) && use_dropin=1
    fi

    local modified=()
    if (( vendor_changed )); then
        modified+=("$main_f")
    fi

    if (( use_dropin )); then
        # dropin_dir 생성
        mkdir -p "$dropin_dir"
        # 기존 dropin 충돌 처리 — 이미 있으면 .kisa.bak 으로 백업 후 새로 생성
        backup_file "$dropin"
        modified+=("$dropin")

        # dropin 파일 생성 (기존 내용 보존 후 누락 항목만 추가 — idempotent)
        local tmp; tmp="$KISA_TMP_DIR/tmp/u66.$$.$RANDOM"
        mkdir -p "$(dirname "$tmp")"

        {
            # 기존 dropin 내용이 있으면 먼저 포함
            if [[ -f "$dropin" ]]; then
                cat "$dropin"
                printf '\n'
            else
                printf '# Managed by KISA U-66 (kisa-audit). Do not edit manually.\n'
            fi

            for line in "${missing_lines[@]}"; do
                printf '%s\n' "$line"
            done

            if [[ -n "$remote_line" ]]; then
                printf '# Remote syslog forwarding (RSYSLOG_REMOTE_SERVER)\n'
                printf '%s\n' "$remote_line"
            fi
        } > "$tmp"

        # atomic replace
        install -m 0640 -o root -g root "$tmp" "$dropin"
        rm -f "$tmp"
        command -v restorecon >/dev/null 2>&1 && restorecon "$dropin" 2>/dev/null || true
    else
        # main 파일 직접 수정
        if (( vendor_changed == 0 )); then
            backup_file "$main_f"
            modified+=("$main_f")
        fi
        {
            printf '\n# [KISA U-66]\n'
            for line in "${missing_lines[@]}"; do
                printf '%s\n' "$line"
            done
            if [[ -n "$remote_line" ]]; then
                printf '# Remote syslog forwarding\n'
                printf '%s\n' "$remote_line"
            fi
        } >> "$main_f"
    fi

    # rsyslogd -N1 syntax check
    if ! rsyslogd -N1 2>/dev/null; then
        local m
        for m in "${modified[@]}"; do restore_file "$m" || true; done
        printf '조치 실패 — rsyslogd -N1 검증 실패, 원복 완료'
        return 1
    fi

    # rsyslog enable + restart 큐잉
    systemctl unmask rsyslog >/dev/null 2>&1 || true
    systemctl enable rsyslog >/dev/null 2>&1 || true
    _queue_service_op restart "$svc"
    _queue_rollback   systemctl_restart "$svc"

    local extra=""
    [[ -n "$remote_line" ]] && extra=" + 원격전송($remote_target)"
    printf '조치 완료 — 규칙 %d개%s 을 %s 에 추가; rsyslogd -N1 통과; rsyslog restart 지연' \
           "${#missing_lines[@]}" "$extra" "$dropin"
}
