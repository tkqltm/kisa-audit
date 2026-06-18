#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-62: 로그인 시 경고 메시지 설정 (중요도: 하)
# KISA 가이드: /etc/issue, /etc/issue.net, /etc/motd 에 경고 메시지 설정.
#   SSH Banner 를 /etc/issue.net 으로 지정.
#
# Rocky 8  : sshd_config main 파일에 Banner /etc/issue.net 직접 설정.
# Rocky 9/10: sshd_config.d drop-in 에 Banner /etc/issue.net 설정.
#   LOGIN_BANNER_TEXT 환경변수(기본값: kisa-audit.sh 하드코딩) 사용.
#
# 조치 전략:
#   1) /etc/issue, /etc/issue.net, /etc/motd → LOGIN_BANNER_TEXT 내용 기록
#      (기존 OS 버전 노출 이스케이프 시퀀스 제거)
#   2) sshd Banner 설정 (OS_MAJOR 에 따라 분기)
#   3) sshd -t 검증 → 실패 시 sshd 관련 변경 원복
#   4) sshd reload 큐잉
#
# 롤백 전략: 각 파일 restore_file + sshd reload

h_U_62_meta() {
    cat <<'JSON'
{
  "code": "U-62",
  "title": "로그인 시 경고 메시지 설정",
  "severity": "하",
  "category": "서비스 관리",
  "purpose": "비인가자들에게 서버에 대한 불필요한 정보를 제공하지 않고, 서버 접속 시 관계자만 접속해야 한다는 경각심을 심어 주기 위함",
  "threat": "로그온 시 경고 메시지가 설정되어 있지 않을 경우, 기본 설정값엔 서버 OS 버전 및 서비스 버전이 비인가자에게 노출되어 해당 정보를 통해 서비스의 취약점을 이용하여 공격을 시도할 위험이 존재함",
  "criterion_good": "서버 및 Telnet, FTP, SMTP, DNS 서비스에 로그온 시 경고 메시지가 설정된 경우",
  "criterion_bad": "서버 및 Telnet, FTP, SMTP, DNS 서비스에 로그온 시 경고 메시지가 설정되어 있지 않은 경우",
  "action_method": "Telnet, FTP, SMTP, DNS 서비스를 사용하는 경우 설정 파일을 통해 로그온 시 경고 메시지 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "서버 및 서비스에 로그온 시 불필요한 정보 차단 설정 및 불법적인 사용에 대한 경고 메시지 출력 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-62 (2026 ver.)"
  ]
}
JSON
}

_u_62_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: 로그인 경고 메시지 설정 여부"
        echo
        local _f
        for _f in /etc/issue /etc/issue.net /etc/motd; do
            echo "## $_f (배너 내용)"
            if [[ -f "$_f" ]]; then
                if [[ -s "$_f" ]]; then
                    cat "$_f" 2>/dev/null
                else
                    echo "(빈 파일)"
                fi
            else
                echo "(파일 없음)"
            fi
            echo
        done
        echo
        echo "## sshd Banner 설정 (sshd -T 결과)"
        if command -v sshd >/dev/null 2>&1; then
            sshd -T 2>/dev/null | grep -i '^banner' | head -3 || echo "(sshd -T banner 없음)"
        else
            echo "(sshd 명령 없음)"
        fi
        echo
        echo "## /etc/ssh/sshd_config 의 Banner 라인"
        if [[ -f /etc/ssh/sshd_config ]]; then
            grep -nE '^[[:space:]]*Banner[[:space:]]' /etc/ssh/sshd_config 2>&1 || echo "(main config: Banner 라인 없음)"
        fi
        echo
        echo "## /etc/ssh/sshd_config.d/ Banner 드롭인"
        if [[ -d /etc/ssh/sshd_config.d ]]; then
            grep -nE '^[[:space:]]*Banner[[:space:]]' /etc/ssh/sshd_config.d/*.conf 2>/dev/null || echo "(drop-in: Banner 라인 없음)"
        fi
    } | _evidence_capture "$label"
}


_u62_issue()     { printf '/etc/issue'; }
_u62_issue_net() { printf '/etc/issue.net'; }
_u62_motd()      { printf '/etc/motd'; }
_u62_sshd_main() { printf '/etc/ssh/sshd_config'; }
_u62_sshd_drop() { printf '/etc/ssh/sshd_config.d/00-kisa-banner.conf'; }

_u62_banner_text() {
    printf '%s' "${LOGIN_BANNER_TEXT:-Authorized users only. All activity on this system may be monitored and recorded. Unauthorized access is strictly prohibited.}"
}

_u62_has_sshd_include() {
    local main; main="$(_u62_sshd_main)"
    [[ -r "$main" ]] || return 1
    grep -qE '^[[:space:]]*Include[[:space:]]+.*sshd_config\.d' "$main"
}

# 배너 파일 내용이 OS 버전 정보 노출 이스케이프(\S \r \m 등) 없이 경고 텍스트 포함 여부
_u62_file_ok() {
    local f="$1"
    [[ -r "$f" ]] || return 1
    # OS 이스케이프 시퀀스가 있으면 취약
    grep -qE '\\[SrmnolpR]' "$f" && return 1
    # 내용이 비어있거나 기본 OS 버전 정보만 있으면 취약
    local content; content="$(cat "$f" 2>/dev/null)"
    [[ -z "$content" ]] && return 1
    return 0
}

_u62_sshd_banner_ok() {
    local main; main="$(_u62_sshd_main)"
    # sshd -T 로 effective Banner 확인
    local val
    val=$(sshd -T 2>/dev/null | awk 'tolower($1)=="banner"{print $2; exit}')
    [[ -n "$val" && "$val" != "none" ]] && return 0
    return 1
}

h_U_62_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_62_capture_state "$KISA_PHASE"
    fi

    local issue_ok=0 issue_net_ok=0 motd_ok=0 banner_ok=0

    _u62_file_ok "$(_u62_issue)"     && issue_ok=1
    _u62_file_ok "$(_u62_issue_net)" && issue_net_ok=1
    _u62_file_ok "$(_u62_motd)"      && motd_ok=1
    _u62_sshd_banner_ok              && banner_ok=1

    if (( issue_ok && issue_net_ok && motd_ok && banner_ok )); then
        printf '양호 — 경고 메시지 설정됨 (issue/issue.net/motd + SSH Banner)'
        return 0
    fi

    local missing=""
    (( issue_ok == 0 ))     && missing="${missing}issue "
    (( issue_net_ok == 0 )) && missing="${missing}issue.net "
    (( motd_ok == 0 ))      && missing="${missing}motd "
    (( banner_ok == 0 ))    && missing="${missing}SSH-Banner "
    printf '취약 — 경고 메시지 미설정 또는 OS 버전 노출: %s' "${missing% }"
    return 1
}

h_U_62_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        local rc; h_U_62_check >/dev/null 2>&1; rc=$?
        if (( rc == 0 )); then
            printf '(dry-run) 이미 양호 — 조치 불필요'
        else
            printf '(dry-run) /etc/issue + /etc/issue.net + /etc/motd 경고 메시지 설정; SSH Banner /etc/issue.net 설정; sshd reload 지연'
        fi
        return 0
    fi

    local rc; h_U_62_check >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then
        printf '양호 — 이미 경고 메시지 설정됨 (issue/issue.net/motd + SSH Banner)'
        return 0
    fi

    local banner; banner="$(_u62_banner_text)"

    # --- /etc/issue ---
    if ! _u62_file_ok "$(_u62_issue)"; then
        backup_file "$(_u62_issue)"
        printf '%s\n' "$banner" | atomic_write "$(_u62_issue)" 0644 root root
    fi

    # --- /etc/issue.net ---
    if ! _u62_file_ok "$(_u62_issue_net)"; then
        backup_file "$(_u62_issue_net)"
        printf '%s\n' "$banner" | atomic_write "$(_u62_issue_net)" 0644 root root
    fi

    # --- /etc/motd ---
    if ! _u62_file_ok "$(_u62_motd)"; then
        backup_file "$(_u62_motd)"
        printf '%s\n' "$banner" | atomic_write "$(_u62_motd)" 0644 root root
    fi

    # --- SSH Banner 설정 ---
    local sshd_modified=()
    local main; main="$(_u62_sshd_main)"

    if ! _u62_sshd_banner_ok; then
        local use_dropin=0
        if _u62_has_sshd_include && [[ -d /etc/ssh/sshd_config.d ]]; then
            local _other_confs
            _other_confs=$(find /etc/ssh/sshd_config.d -maxdepth 1 -name '*.conf' -type f \
                               ! -name '00-kisa-banner.conf' 2>/dev/null | wc -l)
            (( _other_confs > 0 )) && use_dropin=1
        fi

        if (( use_dropin )); then
            # Rocky 9/10: drop-in
            local drop; drop="$(_u62_sshd_drop)"
            backup_file "$drop"
            sshd_modified+=("$drop")
            mkdir -p "$(dirname "$drop")"
            install -m 0600 -o root -g root /dev/null "$drop"
            printf '# Managed by KISA U-62 (kisa-audit). Do not edit manually.\nBanner /etc/issue.net\n' > "$drop"
            command -v restorecon >/dev/null 2>&1 && restorecon "$drop" 2>/dev/null || true
        else
            # Rocky 8: main 파일 직접 수정
            backup_file "$main"
            sshd_modified+=("$main")
            if grep -qE '^[[:space:]]*Banner[[:space:]]' "$main"; then
                set_kv "$main" 'Banner' 'Banner /etc/issue.net'
            else
                printf '\n# [KISA U-62]\nBanner /etc/issue.net\n' >> "$main"
            fi
        fi
    fi

    # sshd -t 검증
    if (( ${#sshd_modified[@]} > 0 )); then
        if ! sshd -t 2>/dev/null; then
            local m
            for m in "${sshd_modified[@]}"; do restore_file "$m" || true; done
            printf '조치 실패 — sshd -t 검증 실패로 SSH 관련 변경 원복 완료'
            return 1
        fi
        _queue_service_op reload sshd
        _queue_rollback   systemctl_reload sshd
    fi

    printf '조치 완료 — /etc/issue + /etc/issue.net + /etc/motd 경고 메시지 설정; SSH Banner /etc/issue.net; sshd reload 지연'
    return 0
}
