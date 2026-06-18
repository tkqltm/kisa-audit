#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-53: FTP 서비스 정보 노출 제한 (중요도: 하)
# KISA 가이드: vsFTP ftpd_banner 설정으로 버전 정보 노출 차단.
#   no_anon_password=YES 도 함께 설정.
#
# Rocky 8/9/10: vsftpd 미설치 시 N/A.
#   vsftpd 설정 파일: /etc/vsftpd/vsftpd.conf (Rocky 계열 기본 경로).
#
# 조치 전략:
#   1) vsftpd 미설치 → N/A
#   2) ftpd_banner 미설정 또는 빈 값이면 취약
#   3) ftpd_banner=<LOGIN_BANNER_TEXT 일부> 설정
#      no_anon_password=YES 설정
#   4) vsftpd reload/restart 큐잉
#
# 롤백 전략: /etc/vsftpd/vsftpd.conf restore_file + vsftpd restart

h_U_53_meta() {
    cat <<'JSON'
{
  "code": "U-53",
  "title": "FTP 서비스 정보 노출 제한",
  "severity": "하",
  "category": "서비스 관리",
  "purpose": "FTP 서비스 접속 배너를 통한 불필요한 정보 노출을 방지하기 위함",
  "threat": "서비스 접속 배너가 차단되지 않을 경우, 비인가자가 FTP 접속 시도 시 노출되는 접속 배너 정보를 수집하여 악의적인 공격에 이용할 위험이 존재함",
  "criterion_good": "FTP 접속 배너에 노출되는 정보가 없는 경우",
  "criterion_bad": "FTP 접속 배너에 노출되는 정보가 있는 경우",
  "action_method": "- FTP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 - FTP 서비스 사용 시 FTP 설정 파일을 통해 접속 배너 설정 ※ 접속 배너에 서비스 이름이나 버전 정보를 노출하지 않는 것을 권고",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "FTP 서비스 정보 노출 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-53 (2026 ver.)"
  ]
}
JSON
}

_u_53_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: FTP 서비스 비활성화 여부"
        echo
        echo "## FTP 패키지 설치 (vsftpd / proftpd / pure-ftpd)"
        for pkg in vsftpd proftpd pure-ftpd; do
            printf '%-12s : %s\n' "$pkg" "$(rpm -q "$pkg" 2>&1)"
        done
        echo
        echo "## FTP 관련 systemd 서비스 상태"
        for svc in vsftpd vsftpd.socket proftpd pure-ftpd; do
            printf '%-18s is-enabled=%s   is-active=%s\n' \
                "$svc" \
                "$(systemctl is-enabled "$svc" 2>&1)" \
                "$(systemctl is-active  "$svc" 2>&1)"
        done
        echo
        echo "## vsftpd.conf 활성 설정 라인"
        local _cf=""
        if [[ -f /etc/vsftpd/vsftpd.conf ]]; then _cf=/etc/vsftpd/vsftpd.conf
        elif [[ -f /etc/vsftpd.conf ]]; then _cf=/etc/vsftpd.conf
        fi
        if [[ -n "$_cf" ]]; then
            grep -nvE '^[[:space:]]*(#|$)' "$_cf" 2>/dev/null || echo "(활성 항목 없음)"
        else
            echo "(vsftpd.conf 없음)"
        fi
        echo
        echo "## TCP 21(ftp) LISTEN 상태"
        if command -v ss >/dev/null 2>&1; then
            ss -tlnp 2>/dev/null | awk 'NR==1 || $4 ~ /:21$/' || true
        fi
    } | _evidence_capture "$label"
}


_u53_vsftpd_conf() {
    if [[ -f /etc/vsftpd/vsftpd.conf ]]; then
        printf '/etc/vsftpd/vsftpd.conf'
    else
        printf '/etc/vsftpd.conf'
    fi
}

_u53_vsftpd_installed() {
    rpm -q vsftpd >/dev/null 2>&1
}

_u53_banner_ok() {
    local cf; cf="$(_u53_vsftpd_conf)"
    [[ -r "$cf" ]] || return 1
    local val
    val=$(grep -E '^[[:space:]]*ftpd_banner[[:space:]]*=' "$cf" \
          | tail -1 | sed 's/.*=[[:space:]]*//')
    # 미설정이거나 빈 값이면 취약
    [[ -z "$val" ]] && return 1
    return 0
}

_u53_anon_pw_ok() {
    local cf; cf="$(_u53_vsftpd_conf)"
    [[ -r "$cf" ]] || return 1
    grep -qiE '^[[:space:]]*no_anon_password[[:space:]]*=[[:space:]]*YES' "$cf"
}

h_U_53_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_53_capture_state "$KISA_PHASE"
    fi

    if ! _u53_vsftpd_installed; then
        printf '양호 — vsftpd 미설치(FTP 서비스 없음, 취약점 해당없음)'
        return 0
    fi

    local cf; cf="$(_u53_vsftpd_conf)"
    if [[ ! -r "$cf" ]]; then
        printf 'vsftpd.conf 읽기 실패: %s' "$cf"
        return 2
    fi

    local banner_ok=0 anon_ok=0
    _u53_banner_ok   && banner_ok=1
    _u53_anon_pw_ok  && anon_ok=1

    if (( banner_ok == 0 )); then
        printf '취약 — ftpd_banner 미설정, FTP 접속 시 버전 정보 노출'
        return 1
    fi

    local anon_str; (( anon_ok )) && anon_str='YES' || anon_str='미설정'
    printf '양호 — ftpd_banner 설정됨, no_anon_password=%s' "$anon_str"
    return 0
}

h_U_53_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        if ! _u53_vsftpd_installed; then
            printf '(dry-run) vsftpd 미설치, 조치 불필요(N/A)'
            return 0
        fi
        printf '(dry-run) vsftpd.conf ftpd_banner + no_anon_password=YES 설정 예정; vsftpd restart 지연'
        return 0
    fi

    if ! _u53_vsftpd_installed; then
        printf '해당없음 — vsftpd 미설치(FTP 서비스 없음)'
        return 3
    fi

    local rc; h_U_53_check >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then
        printf '양호 — 이미 ftpd_banner + no_anon_password 설정됨'
        return 0
    fi

    local cf; cf="$(_u53_vsftpd_conf)"
    if [[ ! -f "$cf" ]]; then
        printf '조치 실패 — vsftpd.conf 없음: %s' "$cf"
        return 1
    fi

    backup_file "$cf"

    # ftpd_banner: LOGIN_BANNER_TEXT 에서 첫 80자 추출, 개행 제거
    local banner_text
    banner_text="${LOGIN_BANNER_TEXT:-Authorized users only. All activity may be monitored.}"
    banner_text="$(printf '%s' "$banner_text" | tr -d '\n' | cut -c1-80)"

    if ! _u53_banner_ok; then
        set_kv "$cf" 'ftpd_banner' "ftpd_banner=${banner_text}"
    fi

    if ! _u53_anon_pw_ok; then
        set_kv "$cf" 'no_anon_password' 'no_anon_password=YES'
    fi

    _queue_service_op restart vsftpd
    _queue_rollback   systemctl_restart vsftpd

    printf '조치 완료 — vsftpd ftpd_banner + no_anon_password=YES 설정, vsftpd restart 지연'
    return 0
}
