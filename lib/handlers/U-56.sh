#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-56: FTP 서비스 접근 제어 설정 (중요도: 하)
# KISA 가이드: vsftpd userlist/tcp_wrappers 기반 접근 제어 적용.
#
# Rocky 8/9/10: vsftpd 미설치 시 N/A.
#   접근 제어 판단 기준:
#     - vsftpd.conf 에 tcp_wrappers=YES 설정
#     - 또는 userlist_enable=YES + userlist_file 존재
#     - 또는 pam_listfile 기반 PAM 설정
#   auto 조치: tcp_wrappers=YES + userlist_enable=YES 설정 (vsftpd 에서 지원 시)
#              Rocky 계열 tcp_wrappers 지원 여부 확인.
#
# 조치 전략:
#   1) vsftpd 미설치 → N/A
#   2) 접근 제어 설정 확인
#   3) tcp_wrappers 지원 여부에 따라 자동/manual 분기
#      - tcp_wrappers: vsftpd --version 출력에 tcp_wrappers 지원 명시 여부
#      - 지원 시 tcp_wrappers=YES 설정
#      - userlist_enable=YES 설정 (user_list 파일 기반 제어)
#   4) vsftpd restart 큐잉
#
# 롤백 전략: vsftpd.conf restore_file + vsftpd restart

h_U_56_meta() {
    cat <<'JSON'
{
  "code": "U-56",
  "title": "FTP 서비스 접근 제어 설정",
  "severity": "하",
  "category": "서비스 관리",
  "purpose": "접근 권한이 없는 비인가자의 접근을 통제하기 위함",
  "threat": "FTP 서비스의 접근제한 설정이 적절하지 않을 경우, 인증 절차 없이 비인가자가 디렉터리나 파일에 접근할 수 있어 중요 파일 변조 및 유출을 시도할 위험이 존재함",
  "criterion_good": "특정 IP주소 또는 호스트에서만 FTP 서버에 접속할 수 있도록 접근 제어 설정을 적용한 경우",
  "criterion_bad": "FTP 서버에 접근 제어 설정을 적용하지 않은 경우",
  "action_method": "- FTP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 - FTP 서비스 사용 시 접근 제어 설정",
  "action_impact": "특정 IP주소 또는 호스트에서만 FTP 접속이 가능함",
  "method": [
    "FTP 서비스에 비인가자의 접근 가능 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-56 (2026 ver.)"
  ]
}
JSON
}

_u_56_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: FTP 서비스 접근 제어 설정 (tcp_wrappers / userlist / PAM)"
        echo
        echo "## vsftpd 패키지 + 서비스 상태"
        rpm -q vsftpd 2>&1 || true
        echo "is-enabled vsftpd: $(systemctl is-enabled vsftpd 2>&1)"
        echo "is-active  vsftpd: $(systemctl is-active  vsftpd 2>&1)"
        echo
        local _cf
        if [[ -f /etc/vsftpd/vsftpd.conf ]]; then _cf=/etc/vsftpd/vsftpd.conf
        elif [[ -f /etc/vsftpd.conf ]]; then _cf=/etc/vsftpd.conf
        else _cf=""; fi
        echo "## vsftpd.conf 접근 제어 키 (tcp_wrappers, userlist_*, pam_service_name)"
        if [[ -n "$_cf" ]]; then
            grep -niE '^[[:space:]]*(tcp_wrappers|userlist_enable|userlist_deny|userlist_file|pam_service_name|listen_address|local_enable|allow_writeable_chroot)[[:space:]]*=' "$_cf" 2>&1 || echo "(관련 라인 없음)"
        else
            echo "(vsftpd.conf 없음)"
        fi
        echo
        echo "## /etc/vsftpd/user_list (활성 라인)"
        if [[ -f /etc/vsftpd/user_list ]]; then
            grep -nvE '^[[:space:]]*(#|$)' /etc/vsftpd/user_list 2>/dev/null || echo "(활성 항목 없음)"
        else
            echo "(/etc/vsftpd/user_list 없음)"
        fi
        echo
        echo "## /etc/pam.d/vsftpd (활성 라인)"
        if [[ -f /etc/pam.d/vsftpd ]]; then
            grep -nvE '^[[:space:]]*(#|$)' /etc/pam.d/vsftpd 2>/dev/null || echo "(활성 항목 없음)"
        fi
        echo
        echo "## /etc/hosts.allow / /etc/hosts.deny (TCP Wrapper)"
        for f in /etc/hosts.allow /etc/hosts.deny; do
            if [[ -f "$f" ]]; then
                grep -nE '^[[:space:]]*(vsftpd|ALL)' "$f" 2>&1 || echo "($f: vsftpd/ALL 라인 없음)"
            fi
        done
    } | _evidence_capture "$label"
}


_u56_vsftpd_conf() {
    if [[ -f /etc/vsftpd/vsftpd.conf ]]; then
        printf '/etc/vsftpd/vsftpd.conf'
    else
        printf '/etc/vsftpd.conf'
    fi
}

_u56_vsftpd_installed() {
    rpm -q vsftpd >/dev/null 2>&1
}

_u56_tcp_wrappers_supported() {
    # vsftpd 가 tcp_wrappers 로 빌드됐는지 확인
    command -v vsftpd >/dev/null 2>&1 || return 1
    vsftpd --version 2>&1 | grep -qi 'tcp_wrappers' && return 0
    # Rocky 9/10 빌드에서는 tcp_wrappers 미지원이 일반적
    return 1
}

_u56_access_control_ok() {
    local cf; cf="$(_u56_vsftpd_conf)"
    [[ -r "$cf" ]] || return 1

    # tcp_wrappers=YES
    grep -qiE '^[[:space:]]*tcp_wrappers[[:space:]]*=[[:space:]]*YES' "$cf" && return 0
    # userlist_enable=YES
    grep -qiE '^[[:space:]]*userlist_enable[[:space:]]*=[[:space:]]*YES' "$cf" && return 0

    return 1
}

h_U_56_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_56_capture_state "$KISA_PHASE"
    fi

    if ! _u56_vsftpd_installed; then
        printf '양호 — vsftpd 미설치(FTP 서비스 없음, 취약점 해당없음)'
        return 0
    fi

    local cf; cf="$(_u56_vsftpd_conf)"
    if [[ ! -r "$cf" ]]; then
        printf 'vsftpd.conf 읽기 실패: %s' "$cf"
        return 2
    fi

    if _u56_access_control_ok; then
        local ctrl=""
        grep -qiE '^[[:space:]]*tcp_wrappers[[:space:]]*=[[:space:]]*YES' "$cf" && ctrl="${ctrl}tcp_wrappers=YES "
        grep -qiE '^[[:space:]]*userlist_enable[[:space:]]*=[[:space:]]*YES' "$cf" && ctrl="${ctrl}userlist_enable=YES"
        printf '양호 — FTP 접근 제어 설정됨: %s' "${ctrl% }"
        return 0
    fi

    printf '취약 — vsftpd 접근 제어 미설정 (tcp_wrappers/userlist 없음)'
    return 1
}

h_U_56_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        if ! _u56_vsftpd_installed; then
            printf '(dry-run) vsftpd 미설치, 조치 불필요(N/A)'
            return 0
        fi
        local rc; h_U_56_check >/dev/null 2>&1; rc=$?
        if (( rc == 0 )); then
            printf '(dry-run) 이미 양호, 조치 불필요'
        else
            printf '(dry-run) vsftpd.conf userlist_enable=YES + userlist_deny=YES 설정 예정'
        fi
        return 0
    fi

    if ! _u56_vsftpd_installed; then
        printf '해당없음 — vsftpd 미설치(FTP 서비스 없음)'
        return 3
    fi

    local rc; h_U_56_check >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then
        printf '양호 — 이미 접근 제어 설정됨, 조치 불필요'
        return 0
    fi

    local cf; cf="$(_u56_vsftpd_conf)"
    if [[ ! -f "$cf" ]]; then
        printf '조치 실패 — vsftpd.conf 없음: %s' "$cf"
        return 1
    fi

    backup_file "$cf"

    # userlist 기반 접근 제어 설정
    set_kv "$cf" 'userlist_enable' 'userlist_enable=YES'
    set_kv "$cf" 'userlist_deny'   'userlist_deny=YES'

    # user_list 파일 경로 확인 (없으면 기본 경로 생성)
    local ul_file='/etc/vsftpd/user_list'
    if [[ ! -f "$ul_file" ]]; then
        local ul_dir; ul_dir="$(dirname "$ul_file")"
        [[ -d "$ul_dir" ]] || mkdir -p "$ul_dir"
        printf '# vsftpd user_list — 이 파일에 등록된 계정은 FTP 접근 차단됨(userlist_deny=YES)\n# 시스템 계정을 추가하여 FTP 접근 차단하세요.\nroot\nbin\ndaemon\nadm\nlp\nsync\nshutdown\nhalt\nmail\nnobody\n' > "$ul_file"
        chmod 640 "$ul_file"
        chown root:root "$ul_file" 2>/dev/null || true
    fi

    # tcp_wrappers 지원 시 추가 설정
    if _u56_tcp_wrappers_supported; then
        set_kv "$cf" 'tcp_wrappers' 'tcp_wrappers=YES'
    fi

    _queue_service_op restart vsftpd
    _queue_rollback   systemctl_restart vsftpd

    printf '조치 완료 — vsftpd userlist_enable=YES + userlist_deny=YES 설정; vsftpd restart 지연'
    return 0
}
