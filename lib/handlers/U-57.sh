#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-57: Ftpusers 파일 설정 (중요도: 중)
# KISA 가이드: /etc/vsftpd/ftpusers 또는 /etc/vsftpd/user_list 에 root 포함.
#
# Rocky 8/9/10: vsftpd 미설치 시 N/A.
#   Rocky vsftpd 기본 설치 시 /etc/vsftpd/ftpusers, /etc/vsftpd/user_list 존재.
#   user_list + userlist_deny=YES 구성에서 root 가 주석 처리되면 취약.
#   ftpusers 파일에 root 가 주석 처리되어 있어도 취약.
#
# 조치 전략:
#   1) vsftpd 미설치 → N/A
#   2) ftpusers, user_list 에 주석 없는 root 라인 확인
#   3) 없거나 주석 처리됐으면 → 주석 제거 또는 추가
#   4) vsftpd.conf userlist_deny=YES 확인 (user_list 사용 시)
#
# 롤백 전략: 해당 파일들 restore_file

h_U_57_meta() {
    cat <<'JSON'
{
  "code": "U-57",
  "title": "Ftpusers 파일 설정",
  "severity": "중",
  "category": "서비스 관리",
  "purpose": "root 계정의 FTP 직접 접속을 제한하여 root 비밀번호 정보 노출을 방지하기 위함",
  "threat": "FTP 서비스에 root 계정으로 접근할 경우, 데이터가 평문으로 전송되어 비인가자가 스니핑을 통해 관리자 계정 및 중요 정보를 외부로 유출할 위험이 존재함",
  "criterion_good": "root 계정 접속을 차단한 경우",
  "criterion_bad": "root 계정 접속을 허용한 경우",
  "action_method": "- FTP 서비스를 사용하지 않는 경우 서비스 중지 및 비활성화 설정 - FTP 서비스 사용 시 root 계정으로 직접 접속할 수 없도록 설정",
  "action_impact": "애플리케이션에서 root 계정으로 직접 접속하여 FTP를 사용하고 있는 경우 확인 필요",
  "method": [
    "FTP 서비스에 root 계정 접근 제한 설정 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-57 (2026 ver.)"
  ]
}
JSON
}

_u_57_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령:"
        echo "## vsftpd 패키지 설치 여부"
        rpm -q vsftpd 2>&1 || true
        echo
        echo "## /etc/vsftpd/ftpusers (root 라인 매칭)"
        if [[ -f /etc/vsftpd/ftpusers ]]; then
            grep -nE '^[[:space:]]*#?[[:space:]]*root[[:space:]]*$' /etc/vsftpd/ftpusers 2>&1 || echo "(root 라인 없음)"
        else
            echo "(/etc/vsftpd/ftpusers 없음)"
        fi
        echo
        echo "## /etc/vsftpd/user_list (root 라인 매칭)"
        if [[ -f /etc/vsftpd/user_list ]]; then
            grep -nE '^[[:space:]]*#?[[:space:]]*root[[:space:]]*$' /etc/vsftpd/user_list 2>&1 || echo "(root 라인 없음)"
        else
            echo "(/etc/vsftpd/user_list 없음)"
        fi
        echo
        echo "## vsftpd.conf userlist_deny 설정"
        local _cf
        if [[ -f /etc/vsftpd/vsftpd.conf ]]; then _cf=/etc/vsftpd/vsftpd.conf
        elif [[ -f /etc/vsftpd.conf ]]; then _cf=/etc/vsftpd.conf
        else _cf=""; fi
        if [[ -n "$_cf" ]]; then
            grep -niE '^[[:space:]]*userlist_(enable|deny)[[:space:]]*=' "$_cf" 2>&1 || echo "(userlist_enable/userlist_deny 라인 없음)"
        else
            echo "(vsftpd.conf 없음)"
        fi
        echo
        echo "## 서비스 상태"
        echo "is-enabled vsftpd: $(systemctl is-enabled vsftpd 2>&1)"
        echo "is-active  vsftpd: $(systemctl is-active  vsftpd 2>&1)"
    } | _evidence_capture "$label"
}


_u57_vsftpd_conf() {
    if [[ -f /etc/vsftpd/vsftpd.conf ]]; then
        printf '/etc/vsftpd/vsftpd.conf'
    else
        printf '/etc/vsftpd.conf'
    fi
}

_u57_vsftpd_installed() {
    rpm -q vsftpd >/dev/null 2>&1
}

# root 가 주석 없이 파일에 있으면 0(OK), 없거나 주석처리면 1(취약)
_u57_root_in_file() {
    local f="$1"
    [[ -r "$f" ]] || return 1
    grep -qE '^[[:space:]]*root[[:space:]]*$' "$f"
}

_u57_is_ok() {
    local ftpusers='/etc/vsftpd/ftpusers'
    local user_list='/etc/vsftpd/user_list'

    # ftpusers 에 root 있으면 OK
    if [[ -f "$ftpusers" ]] && _u57_root_in_file "$ftpusers"; then
        return 0
    fi

    # user_list 에 root 있고 userlist_deny=YES 이면 OK
    if [[ -f "$user_list" ]] && _u57_root_in_file "$user_list"; then
        local cf; cf="$(_u57_vsftpd_conf)"
        [[ -r "$cf" ]] || return 1
        if grep -qiE '^[[:space:]]*userlist_deny[[:space:]]*=[[:space:]]*YES' "$cf"; then
            return 0
        fi
    fi

    return 1
}

h_U_57_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_57_capture_state "$KISA_PHASE"
    fi

    if ! _u57_vsftpd_installed; then
        printf '양호 — vsftpd 미설치(FTP 서비스 없음, 취약점 해당없음)'
        return 0
    fi

    local ftpusers='/etc/vsftpd/ftpusers'
    local user_list='/etc/vsftpd/user_list'

    if ! [[ -f "$ftpusers" ]] && ! [[ -f "$user_list" ]]; then
        printf '취약 — ftpusers/user_list 파일 없음, root FTP 접근 차단 불가'
        return 1
    fi

    if _u57_is_ok; then
        printf '양호 — ftpusers/user_list 에 root 포함됨, root FTP 접근 차단'
        return 0
    fi

    printf '취약 — ftpusers/user_list 에 root 미포함 또는 주석 처리됨'
    return 1
}

h_U_57_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        if ! _u57_vsftpd_installed; then
            printf '(dry-run) vsftpd 미설치, 조치 불필요(N/A)'
            return 0
        fi
        local rc; h_U_57_check >/dev/null 2>&1; rc=$?
        (( rc == 0 )) \
            && printf '(dry-run) 이미 양호, 조치 불필요' \
            || printf '(dry-run) ftpusers/user_list 에 root 추가 예정'
        return 0
    fi

    if ! _u57_vsftpd_installed; then
        printf '해당없음 — vsftpd 미설치(FTP 서비스 없음)'
        return 3
    fi

    local rc; h_U_57_check >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then
        printf '양호 — 이미 root FTP 접근 차단됨'
        return 0
    fi

    local ftpusers='/etc/vsftpd/ftpusers'
    local user_list='/etc/vsftpd/user_list'
    local changed=0

    # --- ftpusers 처리 ---
    if [[ -f "$ftpusers" ]]; then
        if ! _u57_root_in_file "$ftpusers"; then
            backup_file "$ftpusers"
            # 주석 처리된 #root → root 로 변경, 없으면 추가
            local tmp; tmp="${KISA_TMP_DIR}/tmp/u57_ftpusers.$$.${RANDOM}"
            mkdir -p "${KISA_TMP_DIR}/tmp"
            awk '
                /^[[:space:]]*#[[:space:]]*root[[:space:]]*$/ { print "root"; changed=1; next }
                { print }
                END { if (!changed) print "root" }
            ' "$ftpusers" > "$tmp"
            # 위 awk 로직은 END 에서 always root 추가 가능성 있으므로 수정
            # 다시 단순하게: 주석 root 언주석, 없으면 append
            awk '
                /^[[:space:]]*#[[:space:]]*root[[:space:]]*$/ { sub(/^[[:space:]]*#[[:space:]]*/, ""); printed=1 }
                { print }
            ' "$ftpusers" > "$tmp"
            if ! grep -qE '^[[:space:]]*root[[:space:]]*$' "$tmp"; then
                printf 'root\n' >> "$tmp"
            fi
            local om; om=$(stat -c '%a' "$ftpusers" 2>/dev/null || printf '640')
            mv -f "$tmp" "$ftpusers"
            chmod "$om" "$ftpusers" 2>/dev/null || true
            chown root:root "$ftpusers" 2>/dev/null || true
            changed=1
        fi
    fi

    # --- user_list 처리 ---
    if [[ -f "$user_list" ]]; then
        if ! _u57_root_in_file "$user_list"; then
            backup_file "$user_list"
            local tmp2; tmp2="${KISA_TMP_DIR}/tmp/u57_userlist.$$.${RANDOM}"
            mkdir -p "${KISA_TMP_DIR}/tmp"
            awk '
                /^[[:space:]]*#[[:space:]]*root[[:space:]]*$/ { sub(/^[[:space:]]*#[[:space:]]*/, "") }
                { print }
            ' "$user_list" > "$tmp2"
            if ! grep -qE '^[[:space:]]*root[[:space:]]*$' "$tmp2"; then
                printf 'root\n' >> "$tmp2"
            fi
            local om2; om2=$(stat -c '%a' "$user_list" 2>/dev/null || printf '640')
            mv -f "$tmp2" "$user_list"
            chmod "$om2" "$user_list" 2>/dev/null || true
            chown root:root "$user_list" 2>/dev/null || true
            changed=1
        fi
        # userlist_deny=YES 확인 및 설정
        local cf; cf="$(_u57_vsftpd_conf)"
        if [[ -f "$cf" ]] && ! grep -qiE '^[[:space:]]*userlist_deny[[:space:]]*=[[:space:]]*YES' "$cf"; then
            backup_file "$cf"
            set_kv "$cf" 'userlist_deny' 'userlist_deny=YES'
            changed=1
        fi
    fi

    if [[ ! -f "$ftpusers" ]] && [[ ! -f "$user_list" ]]; then
        # 파일이 없으면 생성
        local ul_dir='/etc/vsftpd'
        [[ -d "$ul_dir" ]] || mkdir -p "$ul_dir"
        printf 'root\n' > "${ul_dir}/ftpusers"
        chmod 640 "${ul_dir}/ftpusers"
        chown root:root "${ul_dir}/ftpusers" 2>/dev/null || true
        changed=1
    fi

    if (( changed )); then
        _queue_service_op restart vsftpd
        _queue_rollback   systemctl_restart vsftpd
        printf '조치 완료 — ftpusers/user_list 에 root 차단 설정(vsftpd restart 지연)'
        return 0
    fi

    printf '양호 — 이미 root FTP 접근 차단됨'
    return 0
}
