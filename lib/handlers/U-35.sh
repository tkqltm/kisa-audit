#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-35: 공유 서비스에 대한 익명 접근 제한 (중요도: 상)
# KISA 가이드: FTP(vsftpd/proftpd) 익명 접근 비활성화, Samba guest 접근 제한.
#
# Rocky 8/9/10 대상:
#   - vsftpd: /etc/vsftpd/vsftpd.conf 또는 /etc/vsftpd.conf → anonymous_enable=NO
#   - proftpd: /etc/proftpd.conf 또는 /etc/proftpd/proftpd.conf → <Anonymous> 블록 주석
#   - Samba(smb): /etc/samba/smb.conf → [global] 섹션에 map to guest = never
#     ※ Samba 기본 미설치 → 미설치 시 해당없음
#   - /etc/passwd 의 ftp/anonymous 계정 존재 여부
#
# 조치 전략:
#   vsftpd: set_kv anonymous_enable=NO + restart
#   proftpd: <Anonymous> 블록 주석화 + restart
#   samba: set_kv map to guest = never + restart
#
# 롤백 전략: backup_file 후 설정 변경. 서비스 restart는 _queue_rollback 등록.

h_U_35_meta() {
    cat <<'JSON'
{
  "code": "U-35",
  "title": "공유 서비스에 대한 익명 접근 제한 설정",
  "severity": "상",
  "category": "서비스 관리",
  "purpose": "공유 서비스의 익명 접근을 제한하여 중요 정보의 노출을 방지하기 위함",
  "threat": "공유 서비스의 익명 접근을 허용할 경우, 비인가자의 무단 접근으로 인한 중요 정보 탈취 또는 변조, 악성 코드 유포 등의 위험이 존재함",
  "criterion_good": "공유 서비스에 대해 익명 접근을 제한한 경우",
  "criterion_bad": "공유 서비스에 대해 익명 접근을 허용한 경우",
  "action_method": "공유 서비스의 익명 접근 제한 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "공유 서비스의 익명 접근 제한 설정 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-35 (2026 ver.)"
  ]
}
JSON
}

_u_35_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: 공유 서비스 익명 접근 제한 (anonymous FTP / Samba guest)"
        echo
        echo "## ftp/anonymous 계정 존재 여부"
        getent passwd ftp anonymous 2>&1 || echo "(ftp/anonymous 계정 없음)"
        echo
        echo "## vsftpd 패키지 + anonymous_enable 설정"
        rpm -q vsftpd 2>&1 || true
        local _vcf
        if [[ -f /etc/vsftpd/vsftpd.conf ]]; then _vcf=/etc/vsftpd/vsftpd.conf
        elif [[ -f /etc/vsftpd.conf ]]; then _vcf=/etc/vsftpd.conf
        else _vcf=""; fi
        if [[ -n "$_vcf" ]]; then
            grep -niE '^[[:space:]]*(anonymous_enable|anon_world_readable_only|anon_root|anon_upload_enable|anon_mkdir_write_enable|no_anon_password)[[:space:]]*=' "$_vcf" 2>&1 || echo "(anonymous_* 라인 없음)"
        else
            echo "(vsftpd.conf 없음)"
        fi
        echo
        echo "## proftpd 패키지 + 익명 설정"
        rpm -q proftpd 2>&1 || true
        for pcf in /etc/proftpd.conf /etc/proftpd/proftpd.conf; do
            if [[ -f "$pcf" ]]; then
                echo "### $pcf"
                grep -niE '<Anonymous|UserAlias|AnonymousGroup' "$pcf" 2>&1 || echo "(Anonymous 블록 없음)"
            fi
        done
        echo
        echo "## Samba 패키지 + guest/null session 설정"
        rpm -q samba 2>&1 || true
        if [[ -f /etc/samba/smb.conf ]]; then
            grep -niE '^[[:space:]]*(map[[:space:]]+to[[:space:]]+guest|guest[[:space:]]+(account|ok)|null[[:space:]]+passwords|usershare[[:space:]]+allow[[:space:]]+guests)' /etc/samba/smb.conf 2>&1 || echo "(guest/null 라인 없음)"
        else
            echo "(/etc/samba/smb.conf 없음)"
        fi
        echo
        echo "## 서비스 상태"
        for svc in vsftpd proftpd smb nmb; do
            printf '%-10s is-enabled=%s   is-active=%s\n' \
                "$svc" \
                "$(systemctl is-enabled "$svc" 2>&1)" \
                "$(systemctl is-active  "$svc" 2>&1)"
        done
    } | _evidence_capture "$label"
}


_u35_vsftpd_conf() {
    if [[ -f /etc/vsftpd/vsftpd.conf ]]; then printf '/etc/vsftpd/vsftpd.conf'
    elif [[ -f /etc/vsftpd.conf ]];      then printf '/etc/vsftpd.conf'
    fi
}
_u35_proftpd_conf() {
    if [[ -f /etc/proftpd/proftpd.conf ]]; then printf '/etc/proftpd/proftpd.conf'
    elif [[ -f /etc/proftpd.conf ]];       then printf '/etc/proftpd.conf'
    fi
}
_u35_smb_conf() { printf '/etc/samba/smb.conf'; }

# vsftpd 익명 접근 활성화 여부 (0=활성, 1=비활성)
_u35_vsftpd_anon_on() {
    local f; f="$(_u35_vsftpd_conf)"
    [[ -z "$f" ]] && return 1
    # anonymous_enable=YES 이거나 설정 없을 때(기본 YES)
    local val
    val=$(grep -i '^[[:space:]]*anonymous_enable' "$f" 2>/dev/null | tail -1 | tr -d ' ' | cut -d= -f2 | tr '[:upper:]' '[:lower:]')
    if [[ "$val" == "no" ]]; then return 1; fi
    # 값이 없거나 YES 이면 활성
    return 0
}

# proftpd Anonymous 블록 활성화 여부 (0=활성, 1=없거나 비활성)
_u35_proftpd_anon_on() {
    local f; f="$(_u35_proftpd_conf)"
    [[ -z "$f" ]] && return 1
    # 비주석 <Anonymous 블록 존재 여부
    grep -qiE '^[[:space:]]*<Anonymous' "$f" 2>/dev/null && return 0
    return 1
}

# Samba guest ok 활성화 여부 (0=활성, 1=없거나 비활성)
_u35_smb_guest_on() {
    local f; f="$(_u35_smb_conf)"
    [[ -f "$f" ]] || return 1
    # guest ok = yes 또는 map to guest = bad user/bad password 는 guest 허용
    grep -qiE '^[[:space:]]*(guest ok|guest okay)[[:space:]]*=[[:space:]]*yes' "$f" 2>/dev/null && return 0
    local maptg
    maptg=$(grep -i '^[[:space:]]*map to guest' "$f" 2>/dev/null | tail -1 | tr -d ' ' | cut -d= -f2 | tr '[:upper:]' '[:lower:]')
    if [[ "$maptg" == "baduser" || "$maptg" == "badpassword" ]]; then return 0; fi
    return 1
}

h_U_35_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_35_capture_state "$KISA_PHASE"
    fi

    local issues=()
    local has_svc=0

    # vsftpd
    local vf; vf="$(_u35_vsftpd_conf)"
    if [[ -n "$vf" ]]; then
        has_svc=1
        if _u35_vsftpd_anon_on; then
            issues+=("vsftpd anonymous_enable=YES: $vf")
        fi
        # vsftpd 설치 상태 + ftp 계정 로그인 가능 shell 이면 취약
        if grep -qE '^(ftp|anonymous):[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:(/bin/bash|/bin/sh|/bin/dash)$' /etc/passwd 2>/dev/null; then
            issues+=('ftp/anonymous 계정에 로그인 shell 할당됨')
        fi
    fi

    # proftpd
    local pf; pf="$(_u35_proftpd_conf)"
    if [[ -n "$pf" ]]; then
        has_svc=1
        if _u35_proftpd_anon_on; then
            issues+=("proftpd <Anonymous> 블록 활성: $pf")
        fi
    fi

    # samba
    local sf; sf="$(_u35_smb_conf)"
    if [[ -f "$sf" ]]; then
        has_svc=1
        if _u35_smb_guest_on; then
            issues+=("Samba guest 접근 허용: $sf")
        fi
    fi

    if (( has_svc == 0 )); then
        printf '해당없음 — vsftpd/proftpd/samba 미설치, ftp 계정 없음'
        return 3
    fi

    if (( ${#issues[@]} == 0 )); then
        printf '양호 — 익명/guest 접근 제한 설정 적용됨'
        return 0
    fi

    printf '취약 — 익명/guest 접근 허용: %s' "${issues[*]}"
    return 1
}

h_U_35_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        local rc; h_U_35_check >/dev/null 2>&1; rc=$?
        case $rc in
            0) printf '(dry-run) 이미 양호, 조치 불필요' ;;
            3) printf '(dry-run) 관련 서비스 미설치, 조치 불필요(N/A)' ;;
            *) printf '(dry-run) vsftpd/proftpd/samba 익명 접근 비활성화 예정' ;;
        esac
        return 0
    fi

    local rc; h_U_35_check >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then printf '양호 — 이미 익명 접근 제한됨'; return 0; fi
    if (( rc == 3 )); then printf '해당없음 — 관련 서비스 미설치'; return 3; fi

    local changed=0 errs=()

    # vsftpd 처리
    local vf; vf="$(_u35_vsftpd_conf)"
    if [[ -n "$vf" ]] && _u35_vsftpd_anon_on; then
        backup_file "$vf"
        set_kv "$vf" 'anonymous_enable' 'anonymous_enable=NO'
        # vsftpd 서비스 있으면 재시작 큐
        local vsvc
        for vsvc in vsftpd vsftpd@; do
            if systemctl is-active "$vsvc" >/dev/null 2>&1; then
                _queue_service_op restart "$vsvc"
                _queue_rollback systemctl_restart "$vsvc"
                break
            fi
        done
        changed=1
    fi

    # proftpd 처리: <Anonymous> 블록 전체 주석 처리
    local pf; pf="$(_u35_proftpd_conf)"
    if [[ -n "$pf" ]] && _u35_proftpd_anon_on; then
        backup_file "$pf"
        local tmp="$KISA_TMP_DIR/tmp/u35.proftpd.$$.$RANDOM"
        mkdir -p "$(dirname "$tmp")"
        local om ou og
        om=$(stat -c '%a' "$pf" 2>/dev/null || true)
        ou=$(stat -c '%u' "$pf" 2>/dev/null || true)
        og=$(stat -c '%g' "$pf" 2>/dev/null || true)
        awk '
            /^[[:space:]]*<Anonymous/,/<\/Anonymous>/ {
                printf "# [KISA U-35] %s\n", $0
                next
            }
            { print }
        ' "$pf" > "$tmp"
        mv -f "$tmp" "$pf"
        [[ -n "$om" ]] && chmod "$om" "$pf" 2>/dev/null || true
        [[ -n "$ou" && -n "$og" ]] && chown "$ou:$og" "$pf" 2>/dev/null || true
        command -v restorecon >/dev/null 2>&1 && restorecon "$pf" 2>/dev/null || true
        if systemctl is-active proftpd >/dev/null 2>&1; then
            _queue_service_op restart proftpd
            _queue_rollback systemctl_restart proftpd
        fi
        changed=1
    fi

    # samba 처리
    local sf; sf="$(_u35_smb_conf)"
    if [[ -f "$sf" ]] && _u35_smb_guest_on; then
        backup_file "$sf"
        # map to guest = never 설정
        set_kv "$sf" 'map to guest' '	map to guest = never'
        # guest ok = yes 라인 주석
        local tmp2="$KISA_TMP_DIR/tmp/u35.smb.$$.$RANDOM"
        mkdir -p "$(dirname "$tmp2")"
        local om2 ou2 og2
        om2=$(stat -c '%a' "$sf" 2>/dev/null || true)
        ou2=$(stat -c '%u' "$sf" 2>/dev/null || true)
        og2=$(stat -c '%g' "$sf" 2>/dev/null || true)
        awk '
            /^[[:space:]]*(guest ok|guest okay)[[:space:]]*=[[:space:]]*yes/i {
                printf "# [KISA U-35] %s\n", $0; next
            }
            { print }
        ' "$sf" > "$tmp2"
        mv -f "$tmp2" "$sf"
        [[ -n "$om2" ]] && chmod "$om2" "$sf" 2>/dev/null || true
        [[ -n "$ou2" && -n "$og2" ]] && chown "$ou2:$og2" "$sf" 2>/dev/null || true
        command -v restorecon >/dev/null 2>&1 && restorecon "$sf" 2>/dev/null || true
        for ssvc in smb nmb; do
            if systemctl is-active "$ssvc" >/dev/null 2>&1; then
                _queue_service_op restart "$ssvc"
                _queue_rollback systemctl_restart "$ssvc"
            fi
        done
        changed=1
    fi

    if (( changed == 0 )); then
        printf '양호 — 익명 접근 이미 제한됨'
        return 0
    fi

    printf '조치 완료 — vsftpd/proftpd/samba 익명 접근 제한 적용'
    return 0
}
