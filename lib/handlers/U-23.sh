#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-23: SUID, SGID, Sticky bit 설정 파일 점검 (중요도: 상)
# KISA 가이드: root 소유 SUID/SGID 파일 중 시스템 필수 목록 외 불필요한 것 탐지
#
# 점검 기준:
#   양호: 시스템 필수 목록(화이트리스트) 외 SUID/SGID 설정 파일 없음
#   취약: 화이트리스트 외 SUID/SGID 파일 존재
#
# 조치 전략:
#   - 자동 chmod -s 는 운영 영향이 크므로 수행하지 않음
#   - 화이트리스트(SUID_SGID_WHITELIST 파일 또는 내장 기본값) 기반으로 목록 분류
#   - 화이트리스트 외 파일은 목록 출력 후 return 2 (수동 조치 권고)
#
# Rocky 8/9/10 공통: find -xdev 로 마운트 포인트 경계 제한

h_U_23_meta() {
    cat <<'JSON'
{
  "code": "U-23",
  "title": "SUID, SGID, Sticky bit 설정 파일 점검",
  "severity": "상",
  "category": "파일 및 디렉토리 관리",
  "purpose": "불필요한 SUID, SGID, Sticky bit 설정 제거로 악의적인 사용자의 권한 상승을 방지하기 위함",
  "threat": "SUID, SGID, Sticky bit 설정이 적절하지 않을 경우, SUID, SGID, Sticky bit가 설정된 파일로 특정 명령어를 실행하여 root 권한 획득이 가능한 위험이 존재함",
  "criterion_good": "주요 실행 파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있지 않은 경우",
  "criterion_bad": "주요 실행 파일의 권한에 SUID와 SGID에 대한 설정이 부여된 경우",
  "action_method": "- 불필요한 SUID, SGID 권한 또는 해당 파일 제거하도록 설정 - 애플리케이션에서 생성한 파일이나 사용자가 임의로 생성한 파일 등 의심스럽거나 특이한 파일에 SUID 권한이 부여된 경우 제거하도록 설정",
  "action_impact": "SUID, SGID, Sticky bit 설정 파일 제거 시, OS 및 응용프로그램 등 서비스 정상 작동 확인 필요",
  "method": [
    "불필요하거나 악의적인 파일에 SUID, SGID, Sticky bit 설정 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-23 (2026 ver.)"
  ]
}
JSON
}

_u_23_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: SUID/SGID 비인가 파일 검출 (호스트 FS 한정 — 컨테이너/factory 등 제외)"
        echo
        echo "## 화이트리스트 외 SUID/SGID 파일 (수동 조치 대상 — chmod -s 권장 명령 포함)"
        local _n=0 _f
        while IFS= read -r _f; do
            [[ -z "$_f" ]] && continue
            printf "%-48s  조치: chmod -s '%s'\n" "$_f" "$_f"
            _n=$((_n+1))
        done < <(_u23_non_wl_files | sort -u)
        (( _n == 0 )) && echo "(없음 — 화이트리스트 외 SUID/SGID 파일 없음)"
        echo
        echo "## 전체 root 소유 SUID/SGID 파일 (화이트리스트 포함, 참고용)"
        _u23_scan 2>/dev/null | sort -u | head -100
    } | _evidence_capture "$label"
}


# 시스템 필수 SUID/SGID 화이트리스트 (Rocky 8/9/10 기준)
# 근거: 3대 Rocky 8.10/9.7/10.1 기본 설치 후 실제 SUID 파일 목록 기반
_u23_whitelist() {
    cat <<'EOF'
/usr/bin/at
/usr/bin/chage
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/crontab
/usr/bin/gpasswd
/usr/bin/locate
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/plocate
/usr/bin/su
/usr/bin/sudo
/usr/bin/umount
/usr/bin/write
/usr/sbin/grub2-set-bootflag
/usr/sbin/pam_timestamp_check
/usr/sbin/unix_chkpwd
/usr/sbin/userhelper
/usr/sbin/usernetctl
/usr/libexec/cockpit-session
/usr/libexec/dbus-1/dbus-daemon-launch-helper
/usr/libexec/openssh/ssh-keysign
/usr/libexec/sssd/krb5_child
/usr/libexec/sssd/ldap_child
/usr/libexec/sssd/proxy_child
/usr/libexec/sssd/selinux_child
/usr/libexec/utempter/utempter
/usr/lib/polkit-1/polkit-agent-helper-1
EOF
}

_u23_scan() {
    # KISA 가이드: find / -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev
    # 비-호스트 경로(컨테이너 이미지 레이어·/usr/share/factory 템플릿·snap 등) 및
    # kisa-audit 자기 트리는 제외 (호스트 실행 벡터 아님 + 조치 시 원본 손상).
    # backup_file 이 만든 *.kisa.bak 백업은 SUID 비트 보존되므로 검출 대상 제외.
    local -a _prune=()
    _kisa_build_prune_expr _prune
    find / -xdev \
        \( "${_prune[@]}" \) -prune -o \
        -user root -type f \( -perm -04000 -o -perm -02000 -o -perm -01000 \) \
        ! -name '*.kisa.bak' ! -name '*.kisa.bak.absent' \
        -print 2>/dev/null
}

_u23_build_wl_arr() {
    # 외부 파일 지정 시 사용, 없으면 내장 화이트리스트
    if [[ -n "${SUID_SGID_WHITELIST:-}" && -f "${SUID_SGID_WHITELIST}" ]]; then
        cat "${SUID_SGID_WHITELIST}"
    else
        _u23_whitelist
    fi
}

_u23_non_wl_files() {
    local -a wl_arr=()
    while IFS= read -r wl; do
        [[ -n "$wl" ]] && wl_arr+=("$wl")
    done < <(_u23_build_wl_arr)

    local f
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        local in_wl=0
        local w
        for w in "${wl_arr[@]}"; do
            [[ "$f" == "$w" ]] && { in_wl=1; break; }
        done
        (( in_wl )) || printf '%s\n' "$f"
    done < <(_u23_scan)
}

h_U_23_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_23_capture_state "$KISA_PHASE"
    fi

    local found
    found=$(_u23_scan)

    if [[ -z "$found" ]]; then
        printf '시스템에 SUID/SGID 파일 없음'
        return 0
    fi

    local non_wl=()
    while IFS= read -r f; do
        non_wl+=("$f")
    done < <(_u23_non_wl_files)

    if [[ ${#non_wl[@]} -eq 0 ]]; then
        local total
        total=$(printf '%s\n' "$found" | wc -l | tr -d ' ')
        printf '양호 — 화이트리스트 외 SUID/SGID 파일 없음 (시스템 필수 %s개만 존재)' "$total"
        return 0
    fi

    printf '취약 — 화이트리스트 외 SUID/SGID 파일 %d개 (목록은 아래 evidence 참조)' \
        "${#non_wl[@]}"
    return 1
}

h_U_23_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        local cnt
        cnt=$(printf '%s\n' "$(_u23_non_wl_files)" | grep -c . || true)
        printf '(dry-run) 화이트리스트 외 SUID/SGID 파일 %d개 — 수동 조치 안내 예정 (자동 chmod -s 안 함)' "$cnt"
        return 0
    fi

    local non_wl=()
    while IFS= read -r f; do
        non_wl+=("$f")
    done < <(_u23_non_wl_files)

    if [[ ${#non_wl[@]} -eq 0 ]]; then
        printf '양호 — 화이트리스트 외 SUID/SGID 파일 없음 (조치 불필요)'
        return 0
    fi

    # 자동 chmod -s 는 운영 영향(관련 서비스 중단)이 크므로 수동 조치 권고.
    # 상세 목록·권장 명령은 evidence 영역(_u_23_capture_state)에 기록됨.
    log_warn "U-23: 화이트리스트 외 SUID/SGID 파일 ${#non_wl[@]}개 — 목록은 report.html evidence 참조, 검토 후 'chmod -s <파일>' 수동 제거"

    printf '수동 조치 필요 — 화이트리스트 외 SUID/SGID 파일 %d개\n조치: 각 파일 검토 후 `chmod -s <파일>` 로 제거 (서비스 영향 확인). 전체 목록은 아래 evidence 참조.' \
        "${#non_wl[@]}"
    return 2
}
