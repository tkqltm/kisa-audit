#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-09: 계정이 존재하지 않는 GID 금지 (중요도: 하)
#
# KISA 가이드 원문 (p.33):
#   점검 내용: 그룹 설정 파일(/etc/group)에 불필요한 그룹이 존재 여부 점검
#   판단 기준: 양호 - 시스템 관리나 운용에 불필요한 그룹이 제거된 경우
#              취약 - 시스템 관리나 운용에 불필요한 그룹이 존재하는 경우
#   조치 방법: 불필요한 그룹이 존재하는 경우 관리자와 검토하여 제거하도록 설정
#             ※ /etc/group 파일과 /etc/passwd 파일을 비교하여 점검하기를 권고함
#   ※ 해당 그룹 제거 시 그룹 권한으로 존재하는 파일이 존재하는지 확인이 필요하며,
#     사용자가 없는 그룹이더라도 추후 권한 할당을 위해 그룹을 먼저 생성하였을
#     가능성도 존재하므로 확인 필요
#
#   => KISA 는 **특정 그룹명 삭제 목록** 을 제시하지 않음. "멤버 없음 + 관리자 검토" 기준.
#
# 점검 로직:
#   1) /etc/group 각 행에서 members 필드 비어 있고
#   2) /etc/passwd 에서도 해당 GID 를 primary GID 로 사용하는 계정이 없는 그룹 = 후보
#   3) OS rpm 패키지(setup, systemd, cockpit, libvirt 등)가 관리하는 기본 그룹은
#      제거 시 rpm 검증(rpm -Va) 실패 및 서비스 파일 소유권 오류를 유발하므로
#      기본적으로 제외. 단, EXEMPT_* 환경변수로 사이트별 예외 제어 가능.
#
# 자동 조치 불가 사유:
#   - KISA 원문: "관리자와 검토하여 제거" — 자동 삭제 대상 아님
#   - 그룹 소유 파일이 있으면 groupdel 시 파일이 고아 됨 (KISA 원문 경고)
#   - 추후 권한 할당용으로 생성된 그룹일 수 있음 (KISA 원문 경고)
#   → apply 는 return 2 (manual)
#
# KISA U-11 "로그인 불필요 계정 목록" 과의 관계:
#   - U-11 은 games, nobody 등 **계정(account)** 의 shell 을 nologin 으로 변경하는 항목
#   - U-09 는 **그룹(group)** 멤버 유무 점검. games 계정은 nologin 으로, games 그룹은 유지.
#   - 두 항목이 다루는 대상 층이 다름 → games 그룹이 U-09 화이트리스트에 있다고 KISA 위배 아님
#
# 환경변수 (사이트별 예외 제어):
#   EXEMPT_GROUPS="mysql,postgres,ceph,tibero,oracle"
#     → DBMS 등 사이트 고유 서비스 그룹 추가 화이트리스트
#   EXTRA_FLAG_GROUPS="legacy_svc"
#     → 기본 화이트리스트에 있더라도 강제로 "취약 후보"로 flag
#
# Rocky 8/9/10 공통: /etc/group, /etc/gshadow, /etc/passwd 비교

h_U_09_meta() {
    cat <<'JSON'
{
  "code": "U-09",
  "title": "계정이 존재하지 않는 GID 금지",
  "severity": "하",
  "category": "계정 관리",
  "purpose": "시스템에 불필요한 그룹이 존재하는지 점검하여 불필요한 그룹의 소유권으로 설정된 파일의 노출로 인해 발생할 수 있는 위험에 대해 대비를 하기 위함",
  "threat": "계정이 존재하지 않거나 불필요한 그룹이 존재하는 경우, 해당 그룹의 소유로 설정된 파일을 통한 권한 남용 또는 의도치 않은 권한 부여, 보안 감사 및 관리의 어려움 등의 위험이 존재함",
  "criterion_good": "시스템 관리나 운용에 불필요한 그룹이 제거된 경우",
  "criterion_bad": "시스템 관리나 운용에 불필요한 그룹이 존재하는 경우",
  "action_method": "불필요한 그룹이 존재하는 경우 관리자와 검토하여 제거하도록 설정 ※ /etc/group 파일과 /etc/passwd 파일을 비교하여 점검하기를 권고함",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "그룹 설정 파일(/etc/group)에 불필요한 그룹이 존재 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-09 (2026 ver.)"
  ]
}
JSON
}

_u_09_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: 계정이 존재하지 않는 GID(불필요한 그룹) 검출"
        echo
        echo "## /etc/group 파일 정보"
        ls -l /etc/group /etc/gshadow 2>&1 || true
        echo
        echo "## 멤버 없음 + primary GID 미사용 그룹 후보"
        echo "(KISA 기준: /etc/group 의 4번째 필드(members)가 비어있고 /etc/passwd 에서도 GID 미사용)"
        local _grp _gid _members _users
        while IFS=: read -r _grp _ _gid _members; do
            [[ -n "$_members" ]] && continue
            _users=$(awk -F: -v g="$_gid" '($4==g){c++} END{print c+0}' /etc/passwd 2>/dev/null)
            (( _users == 0 )) && printf '  ! gid=%-6s name=%s\n' "$_gid" "$_grp"
        done < /etc/group | head -40
        echo
        echo "## 환경변수: EXEMPT_GROUPS=${EXEMPT_GROUPS:-(미설정)} EXTRA_FLAG_GROUPS=${EXTRA_FLAG_GROUPS:-(미설정)}"
        echo
        echo "## /etc/group 전체 라인 수"
        wc -l /etc/group 2>&1 || true
    } | _evidence_capture "$label"
}


_u09_group_file()  { printf '/etc/group'; }
_u09_passwd_file() { printf '/etc/passwd'; }

# GID 를 기본 그룹으로 사용하는 /etc/passwd 계정 수 반환
_u09_gid_user_count() {
    local gid="$1"
    awk -F: -v g="$gid" '($4==g){c++} END{print c+0}' "$(_u09_passwd_file)" 2>/dev/null
}

# OS rpm 패키지(setup/systemd/...)가 관리하는 "기본 시스템 그룹"
# 근거: rpm -q --whatprovides /etc/group  ->  setup 패키지
#      rpm -ql setup | grep -E 'group|passwd'
#      setup-2.13.7-10.el9 기준 /etc/group 초기값 + systemd/cockpit/libvirt 등이
#      post-install 시 생성하는 그룹
# KISA 판정 기준 "시스템 관리나 운용에 필요한 그룹" 에 해당
_u09_is_default_system_group() {
    local name="$1"
    # 카테고리별 그룹 분류(주석 목적):
    #   A) setup 패키지 기본값 (/usr/share/doc/setup/uidgid 참조)
    #   B) systemd / journald 등 systemd 서비스
    #   C) 공통 시스템 서비스 (dnf/rpm 의존성으로 자동 생성)
    case "$name" in
        root|bin|daemon|sys|adm|tty|disk|lp|mem|kmem|wheel|cdrom|mail|man|\
        dialout|floppy|games|tape|video|ftp|lock|audio|users|nobody|utmp|utempter|\
        input|kvm|render|sgx|clock|\
        systemd-journal|systemd-network|systemd-resolve|\
        systemd-timesync|systemd-coredump|systemd-oom|\
        dbus|polkitd|tss|sshd|ssh_keys|chrony|rpc|rpcuser|nfsnobody|\
        dnsmasq|printadmin|sssd|colord|unbound|clevis|pipewire|avahi|avahi-autoipd|\
        geoclue|gluster|saslauth|pesign|abrt|cockpit-ws|cockpit-wsinstance|\
        setroubleshoot|apache|named|postfix|postdrop|mailnull|smmsp|nginx|\
        slocate|plocate|insights|libstoragemgmt|flatpak|radvd|qemu|libvirt|vdsm|\
        brlapi|tcpdump|rngd|landlock)
            return 0 ;;
    esac

    # 사이트별 예외 그룹 (EXEMPT_GROUPS 환경변수)
    if [[ -n "${EXEMPT_GROUPS:-}" ]]; then
        local IFS=','
        local g
        for g in $EXEMPT_GROUPS; do
            g="${g// /}"
            [[ -z "$g" ]] && continue
            [[ "$name" == "$g" ]] && return 0
        done
    fi

    return 1
}

# EXTRA_FLAG_GROUPS: 기본 화이트리스트에 있어도 강제 flag
_u09_is_force_flagged() {
    local name="$1"
    [[ -z "${EXTRA_FLAG_GROUPS:-}" ]] && return 1
    local IFS=','
    local g
    for g in $EXTRA_FLAG_GROUPS; do
        g="${g// /}"
        [[ -z "$g" ]] && continue
        [[ "$name" == "$g" ]] && return 0
    done
    return 1
}

# 멤버가 없는 그룹 목록 반환 — KISA 판정 대상 후보
_u09_empty_groups() {
    local group_f; group_f="$(_u09_group_file)"
    while IFS=: read -r gname _x gid members; do
        [[ -z "$gname" ]] && continue
        if [[ -z "$members" ]]; then
            local ucount; ucount=$(_u09_gid_user_count "$gid")
            if (( ucount == 0 )); then
                if _u09_is_force_flagged "$gname"; then
                    printf '%s:%s\n' "$gname" "$gid"
                    continue
                fi
                _u09_is_default_system_group "$gname" && continue
                printf '%s:%s\n' "$gname" "$gid"
            fi
        fi
    done < "$group_f" 2>/dev/null
}

h_U_09_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_09_capture_state "$KISA_PHASE"
    fi

    local group_f; group_f="$(_u09_group_file)"
    if [[ ! -r "$group_f" ]]; then
        printf '/etc/group 읽기 실패'
        return 2
    fi

    local empty_groups
    empty_groups=$(_u09_empty_groups)

    if [[ -z "$empty_groups" ]]; then
        printf '양호 — OS 기본 시스템 그룹 외 멤버 없는 불필요 그룹 없음'
        return 0
    fi

    local cnt
    cnt=$(printf '%s\n' "$empty_groups" | grep -c '.')
    printf '취약 — 멤버 없는 비표준 그룹 %s개(담당자 확인 필요): %s' \
           "$cnt" "$(printf '%s' "$empty_groups" | awk -F: '{printf "%s ",$1}')"
    return 1
}

h_U_09_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        printf '(dry-run) [MANUAL] 멤버 없는 그룹 목록 확인 후 groupdel 수동 수행 예정'
        return 0
    fi

    local empty_groups
    empty_groups=$(_u09_empty_groups)

    if [[ -z "$empty_groups" ]]; then
        printf '양호 — 이미 멤버 없는 불필요 그룹 없음, 조치 불필요'
        return 0
    fi

    printf '수동 조치 필요 — 멤버 없는 그룹 목록 검토 후 제거 (KISA 원문: 관리자와 검토하여 제거):\n'
    printf '%s\n' "$empty_groups" | while IFS=: read -r gname gid; do
        [[ -z "$gname" ]] && continue
        local sys_mark=""
        (( gid < 1000 )) && sys_mark=" [시스템그룹-주의]"
        printf '  그룹: %-20s GID: %s%s\n' "$gname" "$gid" "$sys_mark"
    done
    printf '\n조치 방법 (KISA 가이드 p.33 참조):\n'
    printf '  # find / -group <그룹명> 2>/dev/null   -- 그룹 소유 파일 확인(필수)\n'
    printf '  # groupdel <그룹명>                     -- 불필요 그룹 제거\n'
    printf '  ※ 소유 파일 있으면 제거 전 소유권 변경 필요(고아 파일 방지)\n'
    printf '  ※ 추후 권한 할당용으로 먼저 생성된 그룹일 수 있으므로 관리자 확인 필요\n'
    return 2
}
