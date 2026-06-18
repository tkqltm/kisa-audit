#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-07: 불필요한 계정 제거 (중요도: 하)
#
# KISA 가이드 원문 (p.31):
#   점검 내용: 시스템 계정 중 불필요한 계정(퇴직, 전직, 휴직 등의 이유로 사용하지 않는
#             계정 및 장기적으로 사용하지 않는 계정 등)이 존재 여부 점검
#   ※ 기본 계정: OS나 Package 설치 시 기본적으로 생성되는 계정(lp, uucp, nuucp 등)
#   ※ 불필요한 기본 계정 제거 시 발생할 업무 영향도를 파악한 후 제거 권고
#
#   => KISA 는 "퇴직·휴직자 계정"을 주 대상으로 하며, OS 기본 계정은 "업무 영향도
#      파악 후" 제거를 권고 (자동 제거 금지). 본 스크립트는 UID>=1000 일반 계정을
#      점검 대상으로 하고, 관리자 그룹 멤버는 제외 (KISA U-08 에서 별도 점검).
#
# 자동 조치 불가 사유:
#   - 어떤 계정이 "불필요"한지는 운영자가 직접 확인해야 함
#   - userdel 잘못 수행 시 서비스 장애, 파일 고아(orphan) 발생 가능
#   - 퇴직자·휴직자 목록은 시스템이 알 수 없음
#   → apply 는 return 2 (manual) 처리
#
# 환경변수 (사이트별 예외):
#   EXEMPT_ACCOUNTS="mysql,postgres,ceph,tibero,oracle,mongodb"
#     → 서비스 운영 계정을 점검 대상에서 제외 (DBMS/애플리케이션 서비스 계정)
#       보통 DBMS 는 UID<1000 시스템 계정으로 동작하나, 일부 배포판/설치 방식에서
#       UID>=1000 으로 생성되므로 false-positive 방지용.
#
# Rocky 8/9/10 공통:
#   - /etc/passwd 에서 UID 1000 이상 일반 사용자 계정 목록 표시
#   - 로그인 가능한 shell 보유 계정 중심으로 안내
#   - 관리자 그룹(wheel 등 SUDOERS_ADMIN_GROUP) 멤버는 U-08 대상 (제외)
#   - EXEMPT_ACCOUNTS 에 명시된 서비스 계정은 제외

h_U_07_meta() {
    cat <<'JSON'
{
  "code": "U-07",
  "title": "불필요한 계정 제거",
  "severity": "하",
  "category": "계정 관리",
  "purpose": "불필요한 계정이 존재하는지 점검하여 관리되지 않은 계정에 의한 침입에 대비하는지 확인하기 위함",
  "threat": "로그인이 가능하고 현재 사용하지 않는 불필요한 계정은 사용 중인 계정보다 상대적으로 관리가 취약하여 공격자의 목표가 되어 계정이 탈취될 수 있는 위험이 존재함(퇴직, 전직, 휴직 등의 사유 발생 시 즉시 권한을 회수하는 것을 권고함)",
  "criterion_good": "불필요한 계정이 존재하지 않는 경우",
  "criterion_bad": "불필요한 계정이 존재하는 경우",
  "action_method": "시스템에 존재하는 계정 확인 후 불필요한 계정 제거하도록 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "시스템 계정 중 불필요한 계정(퇴직, 전직, 휴직 등의 이유로 사용하지 않는 계정 및 장기적으로 사용하지 않는 계정 등)이 존재 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-07 (2026 ver.)"
  ]
}
JSON
}

_u_07_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: 로그인 가능 셸 계정 추출 (시스템 계정/면제 계정 제외)"
        echo
        echo "# 결과: 로그인 가능 일반 계정"
        local _accts
        _accts=$(_u07_regular_accounts 2>/dev/null || true)
        if [[ -z "$_accts" ]]; then
            echo "(없음 — 모든 계정 nologin/false 또는 면제 시스템 계정)"
        else
            printf '%s\n' "$_accts"
        fi
        echo
        echo "# 환경변수: EXEMPT_ACCOUNTS=${EXEMPT_ACCOUNTS:-(미설정)}"
    } | _evidence_capture "$label"
}


_u07_passwd() { printf '/etc/passwd'; }

# 관리자 그룹 멤버 목록 (wheel 그룹의 members 필드 + primary GID=wheel 계정)
_u07_admin_members() {
    local grp="${SUDOERS_ADMIN_GROUP:-wheel}"
    local gid members
    gid=$(getent group "$grp" 2>/dev/null | awk -F: '{print $3}')
    members=$(getent group "$grp" 2>/dev/null | awk -F: '{gsub(/,/," ",$4); print $4}')
    if [[ -n "$gid" ]]; then
        # primary GID 가 관리자 그룹인 계정도 포함
        awk -F: -v g="$gid" '$4==g{print $1}' "$(_u07_passwd)" 2>/dev/null
    fi
    printf '%s\n' $members
}

# EXEMPT_ACCOUNTS 에 포함된 계정인지
_u07_is_exempt() {
    local name="$1"
    [[ -z "${EXEMPT_ACCOUNTS:-}" ]] && return 1
    local IFS=','
    local a
    for a in $EXEMPT_ACCOUNTS; do
        a="${a// /}"
        [[ -z "$a" ]] && continue
        [[ "$name" == "$a" ]] && return 0
    done
    return 1
}

# UID 1000 이상, 로그인 가능 shell 보유, 관리자 그룹 비멤버 = "일반 계정"
_u07_regular_accounts() {
    local admins
    admins=$(_u07_admin_members | sort -u)
    awk -F: '($3>=1000 && $1!="nobody" && $7!="" && $7!="/sbin/nologin" && $7!="/bin/false" && $7!="/usr/sbin/nologin") \
             {print $1 ":" $3 ":" $7}' "$(_u07_passwd)" 2>/dev/null \
      | while IFS=: read -r name uid shell; do
            if printf '%s\n' "$admins" | grep -qxF "$name"; then
                continue
            fi
            if _u07_is_exempt "$name"; then
                continue
            fi
            printf '%s:%s:%s\n' "$name" "$uid" "$shell"
        done
}

h_U_07_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_07_capture_state "$KISA_PHASE"
    fi

    local passwd_f; passwd_f="$(_u07_passwd)"
    if [[ ! -r "$passwd_f" ]]; then
        printf '/etc/passwd 읽기 실패'
        return 2
    fi

    local accounts
    accounts=$(_u07_regular_accounts)

    if [[ -z "$accounts" ]]; then
        printf '양호 — 로그인 가능 일반 계정 없음'
        return 0
    fi

    local cnt
    cnt=$(printf '%s\n' "$accounts" | grep -c '.')
    # 계정 존재 자체를 취약으로 판정 (담당자 확인 필요)
    printf '취약 — 로그인 가능 일반 계정 %s개 (담당자 확인 필요): %s' \
           "$cnt" "$(printf '%s' "$accounts" | awk -F: '{printf "%s ",$1}')"
    return 1
}

h_U_07_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        printf '(dry-run) [MANUAL] 불필요한 계정 목록 확인 후 userdel 수동 수행 필요'
        return 0
    fi

    local accounts
    accounts=$(_u07_regular_accounts)

    if [[ -z "$accounts" ]]; then
        printf '양호 — 이미 로그인 가능 일반 계정 없음, 조치 불필요'
        return 0
    fi

    printf '수동 조치 필요 — 담당자가 다음 계정을 검토하여 불필요한 계정 제거:\n'
    printf '%s\n' "$accounts" | awk -F: '{printf "  계정: %-20s UID: %-6s Shell: %s\n",$1,$2,$3}'
    printf '\n조치 방법:\n'
    printf '  # last <계정명>   -- 최근 로그인 이력 확인\n'
    printf '  # userdel <계정명>           -- 홈 디렉터리 유지\n'
    printf '  # userdel -r <계정명>        -- 홈 디렉터리 함께 삭제\n'
    printf '  ※ 기본 계정(lp, uucp 등) 제거 전 업무 영향도 파악 필요\n'
    return 2
}
