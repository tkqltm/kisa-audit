#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-12: 세션 종료 시간 설정 (중요도: 하)
# KISA 가이드: TMOUT=600(10분) 이하 설정 — /etc/profile
#
# Rocky 8/9/10 공통 전략:
#   - /etc/profile.d/kisa-tmout.sh drop-in 파일로 TMOUT 설정
#     (Rocky 8/9/10 모두 /etc/profile 이 /etc/profile.d/*.sh 를 source 함)
#   - drop-in 방식이 /etc/profile 직접 수정보다 안전하고 관리 용이
#   - csh 사용자를 위해 /etc/csh.cshrc 도 추가 확인
#   - readonly TMOUT 으로 사용자가 해제 못 하도록 고정
#
# 롤백 전략:
#   - backup_file /etc/profile.d/kisa-tmout.sh (ABSENT 마커 사용)
#   - atomic_write 로 생성

h_U_12_meta() {
    cat <<'JSON'
{
  "code": "U-12",
  "title": "세션 종료 시간 설정",
  "severity": "하",
  "category": "계정 관리",
  "purpose": "사용자의 고의 또는 실수로 시스템에 계정이 접속된 상태로 방치됨을 차단하기 위함",
  "threat": "Session timeout 값이 설정되지 않을 경우, 유휴 시간 내 비인가자가 시스템에 접근하여 불필요한 내부 정보를 노출할 위험이 존재함",
  "criterion_good": "Session Timeout이 600초(10분) 이하로 설정된 경우",
  "criterion_bad": "Session Timeout이 600초(10분) 이하로 설정되지 않은 경우",
  "action_method": "600초(10분) 동안 입력이 없는 경우 접속된 Session을 끊도록 설정",
  "action_impact": "모니터링 용도일 경우 세션 타임 설정 시 모니터링 업무가 불가할 수 있으므로 예외 처리 필요",
  "method": [
    "사용자 쉘에 대한 환경설정 파일에서 Session Timeout 설정 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-12 (2026 ver.)"
  ]
}
JSON
}

_u_12_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: 세션 타임아웃(TMOUT) 설정 (KISA 기준 ≤ 600초)"
        echo
        echo "## /etc/profile + /etc/profile.d/*.sh + /etc/bashrc + /etc/csh.* 에서 TMOUT 라인 grep"
        grep -rnE '^[[:space:]]*(readonly[[:space:]]+)?TMOUT=' \
            /etc/profile /etc/profile.d/ /etc/bashrc /etc/csh.cshrc /etc/csh.login 2>/dev/null \
            || echo "(TMOUT 설정 라인 없음)"
        echo
        echo "## 유효 TMOUT 값"
        local _eff; _eff="$(_u12_effective_tmout 2>/dev/null)"
        echo "effective TMOUT = ${_eff:-0} 초 (0 = 미설정)"
        echo
        echo "## 환경변수: SESSION_TIMEOUT=${SESSION_TIMEOUT:-(미설정 — 기본 600)}"
    } | _evidence_capture "$label"
}


_u12_profile_drop() { printf '/etc/profile.d/kisa-tmout.sh'; }
_u12_profile()      { printf '/etc/profile'; }
_u12_csh_login()    { printf '/etc/csh.login'; }
_u12_csh_cshrc()    { printf '/etc/csh.cshrc'; }

# /etc/profile 또는 /etc/profile.d/*.sh 에서 유효 TMOUT 값 반환
_u12_effective_tmout() {
    local v=""
    # drop-in 먼저 확인
    local drop; drop="$(_u12_profile_drop)"
    if [[ -f "$drop" ]]; then
        v=$(grep -E '^[[:space:]]*(readonly[[:space:]]+)?TMOUT=' "$drop" 2>/dev/null \
            | grep -oE '[0-9]+' | head -1)
    fi
    if [[ -z "$v" ]]; then
        # /etc/profile.d/ 전체 스캔
        v=$(grep -rE '^[[:space:]]*(readonly[[:space:]]+)?TMOUT=' /etc/profile.d/ 2>/dev/null \
            | grep -oE '[0-9]+' | sort -n | head -1)
    fi
    if [[ -z "$v" ]]; then
        # /etc/profile 직접 확인
        v=$(grep -E '^[[:space:]]*(readonly[[:space:]]+)?TMOUT=' "$(_u12_profile)" 2>/dev/null \
            | grep -oE '[0-9]+' | head -1)
    fi
    printf '%s' "${v:-0}"
}

h_U_12_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_12_capture_state "$KISA_PHASE"
    fi

    local timeout="${SESSION_TIMEOUT:-600}"
    local cur; cur="$(_u12_effective_tmout)"

    if [[ "$cur" == "0" ]] || [[ -z "$cur" ]]; then
        printf '취약 — TMOUT 미설정(세션 타임아웃 없음)'
        return 1
    fi

    if (( cur <= timeout )); then
        printf '양호 — TMOUT=%s초 설정됨(기준≤%s초)' "$cur" "$timeout"
        return 0
    fi

    printf '취약 — TMOUT=%s초로 기준 초과(기준≤%s초)' "$cur" "$timeout"
    return 1
}

h_U_12_apply() {
    local timeout="${SESSION_TIMEOUT:-600}"

    if [[ "${1:-}" == "--dry-run" ]]; then
        printf '(dry-run) TMOUT=%s 적용 예정(/etc/profile.d/kisa-tmout.sh)' "$timeout"
        return 0
    fi

    local cur; cur="$(_u12_effective_tmout)"
    if [[ "$cur" != "0" ]] && (( cur <= timeout )); then
        printf '양호 — 이미 TMOUT=%s초 설정됨, 조치 불필요' "$cur"
        return 0
    fi

    local drop; drop="$(_u12_profile_drop)"
    backup_file "$drop"

    atomic_write "$drop" 0644 root root <<EOF
# Managed by KISA U-12 (kisa-audit). Do not edit manually.
TMOUT=${timeout}
readonly TMOUT
export TMOUT
EOF

    # 검증
    local new_val; new_val="$(_u12_effective_tmout)"
    if [[ "$new_val" == "$timeout" ]] || (( new_val <= timeout && new_val > 0 )); then
        printf '조치 완료 — TMOUT=%s 설정(/etc/profile.d/kisa-tmout.sh)' "$timeout"
        return 0
    else
        restore_file "$drop"
        printf '조치 실패 — TMOUT 설정 검증 실패, 원복 완료'
        return 1
    fi
}
