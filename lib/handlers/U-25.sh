#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-25: world writable 파일 점검 (중요도: 상)
# KISA 가이드: world writable 일반 파일 탐지 및 디렉터리 sticky bit 미설정 탐지
#
# 점검 기준:
#   양호: world writable 파일 미존재 또는 운영상 필요성 인지
#   취약: world writable 파일 존재하며 이유 미인지
#
# 조치 전략:
#   - 일반 파일(type f): 상위 10개만 리포트, manual (운영 영향 가능성)
#   - world writable 디렉터리 중 sticky bit 미설정: 자동으로 chmod +t 적용
#   - 시스템 디렉터리(/proc /sys /dev /run /sys/kernel) 제외
#
# Rocky 8/9/10 공통

h_U_25_meta() {
    cat <<'JSON'
{
  "code": "U-25",
  "title": "world writable 파일 점검",
  "severity": "상",
  "category": "파일 및 디렉토리 관리",
  "purpose": "world writable 파일을 이용한 시스템 접근 및 악의적인 코드 실행을 방지하기 위함",
  "threat": "시스템 파일과 같은 중요 파일에 world writable이 적용될 경우, 일반 사용자 및 비인가자가 해당 파일을 임의로 수정, 제거할 위험이 존재함",
  "criterion_good": "world writable 파일이 존재하지 않거나, 존재 시 설정 이유를 인지하고 있는 경우",
  "criterion_bad": "world writable 파일이 존재하나 설정 이유를 인지하지 못하고 있는 경우",
  "action_method": "world writable 파일 존재 여부를 확인하고 불필요한 경우 제거하도록 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "불필요한 world writable 파일 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-25 (2026 ver.)"
  ]
}
JSON
}

_u_25_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령:"
        echo "##  find / -type f -perm -002 -xdev (시스템 경로 제외)"
        echo "##  find / -type d -perm -002 ! -perm -1000 -xdev (sticky 미설정 ww 디렉터리)"
        echo
        echo "## world-writable 일반 파일 (최대 50건)"
        local _files _fcnt
        _files=$(_u25_find_ww_files 2>/dev/null || true)
        _fcnt=0
        [[ -n "$_files" ]] && _fcnt=$(printf '%s\n' "$_files" | wc -l | tr -d ' ')
        if (( _fcnt == 0 )); then
            echo "(없음)"
        else
            printf '총 %d건\n' "$_fcnt"
            printf '%s\n' "$_files" | head -50
            (( _fcnt > 50 )) && echo "... (${_fcnt}건 중 50건 표시)"
        fi
        echo
        echo "## sticky 미설정 world-writable 디렉터리 (최대 50건)"
        local _dirs _dcnt
        _dirs=$(_u25_find_ww_dirs_no_sticky 2>/dev/null || true)
        _dcnt=0
        [[ -n "$_dirs" ]] && _dcnt=$(printf '%s\n' "$_dirs" | wc -l | tr -d ' ')
        if (( _dcnt == 0 )); then
            echo "(없음)"
        else
            printf '총 %d건\n' "$_dcnt"
            printf '%s\n' "$_dirs" | head -50
            (( _dcnt > 50 )) && echo "... (${_dcnt}건 중 50건 표시)"
        fi
    } | _evidence_capture "$label"
}


# 제외 경로 (find -prune 용): 공통 비-호스트 경로(컨테이너/factory/snap 등) +
# 런타임 가상 파일시스템(/proc,/sys,/dev,/run). nameref 로 배열 채움.
_u25_prune() {
    local -n _o="$1"
    _kisa_build_prune_expr _o
    _o+=( -o -path /proc -o -path /sys -o -path /dev -o -path /run )
}

_u25_find_ww_files() {
    # world-writable 일반 파일 (비-호스트·시스템 경로 제외, xdev)
    local -a _p=(); _u25_prune _p
    find / \( "${_p[@]}" \) -prune -o \
        -type f -perm -002 -xdev -print 2>/dev/null
}

_u25_find_ww_dirs_no_sticky() {
    # world-writable 디렉터리 중 sticky bit 미설정
    local -a _p=(); _u25_prune _p
    find / \( "${_p[@]}" \) -prune -o \
        -type d -perm -002 ! -perm -1000 -xdev -print 2>/dev/null
}

h_U_25_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_25_capture_state "$KISA_PHASE"
    fi

    local ww_files
    ww_files=$(_u25_find_ww_files)
    local ww_dirs
    ww_dirs=$(_u25_find_ww_dirs_no_sticky)

    local fcount=0 dcount=0
    [[ -n "$ww_files" ]] && fcount=$(printf '%s\n' "$ww_files" | wc -l | tr -d ' ')
    [[ -n "$ww_dirs" ]]  && dcount=$(printf '%s\n' "$ww_dirs"  | wc -l | tr -d ' ')

    if (( fcount == 0 && dcount == 0 )); then
        printf '양호 — world-writable 파일·디렉터리 없음'
        return 0
    fi

    printf '취약 — world-writable 파일 %d개 / sticky 미설정 디렉터리 %d개 (목록은 아래 evidence 참조)' \
        "$fcount" "$dcount"
    return 1
}

h_U_25_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        printf '(dry-run) world-writable 파일은 수동 조치; sticky-bit 없는 디렉터리는 chmod +t 예정'
        return 0
    fi

    # 1) 일반 파일: manual 리포트 (상위 10개)
    local ww_files
    ww_files=$(_u25_find_ww_files)
    local fcount=0
    [[ -n "$ww_files" ]] && fcount=$(printf '%s\n' "$ww_files" | wc -l | tr -d ' ')

    if (( fcount > 0 )); then
        # 상세 목록은 evidence 영역(_u_25_capture_state)에 기록됨 — 콘솔엔 요약만.
        log_warn "U-25: world-writable 일반 파일 ${fcount}개 — 목록은 report.html evidence 참조, 'chmod o-w' 또는 삭제 여부 관리자 결정 필요"
    fi

    # 2) sticky bit 미설정 디렉터리: 자동 조치
    local ww_dirs
    ww_dirs=$(_u25_find_ww_dirs_no_sticky)
    local fixed=0

    if [[ -n "$ww_dirs" ]]; then
        while IFS= read -r d; do
            [[ -z "$d" ]] && continue
            if chmod +t "$d" 2>/dev/null; then
                (( fixed++ ))
                # rollback: chmod -t 로 원복
                _queue_rollback "exec" "chmod -t $(printf '%q' "$d")"
            fi
        done <<< "$ww_dirs"
    fi

    if (( fcount > 0 && fixed == 0 )); then
        printf '수동 조치 필요 — world-writable 파일 %d개\n조치: 각 파일 `chmod o-w` 또는 삭제 여부 검토. 목록은 아래 evidence 참조.' "$fcount"
        return 2
    fi

    if (( fcount > 0 )); then
        printf '일부 조치 완료 — sticky bit 디렉터리 %d개 자동 조치(chmod +t); world-writable 파일 %d개는 수동 조치 필요\n조치: 파일 목록은 아래 evidence 참조, `chmod o-w` 또는 삭제 검토.' \
            "$fixed" "$fcount"
        return 2
    fi

    printf '조치 완료 — sticky bit 미설정 디렉터리 %d개 chmod +t (world-writable 파일 없음)' "$fixed"
    return 0
}
