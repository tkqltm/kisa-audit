#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-26: /dev에 존재하지 않는 device 파일 점검 (중요도: 상)
# KISA 가이드: /dev 디렉터리 내 일반 파일(type f) 존재 여부 점검
#
# 점검 기준:
#   양호: /dev 내 일반 파일 미존재
#   취약: /dev 내 일반 파일 존재 (rootkit 위장 파일 가능성)
#
# 제외 경로:
#   /dev/shm  — tmpfs 공유 메모리 파일 (프로세스 간 IPC 용도, 정상)
#   /dev/mqueue — POSIX 메시지 큐
#
# 조치 전략:
#   - 파일 목록 리포트 후 manual (악성 파일 포렌식 보존 필요)
#   - 자동 삭제는 운영 영향 가능성 있어 manual return
#
# Rocky 8/9/10: devtmpfs 마운트, 일반 파일 존재 시 매우 이례적

h_U_26_meta() {
    cat <<'JSON'
{
  "code": "U-26",
  "title": "/dev에 존재하지 않는 device 파일 점검",
  "severity": "상",
  "category": "파일 및 디렉토리 관리",
  "purpose": "허용한 호스트만 서비스를 사용하게 하여 서비스 취약점을 이용한 외부자 공격을 방지하기 위함",
  "threat": "공격자는 rootkit 설정 파일들을 서버 관리자가 쉽게 발견하지 못하도록 /dev 디렉터리에 device 파일인 것처럼 위장하는 수법을 사용하는 위험이 존재함",
  "criterion_good": "/dev 디렉터리에 대한 파일 점검 후 존재하지 않는 device 파일을 제거한 경우",
  "criterion_bad": "/dev 디렉터리에 대한 파일 미점검 또는 존재하지 않는 device 파일을 방치한 경우",
  "action_method": "major, minor number를 가지지 않는 device 파일 제거하도록 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "허용할 호스트에 대한 접속 IP주소 제한 및 포트 제한 설정 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-26 (2026 ver.)"
  ]
}
JSON
}

_u_26_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: find /dev -type f (정상 디바이스 파일 외 일반 파일 검출)"
        echo
        echo "## /dev 내 일반 파일 (shm/mqueue 제외)"
        local _files
        _files=$(_u26_find_plain_files 2>/dev/null || true)
        if [[ -z "$_files" ]]; then
            echo "(없음 — 양호)"
        else
            printf '%s\n' "$_files" | head -50
            echo
            echo "### 상세 ls -l (최대 30건)"
            local _f
            while IFS= read -r _f; do
                [[ -z "$_f" ]] && continue
                ls -l "$_f" 2>&1
            done <<< "$(printf '%s\n' "$_files" | head -30)"
        fi
        echo
        echo "## 정상 메모리 파일시스템 (참고)"
        ls -ld /dev/shm /dev/mqueue 2>&1 || true
    } | _evidence_capture "$label"
}


_u26_find_plain_files() {
    # /dev 내 일반 파일 중 /dev/shm, /dev/mqueue 제외
    find /dev \
        \( -path /dev/shm -o -path /dev/mqueue \) -prune -o \
        -type f -print 2>/dev/null
}

h_U_26_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_26_capture_state "$KISA_PHASE"
    fi

    if [[ ! -d /dev ]]; then
        printf '해당없음 — /dev 디렉터리 없음'
        return 3
    fi

    local found
    found=$(_u26_find_plain_files)

    if [[ -z "$found" ]]; then
        printf '양호 — /dev 내 일반 파일 없음'
        return 0
    fi

    local cnt
    cnt=$(printf '%s\n' "$found" | wc -l | tr -d ' ')
    local first
    first=$(printf '%s\n' "$found" | head -1)
    printf '취약 — /dev 내 일반 파일 %d개 발견 (예: %s)' "$cnt" "$first"
    return 1
}

h_U_26_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        printf '(dry-run) /dev 내 일반 파일 목록 출력 후 수동 조치 안내 (manual)'
        return 0
    fi

    local found
    found=$(_u26_find_plain_files)

    if [[ -z "$found" ]]; then
        printf '양호 — 이미 /dev 내 일반 파일 없음 (조치 불필요)'
        return 0
    fi

    local cnt
    cnt=$(printf '%s\n' "$found" | wc -l | tr -d ' ')

    # 상세 목록(ls -la)은 evidence 영역(_u_26_capture_state)에 기록됨 — 콘솔엔 요약만.
    log_warn "U-26: /dev 내 일반 파일 ${cnt}개 발견(rootkit 위장 가능성) — 목록은 report.html evidence 참조, 포렌식 보존 후 삭제"

    printf '수동 조치 필요 — /dev 내 일반 파일 %d개 (rootkit 위장 가능성)\n조치: 포렌식 보존 후 삭제. 전체 목록은 아래 evidence 참조.' "$cnt"
    return 2
}
