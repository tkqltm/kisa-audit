#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# U-15: 파일 및 디렉터리 소유자 설정 (중요도: 상)
# 카테고리: 파일 및 디렉토리 관리
#
# 점검 내용: 소유자가 존재하지 않는 파일 및 디렉터리의 존재 여부 점검
# 판단 기준:
#   양호: 소유자가 존재하지 않는 파일 및 디렉터리가 없는 경우
#   취약: 소유자가 존재하지 않는 파일 및 디렉터리가 있는 경우
#
# 조치 전략:
#   - find / \( -nouser -o -nogroup \) -xdev 로 전체 파일시스템 탐색 (-xdev: 마운트 경계 미통과)
#   - 취약 발견 시 최대 10건 샘플만 출력, 전체 목록을 $KISA_TMP_DIR/u15_noowner.txt 에 저장
#   - apply: manual(return 2) — 소유자 없는 파일의 처리(삭제·소유자 변경)는 운영 영향도 있어 자동 조치 불가
#   - 관리자가 목록 확인 후 직접 chown 또는 rm 으로 처리
#
# 롤백 전략:
#   - 자동 조치 없음 → 롤백 불필요
#
# Rocky 8/9/10 특이사항:
#   - -xdev 로 /proc, /sys 등 가상 파일시스템 제외
#   - /var/lib/docker 등 컨테이너 관련 경로에 숫자 UID 파일 존재 가능 → 컨텍스트 확인 필요

h_U_15_meta() {
    cat <<'JSON'
{
  "code": "U-15",
  "title": "파일 및 디렉터리 소유자 설정",
  "severity": "상",
  "category": "파일 및 디렉토리 관리",
  "purpose": "소유자가 존재하지 않는 파일 및 디렉터리를 제거 또는 관리하여 임의의 사용자가 해당 파일을 열람, 수정하는 행위를 사전에 차단하기 위함",
  "threat": "소유자가 존재하지 않는 파일의 UID와 동일한 값으로 특정 계정의 UID를 변경하면 해당 파일의 소유자가 되어 모든 작업이 가능한 위험이 존재함",
  "criterion_good": "소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않는 경우",
  "criterion_bad": "소유자가 존재하지 않는 파일 및 디렉터리가 존재하는 경우",
  "action_method": "소유자가 존재하지 않는 파일 및 디렉터리 제거 또는 소유자 변경 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "소유자가 존재하지 않는 파일 및 디렉터리의 존재 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-15 (2026 ver.)"
  ]
}
JSON
}

# 소유자/그룹 없는 파일 스캔 — 가상fs·컨테이너 이미지 레이어·factory 등 비-호스트 경로 제외
# (rootless 컨테이너 overlay 파일은 호스트에서 nouser 로 보일 수 있어 오탐 → 제외).
_u15_scan() {
    local -a _p=(); _kisa_build_prune_expr _p
    find / -xdev \( "${_p[@]}" \) -prune -o \( -nouser -o -nogroup \) -ls 2>/dev/null
}

_u_15_capture_state() {
    local label="$1"
    local report; report="$(_u15_report_path)"
    mkdir -p "$(dirname "$report")" 2>/dev/null || true
    # 한 번만 스캔하여 보고서 파일에 저장 (check 가 재사용)
    _u15_scan > "$report" || true

    local _cnt
    _cnt=$(wc -l < "$report" 2>/dev/null || printf '0')
    _cnt="${_cnt//[[:space:]]/}"
    {
        echo "# 점검 명령: find / \\( -nouser -o -nogroup \\) -xdev -ls (가상 fs 제외, 마운트 경계 내)"
        echo
        if [[ "$_cnt" -eq 0 ]]; then
            echo "# 결과: 소유자 없는 파일·디렉터리 없음 (양호)"
        else
            echo "# 결과: 소유자 없는 파일·디렉터리 ${_cnt}건 발견 (취약)"
            echo
            echo "## 전체 목록 (find -ls 형식, 최대 200건)"
            head -200 "$report"
            local _excess=$(( _cnt - 200 ))
            (( _excess > 0 )) && echo "... (${_excess}건 추가 있음 — 전체는 ${report})"
        fi
    } | _evidence_capture "$label"
}


_u15_report_path() {
    [[ -n "${KISA_TMP_DIR:-}" ]] || { echo "KISA_TMP_DIR 미설정" >&2; return 1; }
    printf '%s/u15_noowner.txt' "$KISA_TMP_DIR"
}

h_U_15_check() {
    local report; report="$(_u15_report_path)"
    mkdir -p "$(dirname "$report")" 2>/dev/null || true

    if [[ -n "${KISA_PHASE:-}" ]]; then
        # capture_state 가 find 실행 + 보고서 저장을 모두 수행
        _u_15_capture_state "$KISA_PHASE"
    else
        # KISA_PHASE 없을 때만 직접 스캔
        _u15_scan > "$report" || true
    fi

    local count
    count=$(wc -l < "$report" 2>/dev/null || printf '0')
    count="${count//[[:space:]]/}"

    if [[ "$count" -eq 0 ]]; then
        printf '양호 — 소유자 없는 파일·디렉터리 없음'
        return 0
    fi

    local sample
    sample=$(head -5 "$report" | awk '{print $NF}' | tr '\n' ' ')
    printf '취약 — 소유자 없는 파일·디렉터리 %s건 발견 (샘플: %s) — 전체 목록: %s' \
        "$count" "$sample" "$report"
    return 1
}

h_U_15_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        local report; report="$(_u15_report_path)"
        if [[ -f "$report" ]] && [[ -s "$report" ]]; then
            local count; count=$(wc -l < "$report" 2>/dev/null || printf '0')
            count="${count//[[:space:]]/}"
            printf '(dry-run) 수동 조치 필요 — 소유자 없는 파일 %s건 (chown 또는 rm); 전체 목록: %s' \
                "$count" "$report"
        else
            printf '(dry-run) 양호 — 소유자 없는 파일 없음, 조치 불필요'
        fi
        return 0
    fi

    # 자동 조치 불가 항목 — manual 반환
    local report; report="$(_u15_report_path)"
    local count=0
    [[ -f "$report" ]] && count=$(wc -l < "$report" 2>/dev/null || printf '0')
    count="${count//[[:space:]]/}"

    if [[ "$count" -eq 0 ]]; then
        printf '양호 — 이미 소유자 없는 파일 없음, 조치 불필요'
        return 0
    fi

    printf '수동 조치 필요 — 소유자 없는 파일 %s건. ' "$count"
    printf '전체 목록 확인: cat %s | 각 파일에 대해 아래 조치 수행: ' "$report"
    printf '[불필요 파일] rm <path>  [사용 중 파일] chown <owner>:<group> <path>'
    return 2
}
