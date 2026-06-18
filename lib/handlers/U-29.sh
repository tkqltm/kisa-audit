#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-29: hosts.lpd 파일 소유자 및 권한 설정 (중요도: 하)
# KISA 가이드: /etc/hosts.lpd 파일 제거 또는 root 소유·600 이하 권한 설정
#
# 점검 기준:
#   양호: /etc/hosts.lpd 미존재, 또는 소유자 root, 권한 600 이하
#   취약: 파일 존재하며 소유자 root 아님 또는 권한 600 초과
#
# 조치 전략:
#   - 파일 존재 시 backup_file 후 삭제 (Rocky Linux에서 lpd 불필요)
#   - 삭제 실패 시 chown root + chmod 600 으로 fallback
#
# Rocky 8/9/10: /etc/hosts.lpd 기본 미존재, LPD → CUPS 대체

h_U_29_meta() {
    cat <<'JSON'
{
  "code": "U-29",
  "title": "hosts.lpd 파일 소유자 및 권한 설정",
  "severity": "하",
  "category": "파일 및 디렉토리 관리",
  "purpose": "비인가자의 임의적인 /etc/hosts.lpd 변조를 막기 위해 /etc/hosts.lpd 파일 제거 또는 소유자 및 권한 관리하기 위함",
  "threat": "/etc/hosts.lpd 파일의 접근 권한이 적절하지 않을 경우, 비인가자가 /etc/hosts.lpd 파일을 수정하여 허용된 사용자의 서비스를 방해할 수 있으며, 호스트 정보를 획득할 수 있는 위험이 존재함",
  "criterion_good": "/etc/hosts.lpd 파일이 존재하지 않거나, 불가피하게 사용 시 /etc/hosts.lpd 파일의 소유자가 root이고, 권한이 600 이하인 경우",
  "criterion_bad": "/etc/hosts.lpd 파일이 존재하며, 파일의 소유자가 root가 아니거나, 권한이 600 이하가 아닌 경우",
  "action_method": "/etc/hosts.lpd 파일 제거 또는 /etc/hosts.lpd 파일 소유자 및 권한 변경 설정",
  "action_impact": "일반적인 경우 영향 없음",
  "method": [
    "/etc/hosts.lpd 파일의 제거 및 권한 적절성 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-29 (2026 ver.)"
  ]
}
JSON
}

_u_29_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: /etc/hosts.lpd 파일 존재 여부 + 권한"
        echo
        echo "## /etc/hosts.lpd 상태"
        if [[ -e /etc/hosts.lpd ]]; then
            ls -l /etc/hosts.lpd 2>&1 || true
            echo
            echo "## 내용"
            cat /etc/hosts.lpd 2>&1 | head -20 || true
        else
            echo "(/etc/hosts.lpd 없음 - lpd 비사용 환경, 양호)"
        fi
        echo
        echo "## lpd/cups 패키지 + 서비스 상태"
        rpm -q cups lpr 2>&1 | head -5 || true
        echo "is-enabled cups: $(systemctl is-enabled cups 2>&1)"
        echo "is-active  cups: $(systemctl is-active  cups 2>&1)"
    } | _evidence_capture "$label"
}


_u29_target() { printf '/etc/hosts.lpd'; }

h_U_29_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_29_capture_state "$KISA_PHASE"
    fi

    local f; f="$(_u29_target)"

    if [[ ! -e "$f" ]]; then
        printf '양호 — %s 미존재 (lpd 비사용 환경)' "$f"
        return 0
    fi

    local owner perm
    owner=$(stat -c '%U' "$f" 2>/dev/null || true)
    perm=$(stat -c '%a'  "$f" 2>/dev/null || true)

    local bad=0
    [[ "$owner" != "root" ]] && bad=1
    (( 8#${perm:-777} & 8#077 )) && bad=1

    if (( bad == 0 )); then
        printf '양호 — %s 소유자=root, 권한=%s (600 이하)' "$f" "$perm"
        return 0
    fi

    printf '취약 — %s 소유자=%s 권한=%s (root 아님 또는 권한 600 초과)' "$f" "$owner" "$perm"
    return 1
}

h_U_29_apply() {
    local f; f="$(_u29_target)"

    if [[ "${1:-}" == "--dry-run" ]]; then
        if [[ ! -e "$f" ]]; then
            printf '(dry-run) %s 미존재 — 조치 예정 없음' "$f"
        else
            printf '(dry-run) %s backup 후 삭제 예정' "$f"
        fi
        return 0
    fi

    if [[ ! -e "$f" ]]; then
        printf '양호 — 이미 %s 미존재 (조치 불필요)' "$f"
        return 0
    fi

    backup_file "$f"

    if rm -f "$f" 2>/dev/null; then
        printf '조치 완료 — %s 삭제 (backup 보관)' "$f"
        return 0
    fi

    # 삭제 실패 시 권한·소유자 강제 설정
    log_warn "U-29: $f 삭제 실패 — 소유자·권한 조치로 대체"
    chown root "$f" 2>/dev/null || true
    chmod 600  "$f" 2>/dev/null || true

    local owner perm
    owner=$(stat -c '%U' "$f" 2>/dev/null || true)
    perm=$(stat -c '%a'  "$f" 2>/dev/null || true)

    if [[ "$owner" == "root" ]] && (( (8#${perm:-777} & 8#077) == 0 )); then
        printf '조치 완료 — %s 삭제 실패하여 chown root + chmod 600 적용' "$f"
        return 0
    fi

    printf '조치 실패 — %s 삭제·권한조치 모두 실패, 수동 확인 필요' "$f"
    return 1
}
