#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# E-02 (확장): SELinux 모드 관리 (KISA U-01~U-67 범위 밖, 실운영 설정)
#
# 환경변수:
#   SELINUX_MODE — enforcing | permissive | disabled
#                  빈 값이면 현재 상태 유지(skip)
#
# 조치:
#   1) /etc/selinux/config 의 SELINUX= 라인을 target 값으로 set_kv
#   2) enforcing/permissive 전환: setenforce 로 즉시 적용
#   3) disabled 전환:
#      - RHEL 8 : /etc/selinux/config 만 수정 (리부팅 시 적용)
#      - RHEL 9+: selinux 는 /etc/selinux/config 로만 disable 불가, 커널 파라미터 필요.
#                 grubby --update-kernel=ALL --args="selinux=0" 로 커널 파라미터 추가
#                 ※ 리부팅 전까지 실제로는 enforcing 또는 permissive 상태 유지
#   4) disabled → enforcing/permissive 역전환: 커널 파라미터 제거 + 파일 수정 + 리부팅 필요
#
# 롤백:
#   /etc/selinux/config 복원 + grubby args 복원(추가한 경우 제거)

h_E_02_meta() {
    cat <<'JSON'
{
  "code": "E-02",
  "title": "SELinux 모드 관리 (확장)",
  "severity": "상",
  "category": "확장 - SELinux",
  "purpose": "MAC(Mandatory Access Control) 기반 SELinux 정책으로 권한 상승·서비스 침해 영향 범위를 차단. 운영 정책에 맞게 enforcing/permissive/disabled 모드를 명시적으로 관리.",
  "threat": "SELinux 가 의도와 다르게 disabled 로 운영되면 컨테이너 탈출, 서비스 측 익스플로잇 후 시스템 전체 장악 위험이 확대. 반대로 정책 검토 없이 enforcing 으로 전환 시 운영 중인 서비스가 차단될 수 있음.",
  "criterion_good": "SELINUX_MODE 환경변수와 /etc/selinux/config 의 SELINUX= 값이 일치하고, 런타임(getenforce) 도 일치하는 경우",
  "criterion_bad": "정책상 모드와 실제 구성/런타임 모드가 불일치하거나, 정책상 enforcing 인데 disabled 상태인 경우",
  "method": [
    "getenforce",
    "grep -E '^SELINUX=' /etc/selinux/config",
    "RHEL9+ : grubby --info=ALL | grep selinux=0"
  ],
  "action_method": "/etc/selinux/config 의 SELINUX= 값을 SELINUX_MODE 와 일치하도록 set_kv. enforcing/permissive 전환은 setenforce 로 즉시 적용. disabled 전환 (RHEL 9+) 은 grubby --args=\"selinux=0\" 로 커널 파라미터 추가 후 리부팅 필요.",
  "action_impact": "enforcing 전환 시 일부 서비스가 정책 차단으로 동작 불가할 수 있음 — audit2allow 로 정책 보강 필요. disabled ↔ enforcing 전환은 리부팅 필요.",
  "references": [
    "확장 항목 E-02 (KISA 표준 카운트와 분리)"
  ]
}
JSON
}

_e_02_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령:"
        echo "## getenforce"
        if command -v getenforce >/dev/null 2>&1; then
            getenforce 2>&1 || true
        else
            echo "(getenforce 명령 없음)"
        fi
        echo
        echo "## sestatus"
        if command -v sestatus >/dev/null 2>&1; then
            sestatus 2>&1 || true
        else
            echo "(sestatus 명령 없음)"
        fi
        echo
        echo "## /etc/selinux/config"
        _dump_path "/etc/selinux/config" "^SELINUX="
        echo
        echo "## /proc/cmdline (selinux=0/enforcing=0 부팅 인자 확인)"
        cat /proc/cmdline 2>/dev/null || echo "(읽기 실패)"
    } | _evidence_capture "$label"
}


_e02_conf()       { printf '/etc/selinux/config'; }
_e02_has_selinux(){ [[ -r /etc/selinux/config ]] || return 1; command -v getenforce >/dev/null 2>&1; }
_e02_current()    { getenforce 2>/dev/null | tr '[:upper:]' '[:lower:]' || echo disabled; }
_e02_config_val() {
    grep -E '^[[:space:]]*SELINUX=' "$(_e02_conf)" 2>/dev/null \
        | tail -1 | awk -F= '{gsub(/[[:space:]]/,"",$2); print tolower($2)}'
}
_e02_kernel_has_selinux0() {
    # Check if current booted kernel has selinux=0 argument
    grep -qE '(^|\s)selinux=0(\s|$)' /proc/cmdline 2>/dev/null
}
_e02_grubby_has_selinux0() {
    command -v grubby >/dev/null 2>&1 || return 1
    grubby --info=ALL 2>/dev/null | grep -E '^args=' | grep -qE 'selinux=0'
}

h_E_02_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _e_02_capture_state "$KISA_PHASE"
    fi

    if ! _e02_has_selinux; then
        printf '양호 — SELinux 미설치/미사용 (확장 조치 대상 아님)'
        return 0
    fi

    local target="${SELINUX_MODE:-}"
    local cur; cur="$(_e02_current)"
    local cfg; cfg="$(_e02_config_val)"

    if [[ -z "$target" ]]; then
        printf '양호 — 정책 미지정, 시스템 현재 상태 유지 (getenforce=%s, config=%s)' "$cur" "${cfg:-?}"
        return 0
    fi

    case "$target" in
        enforcing|permissive|disabled) ;;
        *)
            printf '취약 — SELINUX_MODE 값 오류: %s (enforcing|permissive|disabled 중 하나)' "$target"
            return 1
            ;;
    esac

    # disabled 목표 시 RHEL 9+ 는 커널 파라미터 체크 필수
    local maj="${OS_MAJOR:-0}"
    if [[ "$target" == "disabled" ]]; then
        if [[ "$cfg" == "disabled" ]] && (( maj >= 9 )) && ! _e02_grubby_has_selinux0; then
            printf '취약 — 시스템 config=disabled 이나 RHEL %d 는 grubby selinux=0 커널 파라미터 필요' "$maj"
            return 1
        fi
        if [[ "$cfg" == "disabled" ]]; then
            printf '양호 — 시스템 config=disabled (실제 적용은 리부팅 후)'
            return 0
        fi
        printf '취약 — 정책=disabled, 시스템 config=%s / getenforce=%s' "${cfg:-?}" "$cur"
        return 1
    fi

    # enforcing/permissive 목표
    if [[ "$cur" == "$target" && "$cfg" == "$target" ]]; then
        printf '양호 — 시스템 getenforce=%s, config=%s' "$cur" "$cfg"
        return 0
    fi
    printf '취약 — 정책=%s, 시스템 getenforce=%s, config=%s' "$target" "$cur" "${cfg:-?}"
    return 1
}

h_E_02_apply() {
    if [[ "${1:-}" == "--dry-run" ]]; then
        if ! _e02_has_selinux; then
            printf '(dry-run) SELinux 미사용 — 조치 불필요'
            return 0
        fi
        local target="${SELINUX_MODE:-}"
        if [[ -z "$target" ]]; then
            printf '(dry-run) SELINUX_MODE 미지정 — 조치 불필요'
            return 0
        fi
        printf '(dry-run) mode=%s 적용' "$target"
        return 0
    fi

    if ! _e02_has_selinux; then
        printf '해당없음 — SELinux 미사용 (조치 대상 아님)'
        return 3
    fi

    local target="${SELINUX_MODE:-}"
    if [[ -z "$target" ]]; then
        printf '해당없음 — SELINUX_MODE 미지정 (조치 건너뜀)'
        return 3
    fi

    case "$target" in
        enforcing|permissive|disabled) ;;
        *)
            printf '조치 실패 — SELINUX_MODE 값 오류: %s' "$target"
            return 1
            ;;
    esac

    local conf; conf="$(_e02_conf)"
    backup_file "$conf"

    # /etc/selinux/config 수정
    if grep -qE '^[[:space:]]*SELINUX=' "$conf" 2>/dev/null; then
        set_kv "$conf" "SELINUX" "SELINUX=${target}"
    else
        printf '\nSELINUX=%s\n' "$target" >> "$conf"
    fi

    local extra=""
    local maj="${OS_MAJOR:-0}"

    if [[ "$target" == "disabled" ]]; then
        if (( maj >= 9 )) && command -v grubby >/dev/null 2>&1; then
            if ! _e02_grubby_has_selinux0; then
                if grubby --update-kernel=ALL --args="selinux=0" >/dev/null 2>&1; then
                    _queue_rollback grubby_remove_args "selinux=0"
                    extra="; grubby selinux=0 커널 파라미터 추가됨 (모든 부트엔트리)"
                else
                    log_warn "E-02: grubby 커널 파라미터 추가 실패"
                fi
            fi
        fi
        printf '조치 완료 — SELINUX=disabled 적용%s; **리부팅 후 실제 disable 상태가 됩니다**' "$extra"
        return 0
    fi

    # enforcing/permissive: setenforce 즉시 적용
    # (현재 disabled 이면 setenforce 불가 — 커널 파라미터 제거 + 리부팅 필요)
    local cur; cur="$(_e02_current)"
    if [[ "$cur" == "disabled" ]]; then
        # RHEL 9+: grubby selinux=0 제거 시도
        if (( maj >= 9 )) && command -v grubby >/dev/null 2>&1 && _e02_grubby_has_selinux0; then
            if grubby --update-kernel=ALL --remove-args="selinux=0" >/dev/null 2>&1; then
                extra="; grubby selinux=0 제거됨"
                _queue_rollback grubby_add_args "selinux=0"
            fi
        fi
        printf '조치 완료 — SELINUX=%s 파일 적용%s; **현재 disabled 상태 — 리부팅 후 %s 로 전환**' "$target" "$extra" "$target"
        return 0
    fi

    # disabled 아님 → setenforce 로 즉시 전환 가능
    local se_val
    case "$target" in
        enforcing)  se_val=1 ;;
        permissive) se_val=0 ;;
    esac
    if setenforce "$se_val" 2>/dev/null; then
        _queue_rollback setenforce "$( [[ "$cur" == enforcing ]] && echo 1 || echo 0 )"
        printf '조치 완료 — SELINUX=%s 적용 (config + setenforce 즉시)' "$target"
        return 0
    fi
    printf '조치 완료 — config 수정됨 (setenforce %s 실패 — 리부팅 후 적용)' "$target"
    return 0
}
