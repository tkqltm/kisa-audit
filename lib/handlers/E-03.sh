#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# E-03 (확장): firewalld 허용 서비스 추가 (KISA U-01~U-67 범위 밖, 실운영 설정)
#
# 환경변수:
#   FIREWALL_SERVICES — 콤마 구분 service 이름 (예: "ssh,https,cockpit")
#                        빈 값이면 skip. firewalld 내장 service 만 허용.
#
# 조치:
#   1) firewalld 활성 여부 확인 (미활성이면 manual)
#   2) 각 service 가 firewalld 에 정의되어 있는지 확인 (--get-services)
#   3) 현재 default zone 에 permanent + runtime 으로 추가
#   4) 이미 추가된 service 는 skip (idempotent)
#
# 롤백:
#   zone XML backup_file + reload 로 원복

h_E_03_meta() {
    cat <<'JSON'
{
  "code": "E-03",
  "title": "방화벽 허용 service (확장)",
  "severity": "중",
  "category": "확장 - 방화벽",
  "purpose": "운영에 필요한 firewalld 내장 service 만 명시적으로 허용하여 default-deny 정책으로 외부 접근 통제.",
  "threat": "방화벽 미설정·과허용 시 불필요한 서비스 포트가 외부에 노출되어 서비스 측 취약점 익스플로잇 표면 확대.",
  "criterion_good": "FIREWALL_SERVICES 환경변수와 default zone 의 --list-services 결과가 일치하는 경우, 또는 FIREWALL_SERVICES 미지정 (확장 조치 대상 아님)",
  "criterion_bad": "FIREWALL_SERVICES 에 명시한 service 가 default zone 에서 허용되지 않은 경우, 또는 firewalld 미실행 상태에서 FIREWALL_SERVICES 가 지정된 경우",
  "method": [
    "systemctl is-active firewalld",
    "firewall-cmd --get-default-zone",
    "firewall-cmd --zone=<zone> --list-services"
  ],
  "action_method": "각 service 가 firewalld 내장(--get-services) 에 정의되어 있는지 확인 후 default zone 에 permanent+runtime 으로 추가. 이미 추가된 service 는 idempotent skip.",
  "action_impact": "외부에서 접근 중인 서비스가 누락되면 통신 단절 위험 — 적용 전 서비스 목록 검토 필수.",
  "references": [
    "확장 항목 E-03 (KISA 표준 카운트와 분리)"
  ]
}
JSON
}

_e_03_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: 방화벽 허용 service (E-03) — FW_ALLOW_SERVICES 일치 검증"
        echo
        echo "## firewalld 서비스 상태"
        echo "is-enabled firewalld: $(systemctl is-enabled firewalld 2>&1)"
        echo "is-active  firewalld: $(systemctl is-active  firewalld 2>&1)"
        echo
        echo "## firewall-cmd default-zone + 활성 zone"
        if systemctl is-active firewalld >/dev/null 2>&1 && command -v firewall-cmd >/dev/null 2>&1; then
            firewall-cmd --get-default-zone 2>&1 || true
            firewall-cmd --get-active-zones 2>&1 || true
            echo
            local _z; _z=$(firewall-cmd --get-default-zone 2>/dev/null || echo public)
            echo "## firewall-cmd --zone=$_z --list-services (현재 허용된 서비스)"
            firewall-cmd --zone="$_z" --list-services 2>&1 || true
            echo
            echo "## firewall-cmd --zone=$_z --list-services --permanent"
            firewall-cmd --zone="$_z" --list-services --permanent 2>&1 || true
        else
            echo "(firewalld 비활성)"
        fi
        echo
        echo "## 환경변수: FW_ALLOW_SERVICES=${FW_ALLOW_SERVICES:-(미설정)}"
    } | _evidence_capture "$label"
}


_e03_firewalld_active() { systemctl is-active firewalld >/dev/null 2>&1; }
_e03_get_zone()         { firewall-cmd --get-default-zone 2>/dev/null || printf 'public'; }

h_E_03_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _e_03_capture_state "$KISA_PHASE"
    fi

    local mode="${FIREWALL_MODE:-}"
    local services="${FIREWALL_SERVICES:-}"

    # FIREWALL_MODE=disable → firewalld 정지 + disable + mask 후 즉시 양호 (services 무관)
    if [[ "$mode" == "disable" ]]; then
        if ! command -v firewall-cmd >/dev/null 2>&1; then
            printf '양호 — firewalld 미설치 (FIREWALL_MODE=disable)'
            return 0
        fi
        if _e03_firewalld_active; then
            systemctl disable --now firewalld 2>/dev/null || true
            systemctl mask firewalld 2>/dev/null || true
        fi
        printf '양호 — FIREWALL_MODE=disable (firewalld stop+disable+mask 처리)'
        return 0
    fi

    # FIREWALL_MODE 빈값(=유지) → FIREWALL_SERVICES 도 빈값이면 양호
    if [[ -z "$services" ]]; then
        printf '양호 — FIREWALL_SERVICES 미지정 (확장 조치 대상 아님)'
        return 0
    fi

    if ! command -v firewall-cmd >/dev/null 2>&1; then
        printf '취약 — firewalld 미설치로 FIREWALL_SERVICES 적용 불가'
        return 1
    fi
    if ! _e03_firewalld_active; then
        printf '취약 — firewalld 비활성, FIREWALL_SERVICES 적용 전 시작 필요'
        return 1
    fi

    local zone; zone="$(_e03_get_zone)"
    local active; active=$(firewall-cmd --zone="$zone" --list-services 2>/dev/null | tr ' ' '\n' | sort -u)
    local missing="" s
    IFS=',' read -r -a svc_arr <<< "$services"
    for s in "${svc_arr[@]}"; do
        s="${s// /}"; [[ -z "$s" ]] && continue
        if ! printf '%s\n' "$active" | grep -qxF "$s"; then
            missing="${missing:+$missing,}${s}"
        fi
    done

    if [[ -z "$missing" ]]; then
        printf '양호 — firewalld zone=%s 에 %s 전부 허용됨' "$zone" "$services"
        return 0
    fi
    printf '취약 — firewalld zone=%s 에 미허용 service: %s' "$zone" "$missing"
    return 1
}

h_E_03_apply() {
    local mode="${FIREWALL_MODE:-}"
    local services="${FIREWALL_SERVICES:-}"

    if [[ "${1:-}" == "--dry-run" ]]; then
        if [[ "$mode" == "disable" ]]; then
            printf '(dry-run) firewalld stop + disable + mask 예정 (FIREWALL_MODE=disable)'
            return 0
        fi
        if [[ -z "$services" ]]; then
            printf '(dry-run) FIREWALL_SERVICES 미지정 — 조치 불필요'
            return 0
        fi
        printf '(dry-run) firewalld 에 service %s 허용 (permanent+runtime) + reload 지연' "$services"
        return 0
    fi

    # FIREWALL_MODE=disable → firewalld stop+disable+mask
    if [[ "$mode" == "disable" ]]; then
        if ! command -v firewall-cmd >/dev/null 2>&1; then
            printf '양호 — 이미 firewalld 미설치 (disable 상태)'
            return 0
        fi
        if _e03_firewalld_active; then
            log_warn "E-03: FIREWALL_MODE=disable — firewalld stop+disable+mask 실행"
            systemctl disable --now firewalld 2>/dev/null || true
            systemctl mask firewalld 2>/dev/null || true
            _queue_rollback exec "systemctl unmask firewalld 2>/dev/null; systemctl enable --now firewalld 2>/dev/null"
            printf '조치 완료 — firewalld stop+disable+mask 처리 (외부 방화벽/보안장비 운용 환경)'
            return 0
        fi
        printf '양호 — 이미 firewalld 비활성'
        return 0
    fi

    if [[ -z "$services" ]]; then
        printf '해당없음 — FIREWALL_SERVICES 미지정으로 조치 불필요'
        return 3
    fi

    if ! command -v firewall-cmd >/dev/null 2>&1; then
        printf '조치 실패 — firewalld 미설치로 조치 불가'
        return 1
    fi
    if ! _e03_firewalld_active; then
        log_warn "E-03: firewalld 비활성 — 시작 시도"
        systemctl unmask firewalld 2>/dev/null || true
        systemctl enable --now firewalld 2>/dev/null || true
        if ! _e03_firewalld_active; then
            printf '조치 실패 — firewalld 시작 실패로 조치 불가'
            return 1
        fi
    fi

    local zone; zone="$(_e03_get_zone)"
    local zone_xml="/etc/firewalld/zones/${zone}.xml"
    backup_file "$zone_xml"

    local defined; defined=$(firewall-cmd --get-services 2>/dev/null | tr ' ' '\n')
    local active;  active=$(firewall-cmd --zone="$zone" --list-services 2>/dev/null | tr ' ' '\n')

    local added=0 skipped=0 invalid=""
    IFS=',' read -r -a svc_arr <<< "$services"
    local s
    for s in "${svc_arr[@]}"; do
        s="${s// /}"; [[ -z "$s" ]] && continue
        if ! printf '%s\n' "$defined" | grep -qxF "$s"; then
            invalid="${invalid:+$invalid,}${s}"
            continue
        fi
        if printf '%s\n' "$active" | grep -qxF "$s"; then
            (( skipped++ )); continue
        fi
        if firewall-cmd --permanent --zone="$zone" --add-service="$s" >/dev/null 2>&1; then
            firewall-cmd --zone="$zone" --add-service="$s" >/dev/null 2>&1 || true
            (( added++ ))
        else
            log_warn "E-03: $s 추가 실패"
        fi
    done

    if [[ -n "$invalid" ]]; then
        log_warn "E-03: firewalld 에 정의되지 않은 service — $invalid"
    fi

    if (( added > 0 )); then
        _queue_rollback systemctl_reload firewalld
    fi

    if (( added == 0 )) && [[ -n "$invalid" ]]; then
        printf '조치 실패 — firewalld service 추가 실패 (무효 service: %s)' "$invalid"
        return 1
    fi

    printf '조치 완료 — firewalld zone=%s service 추가=%d, 이미존재=%d%s' \
        "$zone" "$added" "$skipped" \
        "$( [[ -n "$invalid" ]] && printf ', 무효=%s' "$invalid" )"
    return 0
}
