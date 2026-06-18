#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# E-04 (확장): firewalld 허용 port/protocol 추가 (KISA U-01~U-67 범위 밖, 실운영 설정)
#
# 환경변수:
#   FIREWALL_PORTS — 콤마 구분 port/proto (예: "8080/tcp,9090/tcp,53/udp")
#                    빈 값이면 skip
#
# 조치:
#   1) firewalld 활성 여부 확인
#   2) 각 port/proto 를 현재 default zone 에 permanent + runtime 추가
#   3) 이미 추가된 port 는 skip (idempotent)
#   4) port 형식(숫자/tcp|udp|sctp|dccp) 검증
#
# 롤백:
#   zone XML backup_file + reload 로 원복

h_E_04_meta() {
    cat <<'JSON'
{
  "code": "E-04",
  "title": "방화벽 허용 port (확장)",
  "severity": "중",
  "category": "확장 - 방화벽",
  "purpose": "운영에 필요한 사용자 정의 포트(firewalld 내장 service 외) 를 default zone 에 명시적으로 허용. 표준 service 로 매핑 안되는 포트(예: 9090 cockpit, 8080 webapp) 의 통제 경로.",
  "threat": "방화벽에 막힌 포트로 서비스 시작 시 외부 통신 실패 → 운영 장애. 반대로 port 만 열고 제거 누락 시 불필요 노출 위험.",
  "criterion_good": "FIREWALL_PORTS 환경변수와 default zone 의 --list-ports 결과가 일치하는 경우, 또는 FIREWALL_PORTS 미지정 (확장 조치 대상 아님)",
  "criterion_bad": "FIREWALL_PORTS 에 지정한 port/proto 가 default zone 에 허용되지 않은 경우, 또는 형식 오류(<1-65535>/{tcp|udp|sctp|dccp} 위반) 인 경우",
  "method": [
    "systemctl is-active firewalld",
    "firewall-cmd --zone=<zone> --list-ports"
  ],
  "action_method": "FIREWALL_PORTS 의 각 항목 형식 검증 후 default zone 에 permanent+runtime 으로 add-port. 이미 등록된 항목은 idempotent skip.",
  "action_impact": "내부에서만 사용해야 할 포트를 외부에 노출시키면 위험. 가능하면 IP 제한(rich rule, U-28 ALLOWED_HOSTS) 과 병행 적용 권장.",
  "references": [
    "확장 항목 E-04 (KISA 표준 카운트와 분리)"
  ]
}
JSON
}

_e_04_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: 방화벽 허용 port (E-04) — FW_ALLOW_PORTS 일치 검증"
        echo
        echo "## firewalld 서비스 상태"
        echo "is-enabled firewalld: $(systemctl is-enabled firewalld 2>&1)"
        echo "is-active  firewalld: $(systemctl is-active  firewalld 2>&1)"
        echo
        if systemctl is-active firewalld >/dev/null 2>&1 && command -v firewall-cmd >/dev/null 2>&1; then
            local _z; _z=$(firewall-cmd --get-default-zone 2>/dev/null || echo public)
            echo "default-zone: $_z"
            echo
            echo "## firewall-cmd --zone=$_z --list-ports (runtime)"
            firewall-cmd --zone="$_z" --list-ports 2>&1 || true
            echo
            echo "## firewall-cmd --zone=$_z --list-ports --permanent"
            firewall-cmd --zone="$_z" --list-ports --permanent 2>&1 || true
            echo
            echo "## 현재 LISTEN 중인 TCP 포트"
            if command -v ss >/dev/null 2>&1; then
                ss -tlnp 2>/dev/null | head -30 || true
            fi
        else
            echo "(firewalld 비활성)"
        fi
        echo
        echo "## 환경변수: FW_ALLOW_PORTS=${FW_ALLOW_PORTS:-(미설정)}"
    } | _evidence_capture "$label"
}


_e04_firewalld_active() { systemctl is-active firewalld >/dev/null 2>&1; }
_e04_get_zone()         { firewall-cmd --get-default-zone 2>/dev/null || printf 'public'; }

_e04_validate_port() {
    # 형식: <1-65535>/{tcp,udp,sctp,dccp} 또는 range <n>-<m>/{proto}
    local token="$1"
    [[ "$token" =~ ^[0-9]+(-[0-9]+)?/(tcp|udp|sctp|dccp)$ ]]
}

h_E_04_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _e_04_capture_state "$KISA_PHASE"
    fi

    local mode="${FIREWALL_MODE:-}"
    local ports="${FIREWALL_PORTS:-}"

    # FIREWALL_MODE=disable → E-03 가 firewalld 비활성화 처리. 이 항목은 양호 처리
    if [[ "$mode" == "disable" ]]; then
        printf '양호 — FIREWALL_MODE=disable (E-03 에서 firewalld 비활성)'
        return 0
    fi

    if [[ -z "$ports" ]]; then
        printf '양호 — FIREWALL_PORTS 미지정 (확장 조치 대상 아님)'
        return 0
    fi

    if ! command -v firewall-cmd >/dev/null 2>&1; then
        printf '취약 — firewalld 미설치로 FIREWALL_PORTS 적용 불가'
        return 1
    fi
    if ! _e04_firewalld_active; then
        printf '취약 — firewalld 비활성, FIREWALL_PORTS 적용 전 시작 필요'
        return 1
    fi

    local zone; zone="$(_e04_get_zone)"
    local active; active=$(firewall-cmd --zone="$zone" --list-ports 2>/dev/null | tr ' ' '\n' | sort -u)

    local missing="" bad="" t
    IFS=',' read -r -a port_arr <<< "$ports"
    for t in "${port_arr[@]}"; do
        t="${t// /}"; [[ -z "$t" ]] && continue
        if ! _e04_validate_port "$t"; then
            bad="${bad:+$bad,}${t}"; continue
        fi
        if ! printf '%s\n' "$active" | grep -qxF "$t"; then
            missing="${missing:+$missing,}${t}"
        fi
    done

    if [[ -n "$bad" ]]; then
        printf '취약 — FIREWALL_PORTS 형식 오류: %s (올바른 형식 예: 8080/tcp)' "$bad"
        return 1
    fi

    if [[ -z "$missing" ]]; then
        printf '양호 — firewalld zone=%s 에 %s 전부 허용됨' "$zone" "$ports"
        return 0
    fi
    printf '취약 — firewalld zone=%s 에 미허용 port: %s' "$zone" "$missing"
    return 1
}

h_E_04_apply() {
    local ports="${FIREWALL_PORTS:-}"

    if [[ "${1:-}" == "--dry-run" ]]; then
        if [[ -z "$ports" ]]; then
            printf '(dry-run) FIREWALL_PORTS 미지정 — 조치 불필요'
            return 0
        fi
        printf '(dry-run) firewalld 에 port %s 허용 (permanent+runtime) + reload 지연' "$ports"
        return 0
    fi

    if [[ -z "$ports" ]]; then
        printf '해당없음 — FIREWALL_PORTS 미지정, 조치 불필요'
        return 3
    fi

    if ! command -v firewall-cmd >/dev/null 2>&1; then
        printf '조치 실패 — firewalld 미설치로 조치 불가'
        return 1
    fi
    if ! _e04_firewalld_active; then
        log_warn "E-04: firewalld 비활성 — 시작 시도"
        systemctl unmask firewalld 2>/dev/null || true
        systemctl enable --now firewalld 2>/dev/null || true
        if ! _e04_firewalld_active; then
            printf '조치 실패 — firewalld 시작 실패로 조치 불가'
            return 1
        fi
    fi

    local zone; zone="$(_e04_get_zone)"
    local zone_xml="/etc/firewalld/zones/${zone}.xml"
    backup_file "$zone_xml"

    local active; active=$(firewall-cmd --zone="$zone" --list-ports 2>/dev/null | tr ' ' '\n')

    local added=0 skipped=0 invalid="" t
    IFS=',' read -r -a port_arr <<< "$ports"
    for t in "${port_arr[@]}"; do
        t="${t// /}"; [[ -z "$t" ]] && continue
        if ! _e04_validate_port "$t"; then
            invalid="${invalid:+$invalid,}${t}"; continue
        fi
        if printf '%s\n' "$active" | grep -qxF "$t"; then
            (( skipped++ )); continue
        fi
        if firewall-cmd --permanent --zone="$zone" --add-port="$t" >/dev/null 2>&1; then
            firewall-cmd --zone="$zone" --add-port="$t" >/dev/null 2>&1 || true
            (( added++ ))
        else
            log_warn "E-04: $t 추가 실패"
        fi
    done

    if (( added > 0 )); then
        _queue_rollback systemctl_reload firewalld
    fi

    if [[ -n "$invalid" ]]; then
        log_warn "E-04: 형식 오류로 건너뜀 — $invalid"
    fi

    if (( added == 0 && skipped == 0 )); then
        printf '조치 실패 — firewalld port 추가 실패 (무효 입력: %s)' "${invalid:-none}"
        return 1
    fi

    printf '조치 완료 — firewalld zone=%s port 추가=%d, 이미존재=%d%s' \
        "$zone" "$added" "$skipped" \
        "$( [[ -n "$invalid" ]] && printf ', 무효=%s' "$invalid" )"
    return 0
}
