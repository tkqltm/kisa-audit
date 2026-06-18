#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# U-28: 접속 IP 및 포트 제한 (중요도: 상)
# KISA 가이드: 허용할 호스트에 대한 IP 및 포트 제한 설정 여부 점검·조치
#
# 점검 기준:
#   양호: 특정 IP/포트 허용 정책 설정됨
#   취약: 접속 제한 정책 미설정
#
# 환경변수:
#   ALLOWED_HOSTS — 쉼표 구분 CIDR/IP 목록 (예: "192.168.1.0/24,10.0.0.5")
#                   비어 있으면 apply 시 manual 반환
#
# OS 분기 전략:
#   Rocky 8  : TCP Wrapper (/etc/hosts.allow, /etc/hosts.deny) 지원.
#              libwrap/tcp_wrappers 패키지 설치 여부 확인 후 사용.
#              firewalld 도 사용 가능.
#   Rocky 9/10: tcp_wrappers 제거됨. firewalld 기반 rich rule 조치.
#
# 조치 전략:
#   Rocky 8 + TCP wrappers 설치: hosts.deny ALL:ALL + hosts.allow 설정
#   그 외: firewalld rich rule 추가 (SSH 기본)
#   변경 후 firewall-cmd --reload 는 _queue_service_op reload firewalld 로 지연
#
# Rocky 8/9/10: firewalld 기본 방화벽

h_U_28_meta() {
    cat <<'JSON'
{
  "code": "U-28",
  "title": "접속 IP 및 포트 제한",
  "severity": "상",
  "category": "파일 및 디렉토리 관리",
  "purpose": "허용한 호스트만 서비스를 사용하게 하여 서비스 취약점을 이용한 외부자 공격을 방지하기 위함",
  "threat": "허용할 호스트에 대한 IP 및 포트 제한이 적용되지 않을 경우, Telnet, FTP 같은 보안에 취약한 네트워크 서비스를 통하여 불법적인 접근 및 시스템 침해사고가 발생할 수 있는 위험이 존재함",
  "criterion_good": "접속을 허용할 특정 호스트에 대한 IP주소 및 포트 제한을 설정한 경우",
  "criterion_bad": "접속을 허용할 특정 호스트에 대한 IP주소 및 포트 제한을 설정하지 않은 경우",
  "action_method": "OS에 기본으로 제공하는 방화벽 애플리케이션이나 TCP Wrapper와 같은 호스트별 서비스 제한 애플리케이션을 사용하여 접근 허용 IP 등록 설정",
  "action_impact": "허용되지 않은 IP는 서비스 사용이 불가함",
  "method": [
    "허용할 호스트에 대한 접속 IP주소 제한 및 포트 제한 설정 여부 점검"
  ],
  "references": [
    "KISA 가이드 U-28 (2026 ver.)"
  ]
}
JSON
}

_u_28_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: 접속 IP 및 포트 제한 (firewalld zone rule + TCP Wrapper)"
        echo
        echo "## firewalld 서비스 상태"
        echo "is-enabled firewalld: $(systemctl is-enabled firewalld 2>&1)"
        echo "is-active  firewalld: $(systemctl is-active  firewalld 2>&1)"
        echo
        echo "## firewalld 기본/활성 zone"
        if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active firewalld >/dev/null 2>&1; then
            echo "default-zone: $(firewall-cmd --get-default-zone 2>&1)"
            echo "active-zones:"
            firewall-cmd --get-active-zones 2>&1 || true
            echo
            echo "## 기본 zone 정책 (firewall-cmd --zone=<default> --list-all)"
            local _z
            _z=$(firewall-cmd --get-default-zone 2>/dev/null || echo public)
            firewall-cmd --zone="$_z" --list-all 2>&1 || true
        else
            echo "(firewalld inactive 또는 firewall-cmd 없음)"
        fi
        echo
        echo "## TCP Wrapper - /etc/hosts.allow (주석 제외 라인)"
        if [[ -f /etc/hosts.allow ]]; then
            grep -nvE '^[[:space:]]*(#|$)' /etc/hosts.allow 2>/dev/null || echo "(활성 규칙 없음)"
        else
            echo "(/etc/hosts.allow 없음)"
        fi
        echo
        echo "## TCP Wrapper - /etc/hosts.deny (주석 제외 라인)"
        if [[ -f /etc/hosts.deny ]]; then
            grep -nvE '^[[:space:]]*(#|$)' /etc/hosts.deny 2>/dev/null || echo "(활성 규칙 없음)"
        else
            echo "(/etc/hosts.deny 없음)"
        fi
        echo
        echo "## tcp_wrappers 패키지 (Rocky 8 only)"
        rpm -q tcp_wrappers tcp_wrappers-libs 2>&1 || true
        echo
        echo "## 환경변수: ALLOWED_HOSTS=${ALLOWED_HOSTS:-(미설정)}"
        echo "## 환경변수: FIREWALL_SERVICES=${FIREWALL_SERVICES:-(미설정)}"
        echo "## 환경변수: FIREWALL_PORTS=${FIREWALL_PORTS:-(미설정)}"
    } | _evidence_capture "$label"
}


_u28_firewalld_active() {
    systemctl is-active firewalld >/dev/null 2>&1
}

_u28_get_zone() {
    firewall-cmd --get-default-zone 2>/dev/null || printf 'public'
}

# TCP Wrapper 사용 가능 여부: Rocky 8 에서 libwrap 기반 서비스가 있으면 true
_u28_tcpwrap_available() {
    # tcp_wrappers 패키지 또는 /etc/hosts.allow 파일이 존재하는 경우
    rpm -q tcp_wrappers >/dev/null 2>&1 \
        || rpm -q tcp_wrappers-libs >/dev/null 2>&1 \
        || [[ -f /etc/hosts.allow ]]
}

# 해당 IP에 대한 firewalld rich rule이 이미 있는지 확인
_u28_rule_exists() {
    local ip="$1" zone="$2"
    firewall-cmd --zone="$zone" --list-rich-rules 2>/dev/null \
        | grep -qF "source address=\"${ip}\""
}

h_U_28_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _u_28_capture_state "$KISA_PHASE"
    fi

    local fam="${OS_FAMILY:-}"

    # Rocky 8: TCP Wrapper 또는 firewalld 중 하나라도 설정되면 양호
    if [[ "$fam" == "rocky8" ]]; then
        # TCP Wrapper 설정 확인 (hosts.allow 비주석 항목)
        if [[ -f /etc/hosts.allow ]] && grep -qvE '^[[:space:]]*(#|$)' /etc/hosts.allow 2>/dev/null; then
            local cnt
            cnt=$(grep -cvE '^[[:space:]]*(#|$)' /etc/hosts.allow 2>/dev/null || true)
            printf '양호 — Rocky 8 TCP Wrapper hosts.allow 설정 %d개 존재' "$cnt"
            return 0
        fi
    fi

    # Rocky 8/9/10 공통: firewalld 확인
    # 방화벽 자체가 없으면 "접속 제한 정책 미설정" = 취약
    if ! command -v firewall-cmd >/dev/null 2>&1; then
        if [[ "$fam" == "rocky8" ]]; then
            printf '취약 — firewalld 미설치, TCP Wrapper 설정 없음'
        else
            printf '취약 — firewalld 미설치로 접속 제한 정책 미설정'
        fi
        return 1
    fi

    if ! _u28_firewalld_active; then
        printf '취약 — firewalld 비활성 상태로 접속 제한 정책 미적용'
        return 1
    fi

    local zone; zone="$(_u28_get_zone)"
    local rich_rules
    rich_rules=$(firewall-cmd --zone="$zone" --list-rich-rules 2>/dev/null)

    if printf '%s\n' "$rich_rules" | grep -qE 'source address='; then
        local cnt
        cnt=$(printf '%s\n' "$rich_rules" | grep -c 'source address=' || true)
        printf '양호 — firewalld zone=%s source rich rule %d개 설정됨' "$zone" "$cnt"
        return 0
    fi

    printf '취약 — firewalld zone=%s 접속 제한 정책 미설정' "$zone"
    return 1
}

h_U_28_apply() {
    local hosts="${ALLOWED_HOSTS:-}"
    local fam="${OS_FAMILY:-}"

    if [[ "${1:-}" == "--dry-run" ]]; then
        if [[ -z "$hosts" ]]; then
            printf '(dry-run) ALLOWED_HOSTS 미설정 — 적용 불가, 수동 조치 필요 (manual)'
        elif [[ "$fam" == "rocky8" ]] && _u28_tcpwrap_available; then
            printf '(dry-run) Rocky 8 TCP Wrapper hosts.deny ALL:ALL + hosts.allow SSHD:%s 설정 예정' "$hosts"
        else
            printf '(dry-run) firewalld rich rule 추가 예정 (ALLOWED_HOSTS=%s) + reload 지연' "$hosts"
        fi
        return 0
    fi

    # ALLOWED_HOSTS 미설정 → manual
    if [[ -z "$hosts" ]]; then
        log_warn "U-28: ALLOWED_HOSTS 미설정"
        log_warn "  audit.conf 의 ALLOWED_HOSTS 에 허용할 IP/CIDR 을 쉼표로 구분해 입력 후 재실행."
        log_warn "  예) ALLOWED_HOSTS=\"192.168.1.0/24,10.0.0.5\""
        log_warn "  설정 없이 자동 조치 시 관리자 접속 차단 위험 있음."
        if [[ "$fam" != "rocky8" ]]; then
            log_warn "  Rocky 9/10: tcp_wrappers 제거됨. firewalld rich rule 사용 권고."
        fi
        printf '수동 조치 필요 — ALLOWED_HOSTS 미설정 (관리자 잠김 방지)\n조치: audit.conf 에 ALLOWED_HOSTS 로 허용 IP/CIDR 지정 후 재실행'
        return 2
    fi

    # Rocky 8 + TCP Wrapper 경로
    if [[ "$fam" == "rocky8" ]] && _u28_tcpwrap_available; then
        local deny_f=/etc/hosts.deny
        local allow_f=/etc/hosts.allow

        backup_file "$deny_f"
        backup_file "$allow_f"

        # hosts.deny: ALL:ALL 설정 (없으면 추가)
        if ! grep -qE '^[[:space:]]*ALL[[:space:]]*:[[:space:]]*ALL' "$deny_f" 2>/dev/null; then
            printf '\n# [KISA U-28] 기본 차단\nALL:ALL\n' >> "$deny_f"
        fi

        # hosts.allow: sshd 허용 IP 추가
        IFS=',' read -r -a host_arr <<< "$hosts"
        local added=0
        for ip in "${host_arr[@]}"; do
            ip="${ip// /}"
            [[ -z "$ip" ]] && continue
            if ! grep -qF "sshd : ${ip}" "$allow_f" 2>/dev/null; then
                printf '# [KISA U-28]\nsshd : %s\n' "$ip" >> "$allow_f"
                (( added++ ))
            fi
        done

        printf '조치 완료 — Rocky 8 TCP Wrapper hosts.deny ALL:ALL + hosts.allow sshd %d개 IP 추가' "$added"
        return 0
    fi

    # firewalld 경로 (Rocky 8 TCP wrappers 없는 경우 포함, Rocky 9/10)
    if ! command -v firewall-cmd >/dev/null 2>&1; then
        printf '조치 실패 — firewalld 미설치'
        return 1
    fi

    if ! _u28_firewalld_active; then
        log_warn "U-28: firewalld 비활성 — 시작 시도"
        systemctl unmask firewalld 2>/dev/null || true
        systemctl enable --now firewalld 2>/dev/null || true
        if ! _u28_firewalld_active; then
            printf '조치 실패 — firewalld 시작 실패'
            return 1
        fi
    fi

    local zone; zone="$(_u28_get_zone)"
    local added=0 skipped=0

    # rollback 을 위해 zone XML 백업 (추가 전에).
    # firewall-cmd --permanent 가 /etc/firewalld/zones/<zone>.xml 를 수정/생성하므로
    # 이를 백업하면 rollback 시 XML 원복 + reload 로 runtime 동기화 가능.
    local zone_xml="/etc/firewalld/zones/${zone}.xml"
    backup_file "$zone_xml"

    IFS=',' read -r -a host_arr <<< "$hosts"
    for ip in "${host_arr[@]}"; do
        ip="${ip// /}"
        [[ -z "$ip" ]] && continue

        if _u28_rule_exists "$ip" "$zone"; then
            (( skipped++ ))
            continue
        fi

        local rule="rule family=\"ipv4\" source address=\"${ip}\" service name=\"ssh\" accept"
        # 1) persistent 저장
        if ! firewall-cmd --permanent --zone="$zone" --add-rich-rule="$rule" 2>/dev/null; then
            log_warn "U-28: $ip 에 대한 rich rule(permanent) 추가 실패"
            continue
        fi
        # 2) runtime 즉시 적용 (allow rule 은 기존 접속 끊지 않음)
        firewall-cmd --zone="$zone" --add-rich-rule="$rule" >/dev/null 2>&1 || true
        (( added++ ))
    done

    if (( added == 0 && skipped > 0 )); then
        printf '양호 — 이미 firewalld zone=%s rich rule 설정됨 (%d개 존재, idempotent)' "$zone" "$skipped"
        return 0
    fi

    if (( added > 0 )); then
        # rollback 시 permanent 원복 후 reload 로 runtime 동기화
        _queue_rollback systemctl_reload firewalld
        printf '조치 완료 — firewalld zone=%s rich rule %d개 추가 (runtime+permanent, skip %d)' \
            "$zone" "$added" "$skipped"
        return 0
    fi

    printf '조치 실패 — rich rule 추가 실패, 수동 확인 필요'
    return 1
}
