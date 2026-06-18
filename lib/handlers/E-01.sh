#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# E-01 (확장): SSH 포트 변경 (KISA U-01~U-67 범위 밖, 실운영 설정)
#
# 환경변수:
#   SSH_PORT — 사용할 SSH 포트 (기본 22, 값 없거나 22 면 skip)
#
# 조치:
#   1) /etc/ssh/sshd_config 의 Port 를 새 포트로 설정 (Port 라인 단독 → 기존 22 제거)
#   2) firewalld 에 새 포트 허용 + 기존 22(ssh service / 22/tcp) 제거 (permanent + reload)
#   3) SELinux 활성(enforcing/permissive) 시 semanage port -a -t ssh_port_t -p tcp <PORT>
#   4) sshd 재시작은 세션 끊김 방지로 자동 실행 X — 운영자 수동 안내
#
# ⚠️ 잠김 위험: 기존 22 가 sshd·방화벽 모두에서 제거되어 22 fallback 이 없음.
#    'systemctl restart sshd' 후 새 포트 로그인이 되는지 반드시 확인하고 현재 세션을 유지할 것.
#    문제 시 rollback 으로 sshd_config·방화벽 22 복원 가능.

h_E_01_meta() {
    cat <<'JSON'
{
  "code": "E-01",
  "title": "SSH 포트 변경 (확장)",
  "severity": "중",
  "category": "확장 - 서비스 포트",
  "purpose": "기본 22번 포트를 외부에서 노출하지 않도록 사용자 정의 포트로 이전하여 무차별 대입 공격(brute-force) 표면을 축소.",
  "threat": "기본 포트(22)는 인터넷 스캔/공격 도구의 1순위 표적. 변경하지 않을 경우 자동화된 사전 대입·취약점 스캐닝의 지속적인 노출 위험.",
  "criterion_good": "SSH_PORT 가 미지정(기본 22) 이거나, 지정된 포트가 sshd -T 의 effective Port 와 일치하는 경우",
  "criterion_bad": "SSH_PORT 가 지정되었으나 sshd 에 적용되지 않은 경우, 또는 형식 오류(1-65535 범위 밖) 인 경우",
  "method": [
    "sshd -T | awk 'tolower($1)==\"port\"{print $2}'",
    "환경변수 SSH_PORT 와 비교"
  ],
  "action_method": "Rocky 9/10: /etc/ssh/sshd_config.d/00-kisa-sshport.conf drop-in 생성 (기존 22 유지 + 새 포트 추가). Rocky 8: /etc/ssh/sshd_config 에 Port 라인 추가. SELinux 활성화 시 semanage port -a -t ssh_port_t -p tcp <PORT> 선행. firewalld 활성화 시 firewall-cmd --permanent --add-port=<PORT>/tcp.",
  "action_impact": "관리자가 새 포트로 로그인 가능한지 확인 전엔 기존 22 유지 → 잠금 위험 방지. 확인 후 별도로 22 차단 필요.",
  "references": [
    "확장 항목 E-01 (KISA 표준 카운트와 분리)"
  ]
}
JSON
}

_e_01_capture_state() {
    local label="$1"
    {
        echo "# 점검 명령: SSH 포트 변경 (E-01) — sshd Port + firewalld 허용 일치 검증"
        echo
        echo "## sshd -T effective Port 값"
        if command -v sshd >/dev/null 2>&1; then
            sshd -T 2>/dev/null | grep -i '^port' || echo "(sshd -T 실패)"
        fi
        echo
        echo "## /etc/ssh/sshd_config Port 라인"
        grep -nE '^[[:space:]]*Port[[:space:]]' /etc/ssh/sshd_config 2>/dev/null || echo "(라인 없음, 기본 22)"
        echo
        echo "## /etc/ssh/sshd_config.d/ drop-in Port 라인"
        if [[ -d /etc/ssh/sshd_config.d ]]; then
            grep -rnE '^[[:space:]]*Port[[:space:]]' /etc/ssh/sshd_config.d/ 2>/dev/null || echo "(드롭인 Port 라인 없음)"
        fi
        echo
        echo "## firewalld 활성 zone + 허용 포트"
        if systemctl is-active firewalld >/dev/null 2>&1 && command -v firewall-cmd >/dev/null 2>&1; then
            local _z; _z=$(firewall-cmd --get-default-zone 2>/dev/null || echo public)
            echo "default-zone: $_z"
            echo "## firewall-cmd --zone=$_z --list-ports"
            firewall-cmd --zone="$_z" --list-ports 2>&1 || true
            echo "## firewall-cmd --zone=$_z --list-services"
            firewall-cmd --zone="$_z" --list-services 2>&1 || true
        else
            echo "(firewalld 비활성)"
        fi
        echo
        echo "## sshd 서비스 상태 + 실제 LISTEN 포트"
        echo "is-enabled sshd: $(systemctl is-enabled sshd 2>&1)"
        echo "is-active  sshd: $(systemctl is-active  sshd 2>&1)"
        if command -v ss >/dev/null 2>&1; then
            ss -tlnp 2>/dev/null | awk 'NR==1 || /sshd/' || true
        fi
        echo
        echo "## 환경변수: SSH_PORT=${SSH_PORT:-(미설정, 기본 22)}"
    } | _evidence_capture "$label"
}


_e01_main_conf()   { printf '/etc/ssh/sshd_config'; }
_e01_override()    { printf '/etc/ssh/sshd_config.d/00-kisa-sshport.conf'; }

_e01_has_include() {
    local main; main="$(_e01_main_conf)"
    [[ -r "$main" ]] || return 1
    grep -qE '^[[:space:]]*Include[[:space:]]+.*sshd_config\.d' "$main"
}

_e01_effective_ports() {
    sshd -T 2>/dev/null | awk 'tolower($1)=="port"{print $2}' || true
}

_e01_firewalld_active() {
    systemctl is-active firewalld >/dev/null 2>&1
}

_e01_selinux_active() {
    # 시스템의 실제 SELinux 상태로 판단. audit.conf 의 SELINUX_MODE 와 무관.
    # enforcing/permissive 면 semanage 필수 — 안 하면 sshd 새 포트 바인딩 실패.
    command -v getenforce >/dev/null 2>&1 || return 1
    local m; m="$(getenforce 2>/dev/null || echo Disabled)"
    [[ "$m" == "Enforcing" || "$m" == "Permissive" ]]
}

_e01_validate_port() {
    local p="$1"
    [[ "$p" =~ ^[0-9]+$ ]] || return 1
    (( p >= 1 && p <= 65535 ))
}

h_E_01_check() {
    if [[ -n "${KISA_PHASE:-}" ]]; then
        _e_01_capture_state "$KISA_PHASE"
    fi

    local target="${SSH_PORT:-}"
    local effective; effective="$(_e01_effective_ports)"
    local port_summary; port_summary=$(printf '%s' "$effective" | tr '\n' ',' | sed 's/,$//')

    # SSH_PORT 미지정(빈값) 또는 22 지정 → 포트 유지(변경 안 함).
    # E-01 은 선택적 확장 하드닝이라 "유지"는 정상 → 양호 (meta criterion_good 과 일치).
    if [[ -z "$target" || "$target" == "22" ]]; then
        printf '양호 — SSH_PORT 미지정(빈값=유지), 기본 포트 유지 (effective: %s)' "$port_summary"
        return 0
    fi

    if ! _e01_validate_port "$target"; then
        printf '취약 — SSH_PORT 형식 오류: %s (1-65535 정수)' "$target"
        return 1
    fi

    if printf '%s\n' "$effective" | grep -qxF "$target"; then
        printf '양호 — SSH 포트 %s 적용됨 (sshd -T effective ports: %s)' "$target" "$port_summary"
        return 0
    fi

    printf '취약 — SSH 포트 변경 필요: 현재 effective=[%s], 목표=%s' "${port_summary:-?}" "$target"
    return 1
}

h_E_01_apply() {
    local target="${SSH_PORT:-}"

    if [[ "${1:-}" == "--dry-run" ]]; then
        [[ -z "$target" || "$target" == "22" ]] && { printf '(dry-run) SSH_PORT 미설정 — 조치 불필요'; return 2; }
        _e01_validate_port "$target" || { printf '(dry-run) SSH_PORT=%s 형식 오류 — 조치 중단' "$target"; return 1; }
        printf '(dry-run) sshd_config Port=%s 적용 예정 + SELinux/firewalld 동기화' "$target"
        return 0
    fi

    [[ -z "$target" || "$target" == "22" ]] && { printf '해당없음 — SSH_PORT 미지정/기본 22로 조치 불필요'; return 3; }
    _e01_validate_port "$target" || { printf '조치 실패 — SSH_PORT=%s 형식 오류 (1-65535 정수)' "$target"; return 1; }

    # 이미 적용된 상태면 skip (사용자 정책: 기존 적용분은 건드리지 않음)
    if _e01_effective_ports | grep -qxF "$target"; then
        printf '양호 — 이미 SSH Port=%s 적용됨' "$target"
        return 0
    fi

    local main_f; main_f="$(_e01_main_conf)"
    local ovr;    ovr="$(_e01_override)"
    local use_dropin=0
    if _e01_has_include && [[ -d /etc/ssh/sshd_config.d ]]; then
        local _other_confs
        _other_confs=$(find /etc/ssh/sshd_config.d -maxdepth 1 -name '*.conf' -type f \
                           ! -name '00-kisa-sshport.conf' 2>/dev/null | wc -l)
        (( _other_confs > 0 )) && use_dropin=1
    fi

    local sshd_modified=()
    if (( use_dropin )); then
        backup_file "$ovr"
        sshd_modified+=("$ovr")
        mkdir -p "$(dirname "$ovr")"
        install -m 0600 -o root -g root /dev/null "$ovr"
        printf '# Managed by KISA E-01 (kisa-audit). Do not edit manually.\nPort %s\n' "$target" > "$ovr"
        command -v restorecon >/dev/null 2>&1 && restorecon "$ovr" 2>/dev/null || true
    else
        backup_file "$main_f"
        sshd_modified+=("$main_f")
        set_kv "$main_f" 'Port' "Port ${target}"
    fi

    # 2) SELinux enforcing/permissive 면 ssh_port_t 에 등록
    if _e01_selinux_active; then
        if ! semanage port -l 2>/dev/null | awk '$1=="ssh_port_t"{for(i=3;i<=NF;i++) print $i}' | tr -d ',' | grep -qxF "$target"; then
            semanage port -a -t ssh_port_t -p tcp "$target" 2>/dev/null \
                || semanage port -m -t ssh_port_t -p tcp "$target" 2>/dev/null
            _queue_rollback semanage_port_del "-t ssh_port_t -p tcp $target"
        fi
    fi

    # 3) firewalld 활성화돼있으면 새 포트 허용 + 기존 22(ssh service / 22/tcp) 제거
    if _e01_firewalld_active; then
        firewall-cmd --permanent --add-port="${target}/tcp" >/dev/null 2>&1
        local _had_ssh_svc=0 _had_p22=0
        firewall-cmd --permanent --query-service=ssh  >/dev/null 2>&1 && _had_ssh_svc=1
        firewall-cmd --permanent --query-port=22/tcp   >/dev/null 2>&1 && _had_p22=1
        firewall-cmd --permanent --remove-service=ssh >/dev/null 2>&1
        firewall-cmd --permanent --remove-port=22/tcp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
        # rollback: 새 포트 제거 + 원래 22 허용(ssh service / 22 포트) 복원
        _queue_rollback exec "firewall-cmd --permanent --remove-port=${target}/tcp >/dev/null 2>&1"
        (( _had_ssh_svc )) && _queue_rollback exec "firewall-cmd --permanent --add-service=ssh >/dev/null 2>&1"
        (( _had_p22 ))     && _queue_rollback exec "firewall-cmd --permanent --add-port=22/tcp >/dev/null 2>&1"
    fi

    # 4) sshd_config 문법 검증
    if ! sshd -t 2>/dev/null; then
        local m
        for m in "${sshd_modified[@]}"; do restore_file "$m" || true; done
        printf '조치 실패 — sshd -t 검증 실패로 sshd_config 원복 완료'
        return 1
    fi

    # 5) sshd restart 는 자동 실행 X — SSH 세션 끊김 방지를 위해 운영자 수동 재시작 안내.
    #    rollback 시에도 동일하게 안내만.
    log_warn "E-01: 새 포트 ${target} 적용 + 기존 22 제거(sshd·방화벽). ⚠️ 'systemctl restart sshd' 후 ${target} 로그인 검증 전까지 현재 세션 끊지 말 것 — 22 fallback 없음"

    printf '조치 완료 — SSH Port=%s 적용 + 기존 22 제거 (sshd_config Port=%s 단독 / 방화벽 22 닫음 / SELinux 라벨), systemctl restart sshd 수동 실행 필요' "$target" "$target"
    return 0
}
