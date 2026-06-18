#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — All rights reserved. Unauthorized modification prohibited.
# KISA Audit - OS detection. Sets OS_FAMILY ∈ {rocky8, rocky9, rocky10}
# Sourced by kisa-audit.sh.

[[ -n "${_KISA_OSDETECT_LOADED:-}" ]] && return 0
_KISA_OSDETECT_LOADED=1

detect_os() {
    local id ver_id id_like pretty
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        id="${ID:-}"
        ver_id="${VERSION_ID:-}"
        id_like="${ID_LIKE:-}"
        pretty="${PRETTY_NAME:-unknown}"
    else
        die "/etc/os-release 을 읽을 수 없습니다. 지원하지 않는 OS."
    fi

    # major version
    local major="${ver_id%%.*}"

    case "$id" in
        rocky)
            case "$major" in
                8)  OS_FAMILY=rocky8  ;;
                9)  OS_FAMILY=rocky9  ;;
                10) OS_FAMILY=rocky10 ;;
                *)  die "지원하지 않는 Rocky Linux 버전: $ver_id (지원: 8, 9, 10)" ;;
            esac
            ;;
        rhel|almalinux|centos)
            case "$major" in
                8)  OS_FAMILY=rocky8;  log_warn "Rocky 외 RHEL 호환 OS ($id $ver_id) 로 감지됨. rocky8 프로파일 적용." ;;
                9)  OS_FAMILY=rocky9;  log_warn "Rocky 외 RHEL 호환 OS ($id $ver_id) 로 감지됨. rocky9 프로파일 적용." ;;
                10) OS_FAMILY=rocky10; log_warn "Rocky 외 RHEL 호환 OS ($id $ver_id) 로 감지됨. rocky10 프로파일 적용." ;;
                *)  die "지원하지 않는 버전: $id $ver_id" ;;
            esac
            ;;
        *)
            die "지원하지 않는 OS: ID=$id VERSION_ID=$ver_id (지원: Rocky/RHEL/AlmaLinux/CentOS 8/9/10)"
            ;;
    esac

    OS_ID="$id"
    OS_MAJOR="$major"
    OS_VERSION="$ver_id"
    OS_PRETTY="$pretty"

    # package manager
    if   command -v dnf >/dev/null 2>&1; then PKG_MGR=dnf
    elif command -v yum >/dev/null 2>&1; then PKG_MGR=yum
    else PKG_MGR=""; fi

    # authselect availability (Rocky 8+ ships it; sanity-check anyway)
    if command -v authselect >/dev/null 2>&1; then
        AUTHSELECT_AVAILABLE=1
    else
        AUTHSELECT_AVAILABLE=0
    fi

    export OS_FAMILY OS_ID OS_MAJOR OS_VERSION OS_PRETTY PKG_MGR AUTHSELECT_AVAILABLE
}
