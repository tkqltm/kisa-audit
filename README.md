<div align="center">

# 🛡️ kisa-audit

**KISA 주요정보통신기반시설 Unix 서버 취약점 점검 · 자동 조치 도구**

*Automated security audit & remediation tool for KISA Critical Infrastructure Unix/Linux servers*

[![Version](https://img.shields.io/badge/version-1.0.0-blue?style=flat-square)](./VERSION)
[![License](https://img.shields.io/badge/license-Proprietary-red?style=flat-square)](./LICENSE)
[![Platform](https://img.shields.io/badge/platform-Rocky%20Linux%20%7C%20RHEL%20%7C%20CentOS-informational?style=flat-square)](https://rockylinux.org/)
[![Shell](https://img.shields.io/badge/shell-bash-green?style=flat-square)](https://www.gnu.org/software/bash/)
[![Checks](https://img.shields.io/badge/checks-U--01~U--67%20%2B%20E--01~E--04-orange?style=flat-square)](#-점검-항목)

[한국어](#한국어) · [English](#english)

</div>

---

## 한국어

### 📌 개요

`kisa-audit`은 **KISA(한국인터넷진흥원) 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세 가이드**를 기준으로,  
Rocky Linux / RHEL / CentOS 서버의 보안 취약점을 **자동으로 점검하고 조치**하는 Bash 기반 도구입니다.

- **U-01 ~ U-67** : KISA 표준 Unix 서버 취약점 71개 항목 전체 커버
- **E-01 ~ E-04** : SSH 포트 변경, SELinux, 방화벽 등 확장 조치 항목
- 단일 서버 자가 실행 또는 **다수 서버 일괄 배포·점검** 모두 지원
- 점검 결과를 **HTML / JSON / DOCX** 보고서로 자동 생성

---

### ✨ 주요 기능

| 기능 | 설명 |
|------|------|
| 🔍 **점검 (check)** | 시스템 변경 없이 취약점만 스캔 |
| 🔧 **자동 조치 (apply)** | 취약 항목 자동 수정, 조치 전 `.kisa.bak` 백업 |
| ↩️ **롤백 (rollback)** | `*.kisa.bak` 전수 스캔 후 원본 자동 복구 |
| 📊 **보고서 생성** | HTML · JSON · DOCX 형식 자동 생성 |
| 🚀 **일괄 배포** | `deploy.sh`로 다수 서버 동시 배포·점검·보고서 수집 |
| 🔒 **무결성 검증** | SHA-256 매니페스트로 핸들러 변조 탐지 |
| 🎯 **선택적 실행** | `--only`, `--skip` 으로 특정 항목만 실행 |

---

### 🚀 빠른 시작

#### 단일 서버 (로컬 실행)

```bash
# 1. 릴리스 패키지 다운로드 후 압축 해제
tar -xzf kisa-audit-1.0.0.tar.gz
cd kisa-audit/

# 2. 설정 파일 편집 (필요 시)
vi config/audit.conf

# 3. 점검만 실행 (시스템 변경 없음)
./kisa-audit.sh check

# 4. 취약점 자동 조치
./kisa-audit.sh apply

# 5. 조치 내용 전체 롤백
./kisa-audit.sh rollback
```

#### 다수 서버 일괄 배포 (`deploy.sh`)

```bash
# 1. targets.conf 작성
# 형식: [IP 또는 IP범위]  [SSH포트]  [계정]  [비밀번호]
cat > targets.conf << 'EOF'
192.168.1.10-20   22   root   your_password
192.168.1.100     22   admin  another_password
EOF

# 2. 점검 (모든 서버)
./deploy.sh check

# 3. 자동 조치 + 보고서 수집
./deploy.sh apply

# 4. 보고서 회수 위치: ./reports/<timestamp>-<mode>/<host>/
ls reports/
```

#### 주요 옵션

```
./kisa-audit.sh check|apply|rollback [OPTIONS]

  --yes, -y         대화형 프롬프트 자동 승인
  --quiet           요약만 출력
  --verbose         상세 로그 출력
  --only U-01,E-02  지정 항목만 실행
  --skip U-07,U-08  지정 항목 제외
  --dry-run         변경 예정 내용만 출력 (apply 미수행)
```

---

### 📋 점검 항목

<details>
<summary><b>계정 관리 (U-01 ~ U-13)</b></summary>

| 코드 | 중요도 | 항목 |
|------|--------|------|
| U-01 | 🔴 상 | root 계정 원격 접속 제한 |
| U-02 | 🔴 상 | 비밀번호 관리정책 설정 |
| U-03 | 🔴 상 | 계정 잠금 임계값 설정 |
| U-04 | 🔴 상 | 비밀번호 파일 보호 |
| U-05 | 🔴 상 | root 이외의 UID가 '0' 금지 |
| U-06 | 🔴 상 | 사용자 계정 su 기능 제한 |
| U-07 | 🟢 하 | 불필요한 계정 제거 |
| U-08 | 🟡 중 | 관리자 그룹에 최소한의 계정 포함 |
| U-09 | 🟢 하 | 계정이 존재하지 않는 GID 금지 |
| U-10 | 🟡 중 | 동일한 UID 금지 |
| U-11 | 🟢 하 | 사용자 shell 점검 |
| U-12 | 🟢 하 | 세션 종료 시간 설정 |
| U-13 | 🟡 중 | 안전한 비밀번호 암호화 알고리즘 사용 |

</details>

<details>
<summary><b>파일 및 디렉토리 관리 (U-14 ~ U-33)</b></summary>

| 코드 | 중요도 | 항목 |
|------|--------|------|
| U-14 | 🔴 상 | root 홈, 패스 디렉터리 권한 및 패스 설정 |
| U-15 | 🔴 상 | 파일 및 디렉터리 소유자 설정 |
| U-16 | 🔴 상 | /etc/passwd 파일 소유자 및 권한 설정 |
| U-17 | 🔴 상 | 시스템 시작 스크립트 권한 설정 |
| U-18 | 🔴 상 | /etc/shadow 파일 소유자 및 권한 설정 |
| U-19 | 🔴 상 | /etc/hosts 파일 소유자 및 권한 설정 |
| U-20 | 🔴 상 | /etc/(x)inetd.conf 파일 소유자 및 권한 설정 |
| U-21 | 🔴 상 | /etc/(r)syslog.conf 파일 소유자 및 권한 설정 |
| U-22 | 🔴 상 | /etc/services 파일 소유자 및 권한 설정 |
| U-23 | 🔴 상 | SUID, SGID, Sticky bit 설정 파일 점검 |
| U-24 | 🔴 상 | 사용자, 시스템 환경변수 파일 소유자 및 권한 설정 |
| U-25 | 🔴 상 | world writable 파일 점검 |
| U-26 | 🔴 상 | /dev에 존재하지 않는 device 파일 점검 |
| U-27 | 🔴 상 | $HOME/.rhosts, hosts.equiv 사용 금지 |
| U-28 | 🔴 상 | 접속 IP 및 포트 제한 |
| U-29 | 🟢 하 | hosts.lpd 파일 소유자 및 권한 설정 |
| U-30 | 🟡 중 | UMASK 설정 관리 |
| U-31 | 🟡 중 | 홈디렉토리 소유자 및 권한 설정 |
| U-32 | 🟡 중 | 홈 디렉토리로 지정한 디렉토리의 존재 관리 |
| U-33 | 🟢 하 | 숨겨진 파일 및 디렉토리 검색 및 제거 |

</details>

<details>
<summary><b>서비스 관리 (U-34 ~ U-63)</b></summary>

| 코드 | 중요도 | 항목 |
|------|--------|------|
| U-34 | 🔴 상 | Finger 서비스 비활성화 |
| U-35 | 🔴 상 | 공유 서비스에 대한 익명 접근 제한 설정 |
| U-36 | 🔴 상 | r 계열 서비스 비활성화 |
| U-37 | 🔴 상 | crontab 설정파일 권한 설정 미흡 |
| U-38 | 🔴 상 | DoS 공격에 취약한 서비스 비활성화 |
| U-39 | 🔴 상 | 불필요한 NFS 서비스 비활성화 |
| U-40 | 🔴 상 | NFS 접근 통제 |
| U-41 | 🔴 상 | 불필요한 automountd 제거 |
| U-42 | 🔴 상 | 불필요한 RPC 서비스 비활성화 |
| U-43 | 🔴 상 | NIS, NIS+ 점검 |
| U-44 | 🔴 상 | tftp, talk 서비스 비활성화 |
| U-45 | 🔴 상 | 메일 서비스 버전 점검 |
| U-46 | 🔴 상 | 일반 사용자의 메일 서비스 실행 방지 |
| U-47 | 🔴 상 | 스팸 메일 릴레이 제한 |
| U-48 | 🟡 중 | expn, vrfy 명령어 제한 |
| U-49 | 🔴 상 | DNS 보안 버전 패치 |
| U-50 | 🔴 상 | DNS ZoneTransfer 설정 |
| U-51 | 🟡 중 | DNS 서비스의 취약한 동적 업데이트 설정 금지 |
| U-52 | 🟡 중 | Telnet 서비스 비활성화 |
| U-53 | 🟢 하 | FTP 서비스 정보 노출 제한 |
| U-54 | 🟡 중 | 암호화되지 않는 FTP 서비스 비활성화 |
| U-55 | 🟡 중 | FTP 계정 shell 제한 |
| U-56 | 🟢 하 | FTP 서비스 접근 제어 설정 |
| U-57 | 🟡 중 | Ftpusers 파일 설정 |
| U-58 | 🟡 중 | 불필요한 SNMP 서비스 구동 점검 |
| U-59 | 🔴 상 | 안전한 SNMP 버전 사용 |
| U-60 | 🟡 중 | SNMP Community String 복잡성 설정 |
| U-61 | 🔴 상 | SNMP Access Control 설정 |
| U-62 | 🟢 하 | 로그인 시 경고 메시지 설정 |
| U-63 | 🟡 중 | sudo 명령어 접근 관리 |

</details>

<details>
<summary><b>패치·로그 관리 (U-64 ~ U-67) + 확장 항목 (E-01 ~ E-04)</b></summary>

| 코드 | 중요도 | 항목 |
|------|--------|------|
| U-64 | 🔴 상 | 주기적 보안 패치 및 벤더 권고사항 적용 |
| U-65 | 🟡 중 | NTP 및 시각 동기화 설정 |
| U-66 | 🟡 중 | 정책에 따른 시스템 로깅 설정 |
| U-67 | 🟡 중 | 로그 디렉터리 소유자 및 권한 설정 |
| E-01 | 🟡 중 | SSH 포트 변경 (확장) |
| E-02 | 🔴 상 | SELinux 모드 관리 (확장) |
| E-03 | 🟡 중 | 방화벽 허용 service (확장) |
| E-04 | 🟡 중 | 방화벽 허용 port (확장) |

</details>

---

### 📂 디렉토리 구조

```
kisa-audit/
├── kisa-audit.sh          # 메인 실행 스크립트 (단일 서버)
├── deploy.sh              # 다수 서버 일괄 배포 스크립트
├── targets.conf           # 대상 서버 목록 (IP / Port / 계정)
├── targets.conf.example   # 설정 예시
├── config/
│   └── audit.conf         # 점검 옵션 설정 (비밀번호 정책 등)
├── lib/
│   ├── common.sh          # 공통 함수 라이브러리
│   ├── os_detect.sh       # OS 감지 (Rocky / RHEL / CentOS)
│   ├── report.sh          # 보고서 생성 엔진
│   ├── handlers/          # 개별 취약점 핸들러 (U-01~U-67, E-01~E-04)
│   └── .integrity.sha256  # SHA-256 무결성 매니페스트
├── tools/
│   ├── render-html.py     # HTML 보고서 렌더러
│   ├── render-docx.py     # DOCX 보고서 렌더러
│   └── remediation_guide.py  # 조치 가이드 생성
└── reports/               # 수집된 보고서 저장 디렉토리
```

---

### ⚙️ 지원 환경

| 항목 | 요구사항 |
|------|----------|
| **OS** | Rocky Linux 8/9/10, RHEL 8/9, CentOS 7/8 |
| **Shell** | bash 4.0+ |
| **권한** | root (또는 sudo 권한 계정) |
| **의존성 (로컬)** | `sshpass`, `python3` (deploy.sh 사용 시) |
| **의존성 (원격)** | `bash`, `awk`, `sed`, `grep`, `find` |

---

### 📄 보고서 샘플

점검·조치 완료 후 다음 형식의 보고서가 자동 생성됩니다:

- **`report.html`** — 웹 브라우저에서 바로 열리는 대화형 보고서
- **`report.json`** — 자동화/연동을 위한 구조화 데이터
- **`report.docx`** — 공문 제출용 Word 문서

---

### 🤝 기여 (Contributing)

핸들러 추가·수정 방법은 [`HANDLER-GUIDE.md`](./HANDLER-GUIDE.md)를 참고해주세요.

```bash
# 새 핸들러 작성 후 무결성 매니페스트 재생성
./make-release.sh
```

---

## English

### 📌 Overview

`kisa-audit` is a Bash-based automated security audit and remediation tool for Unix/Linux servers,  
based on the **KISA (Korea Internet & Security Agency) Critical Infrastructure Technical Vulnerability Assessment Guide**.

- Covers **71 standard items (U-01 ~ U-67)** from the KISA Unix server security guide
- **4 extended items (E-01 ~ E-04)**: SSH port hardening, SELinux management, firewall rules
- Supports both **single-server self-execution** and **bulk deployment across multiple servers**
- Automatically generates **HTML / JSON / DOCX** audit reports

---

### 🚀 Quick Start

#### Single Server

```bash
tar -xzf kisa-audit-1.0.0.tar.gz && cd kisa-audit/

# Scan only (no changes)
./kisa-audit.sh check

# Auto-remediate all vulnerable items
./kisa-audit.sh apply

# Rollback all changes
./kisa-audit.sh rollback
```

#### Bulk Deployment

```bash
# Edit targets.conf
# Format: [IP or IP-range]  [SSH-port]  [user]  [password]
echo "192.168.1.10-20  22  root  password" > targets.conf

./deploy.sh check    # Scan all targets
./deploy.sh apply    # Remediate + collect reports
```

---

### 📋 Check Items Summary

| Category | Items | Coverage |
|----------|-------|----------|
| Account Management | U-01 ~ U-13 | Passwords, UID, shell, session |
| File & Directory | U-14 ~ U-33 | Permissions, ownership, SUID/SGID |
| Service Management | U-34 ~ U-63 | Unnecessary services, NFS, DNS, FTP, SNMP |
| Patch & Log | U-64 ~ U-67 | Patching, NTP, syslog, log dirs |
| Extended | E-01 ~ E-04 | SSH port, SELinux, firewall |

---

### 📄 License

Copyright (c) 2026 정하늘 (Ha-Neul Jung) &lt;ahanaoal@gmail.com&gt;  
All rights reserved. See [LICENSE](./LICENSE) for details.

---

<div align="center">

**⭐ 이 프로젝트가 도움이 됐다면 Star를 눌러주세요!**  
*If this project helped you, please give it a Star!*

</div>
