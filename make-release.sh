#!/usr/bin/env bash
# Copyright (c) 2026 정하늘 <ahanaoal@gmail.com> — Licensed under the MIT License.
# kisa-audit 배포 패키지 생성 스크립트.
#
# 사용:
#   ./make-release.sh                 # ./dist/kisa-audit-<VERSION>.tar.gz 생성
#   ./make-release.sh -o /path        # 출력 디렉터리 변경
#
# 포함되는 파일 (실제로 사용자가 배포·실행하는 것만):
#   kisa-audit.sh, deploy.sh, VERSION, README.md
#   config/audit.conf.example, targets.conf.example
#   lib/common.sh, lib/os_detect.sh, lib/report.sh, lib/handlers/U-*.sh, lib/handlers/E-*.sh
#   tools/render-html.py
#
# 제외:
#   - 개발자 전용 문서 (HANDLER-GUIDE.md, HANDLER_SPEC.md)
#   - 런타임/회수 산출물 (reports/, sample-*.html)
#   - 사용자 시크릿 (targets.conf, config/audit.conf, *.tar.gz, dist/)

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

OUT_DIR="$SCRIPT_DIR/dist"
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output) OUT_DIR="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

VERSION="$(cat VERSION 2>/dev/null || echo 'unknown')"
PKG_NAME="kisa-audit-${VERSION}"
mkdir -p "$OUT_DIR"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
DEST="$STAGE/$PKG_NAME"
mkdir -p "$DEST"

# 코어 파일
cp kisa-audit.sh deploy.sh VERSION "$DEST/"
cp targets.conf.example "$DEST/"

# config/audit.conf.example 만 (audit.conf 는 사용자 시크릿이라 제외)
mkdir -p "$DEST/config"
cp config/audit.conf.example "$DEST/config/"

# lib/ 코어 + handlers (sh 파일만)
mkdir -p "$DEST/lib/handlers"
cp lib/common.sh lib/os_detect.sh lib/report.sh "$DEST/lib/"
cp lib/handlers/U-*.sh lib/handlers/E-*.sh "$DEST/lib/handlers/" 2>/dev/null || true

# tools/
mkdir -p "$DEST/tools"
cp tools/render-html.py tools/remediation_guide.py "$DEST/tools/"

# LICENSE (저작권)
[[ -f LICENSE ]] && cp LICENSE "$DEST/"

# README (간단한 사용법)
cat > "$DEST/README.md" <<'EOF'
# KISA 주요정보통신기반시설 취약점 점검 스크립트

KISA "주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)"
U-01 ~ U-67 (Unix 서버 항목) + 확장 항목(E-01~E-04) 자동 점검·조치·롤백 도구.

## 지원 OS
- Rocky Linux / RHEL 8 / 9 / 10

## 사전 요구
- root 권한
- bash 4 이상
- python3 (또는 /usr/libexec/platform-python — Rocky 8 minimal 자동 대응)

## 단일 서버 실행 (자가 완결)
```bash
tar -xzf kisa-audit-<VERSION>.tar.gz
cd kisa-audit-<VERSION>

# (선택) 정책값 지정
cp config/audit.conf.example config/audit.conf
$EDITOR config/audit.conf

./kisa-audit.sh check                   # 점검만 (변경 없음)
./kisa-audit.sh apply --dry-run         # 조치 예정 미리보기
./kisa-audit.sh apply --yes             # 실제 조치
./kisa-audit.sh rollback                # 시스템 전수 *.kisa.bak 복원
./kisa-audit.sh apply --only U-37 --yes # 특정 항목만 조치
```

산출물·흔적:
- `./report.html` — 실행 디렉터리에 단일 자체완결 HTML 리포트 (덮어쓰기)
- `<원본파일>.kisa.bak` — 조치 시 원본 옆에 보존되는 백업 (이미 있으면 건너뜀)
- `<원본파일>.kisa.bak.absent` — apply 가 새로 만든 파일임을 표시 (rollback 시 삭제)
- 임시 디렉터리(/tmp/kisa-audit-XXXXX)는 실행 종료 시 자동 삭제

롤백은 `*.kisa.bak` 만 보고 동작하므로 run-id·메타파일 관리가 필요 없습니다.

## 다수 서버에 배포·실행 (관리 PC)
```bash
cp targets.conf.example targets.conf
# host port user password 형식으로 대상 서버 입력
./deploy.sh check         # 일괄 점검 + report.html 회수
./deploy.sh apply         # 일괄 조치 + report.html 회수
./deploy.sh rollback      # 일괄 롤백
```

회수 위치: `./reports/<timestamp>-<mode>/<host>/report.html`

## 정책값 커스터마이즈
`config/audit.conf` 에서 비밀번호 정책 / SSH / NFS / SNMP / NTP /
원격 syslog(RSYSLOG_REMOTE_SERVER) / 방화벽 등을 조정. 자세한 변수 설명은
`config/audit.conf.example` 주석 참고.

## 보안 주의
- `targets.conf` 는 비밀번호를 평문으로 담으므로 git 커밋 금지·700 권한 권장.
- `audit.conf` 는 자동으로 mode 600 + root:root 강제됨.
- 가능한 경우 SSH 키 인증으로 전환할 것.
EOF

# 권한 정리
find "$DEST" -type f -name '*.sh' -exec chmod 755 {} +
find "$DEST" -type f -name '*.py' -exec chmod 755 {} +
find "$DEST" -type f \( -name '*.md' -o -name '*.example' -o -name 'VERSION' -o -name 'LICENSE' \) -exec chmod 644 {} +

# ─────────── 무결성 매니페스트 생성 ───────────
# 핸들러/라이브러리 변조 차단을 위해 SHA256 해시 매니페스트 생성.
# kisa-audit.sh 시작 시 _kisa_verify_integrity() 가 이 파일을 읽어 검증.
echo
echo "=== 무결성 매니페스트 생성 ==="
(
    cd "$DEST"
    {
        find lib -type f -name '*.sh' | sort
        find tools -type f \( -name '*.py' -o -name '*.sh' \) 2>/dev/null | sort
        echo kisa-audit.sh
    } | xargs sha256sum > lib/.integrity.sha256
    chmod 444 lib/.integrity.sha256
    echo "  생성: lib/.integrity.sha256"
    echo "  파일 수: $(wc -l < lib/.integrity.sha256)"
)

# 패키지화
TARBALL="$OUT_DIR/${PKG_NAME}.tar.gz"
( cd "$STAGE" && tar -czf "$TARBALL" "$PKG_NAME" )

# 요약
echo
echo "=== Release ==="
echo "  Output: $TARBALL"
echo "  Size  : $(du -h "$TARBALL" | cut -f1)"
echo "  Files : $(tar -tzf "$TARBALL" | wc -l)"
echo
echo "=== Manifest (top 30) ==="
tar -tzf "$TARBALL" | head -30
echo "  ..."
echo
echo "Install:"
echo "  scp $TARBALL root@<target>:/tmp/"
echo "  ssh root@<target> 'tar -xzf /tmp/${PKG_NAME}.tar.gz -C /opt/ && /opt/${PKG_NAME}/kisa-audit.sh check'"
