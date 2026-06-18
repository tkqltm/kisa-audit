# -*- coding: utf-8 -*-
# Remediation guide mapping for all KISA standard items (U-01 to U-67)

REMEDIATION_GUIDE = {
    "U-01": """[조치 방법] root 직접 원격 접속 차단
1. SSH 설정 파일 수정:
   # vi /etc/ssh/sshd_config
2. PermitRootLogin 설정을 no로 변경 또는 추가:
   PermitRootLogin no
3. sshd 서비스 재시작:
   # systemctl restart sshd""",

    "U-02": """[조치 방법] 패스워드 복잡성 설정
1. 복잡성 설정 파일 수정:
   # vi /etc/security/pwquality.conf
2. 다음 설정값 적용 (8자 이상, 대/소문자, 숫자, 특수문자 조합):
   minlen = 8
   dcredit = -1
   ucredit = -1
   lcredit = -1
   ocredit = -1""",

    "U-03": """[조치 방법] 계정 잠금 임계값 설정
1. PAM 인증 설정 파일 수정:
   # vi /etc/pam.d/system-auth
   # vi /etc/pam.d/password-auth
2. pam_faillock.so 모듈 추가 (5회 실패 시 120초 잠금):
   auth required pam_faillock.so preauth silent audit deny=5 unlock_time=120
   auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=120
   account required pam_faillock.so""",

    "U-04": """[조치 방법] 패스워드 파일 보호 (shadow 사용)
1. shadow 패스워드 체계로 전환:
   # pwconv
2. 비밀번호 구성 유효성 검증:
   # pwck""",

    "U-05": """[조치 방법] root 외 UID가 0인 계정 존재 금지
1. UID가 0인 계정 조회:
   # awk -F: '$3 == 0 {print $1}' /etc/passwd
2. root 이외의 불필요한 UID 0 계정 제거 또는 UID 변경:
   # userdel -r <계정명>
   # usermod -u <새UID> <계정명>""",

    "U-06": """[조치 방법] root 계정 PATH 환경변수 설정
1. root 환경설정 파일 및 공용 프로필 수정:
   # vi /etc/profile
   # vi ~/.bash_profile
2. PATH 환경변수 내의 맨 앞 또는 중간에 포함된 '.' 또는 '::' 제거""",

    "U-07": """[조치 방법] 불필요한 일반 사용자 계정 정리
1. 로그인 가능 일반 사용자 계정 검토:
   # awk -F: '$3 >= 1000 {print $1}' /etc/passwd
2. 퇴직자, 휴직자 등 미사용 불필요 계정 삭제:
   # userdel -r <계정명>""",

    "U-08": """[조치 방법] root 그룹(GID 0) 내 불필요 계정 정리
1. GID 0인 root 그룹 멤버 조회:
   # grep '^root:' /etc/group
2. root 이외의 불필요한 관리용 계정 제거:
   # gpasswd -d <계정명> root""",

    "U-09": """[조치 방법] 멤버가 없는 불필요한 GID(그룹) 정리
1. 멤버가 없고 GID가 미사용 중인 비표준 그룹 검색
2. 해당 그룹 소유 파일 검색 및 소유권 정리 (필수):
   # find / -group <그룹명> -exec chown root:root {} \\;
3. 불필요 그룹 삭제:
   # groupdel <그룹명>""",

    "U-10": """[조치 방법] 패스워드 이전 비밀번호 재사용 제한
1. PAM 인증 설정 파일 수정:
   # vi /etc/pam.d/system-auth
   # vi /etc/pam.d/password-auth
2. pam_unix.so 모듈에 remember=5 (최근 5개 비밀번호 기억) 옵션 추가:
   password sufficient pam_unix.so sha512 shadow try_first_pass use_authtok remember=5""",

    "U-11": """[조치 방법] 로그인이 불필요한 시스템 계정 로그인 차단
1. 서비스 구동용 시스템 계정(daemon, bin, sys, adm 등)의 쉘 확인
2. 해당 시스템 계정들의 기본 셸을 로그인 불가능한 셸로 변경:
   # usermod -s /sbin/nologin <계정명>""",

    "U-12": """[조치 방법] Session Timeout 설정 (600초 이하)
1. 공용 환경설정 프로필 수정:
   # vi /etc/profile
2. TMOUT 값 설정 및 적용 (600초):
   TMOUT=600
   export TMOUT""",

    "U-13": """[조치 방법] SMTP 서비스 vrfy, expn 명령어 비활성화
1. postfix 또는 sendmail 메일 서비스 설정 변경:
   # vi /etc/postfix/main.cf  -->  disable_vrfy_command = yes 추가
   # vi /etc/mail/sendmail.cf -->  O PrivacyOptions=noexpn,novrfy 추가
2. 메일 서비스 재시작:
   # systemctl restart postfix (또는 sendmail)""",

    "U-14": """[조치 방법] 홈 디렉터리 시작 파일 소유자 및 권한 설정
1. 사용자 홈 디렉터리 내 환경설정 파일(.profile, .bashrc 등) 검사:
   # ls -la /home/<사용자>/
2. 소유주를 해당 계정으로 변경하고 타인 쓰기 권한 제거:
   # chown <사용자명>:<그룹명> /home/<사용자명>/.bashrc
   # chmod 644 /home/<사용자명>/.bashrc""",

    "U-15": """[조치 방법] 소유자 없는 파일 및 디렉터리 제거/소유권 지정
1. 시스템 전수 검색을 통한 고아 파일 검출:
   # find / -nouser -o -nogroup
2. 검색된 파일 삭제 또는 적절한 소유주(root 등) 지정:
   # rm -rf <파일명>
   # chown root:root <파일명>""",

    "U-16": """[조치 방법] /etc/passwd 파일 소유자 및 권한 설정
1. passwd 파일 소유권 및 권한 강제 조치:
   # chown root:root /etc/passwd
   # chmod 644 /etc/passwd""",

    "U-17": """[조치 방법] /etc/group 파일 소유자 및 권한 설정
1. group 파일 소유권 및 권한 강제 조치:
   # chown root:root /etc/group
   # chmod 644 /etc/group""",

    "U-18": """[조치 방법] /etc/shadow 파일 소유자 및 권한 설정
1. shadow 파일 소유권 및 권한 강제 조치 (가장 안전한 000 또는 400):
   # chown root:root /etc/shadow
   # chmod 400 /etc/shadow  (또는 # chmod 000 /etc/shadow)""",

    "U-19": """[조치 방법] /etc/hosts 파일 소유자 및 권한 설정
1. hosts 파일 소유권 및 권한 강제 조치:
   # chown root:root /etc/hosts
   # chmod 644 /etc/hosts""",

    "U-20": """[조치 방법] /etc/xinetd.conf 및 xinetd.d 디렉터리 설정 파일
1. xinetd 관련 파일 소유권 및 권한 강제 조치:
   # chown root:root /etc/xinetd.conf
   # chmod 600 /etc/xinetd.conf""",

    "U-21": """[조치 방법] /etc/rsyslog.conf 파일 소유자 및 권한 설정
1. rsyslog.conf 파일 소유권 및 권한 강제 조치:
   # chown root:root /etc/rsyslog.conf
   # chmod 640 /etc/rsyslog.conf""",

    "U-22": """[조치 방법] /etc/services 파일 소유자 및 권한 설정
1. services 파일 소유권 및 권한 강제 조치:
   # chown root:root /etc/services
   # chmod 644 /etc/services""",

    "U-23": """[조치 방법] 불필요한 SUID, SGID 권한 설정 제거
1. 비인가 SUID/SGID 파일 확인:
   # find / -user root -type f \\( -perm -04000 -o -perm -02000 \\)
2. 필수 실행 파일 외의 불필요한 SUID/SGID 권한 비활성화:
   # chmod -s <파일명>""",

    "U-24": """[조치 방법] 사용자 환경변수 파일(.profile 등) 타인 쓰기 금지
1. 각 사용자 홈 디렉터리 시작 파일 권한 변경:
   # chmod 600 ~/.bash_profile
   # chmod 600 ~/.bashrc""",

    "U-25": """[조치 방법] world writable(누구나 쓰기 가능) 파일 점검
1. 쓰기 권한이 과도한 파일 검색:
   # find / -perm -2 -type f
2. 운영상 쓰기 권한이 불필요한 경우 일반 사용자 권한 제한:
   # chmod o-w <파일명>""",

    "U-26": """[조치 방법] NFS 서비스 비활성화
1. NFS 데몬 구동 여부 및 활성 상태 검사
2. NFS를 사용하지 않는 경우 데몬 중지 및 비활성화:
   # systemctl stop nfs-server
   # systemctl disable nfs-server""",

    "U-27": """[조치 방법] NFS 공유 설정 접근 통제 (NFS 사용 시)
1. NFS 공유 설정 파일 수정:
   # vi /etc/exports
2. 공유 디렉터리에 접근 허용할 특정 IP 대역만 명시 및 root_squash 적용:
   /shared_dir 192.168.200.0/24(rw,sync,root_squash)""",

    "U-28": """[조치 방법] 접속 IP 및 포트 제한 설정
1. 호스트 기반 접근 통제 설정:
   # vi /etc/hosts.allow  -->  sshd : <허용할 특정 IP/대역>
   # vi /etc/hosts.deny   -->  sshd : ALL
2. 또는 firewalld 룰을 통해 특정 허용 대역 외 차단 적용""",

    "U-29": """[조치 방법] r-commands 서비스 비활성화 (rsh, rlogin, rexec)
1. r-commands 서비스 소켓 비활성화 및 패키지 삭제:
   # systemctl disable --now rsh.socket rlogin.socket rexec.socket
   # dnf remove rsh-server""",

    "U-30": """[조치 방법] 시스템 기본 umask 설정
1. 공용 환경설정 파일 수정:
   # vi /etc/profile
   # vi /etc/bashrc
2. umask 값을 022로 변경 적용:
   umask 022""",

    "U-31": """[조치 방법] /etc/passwd 사용자 로그인 쉘 제한
1. 불필요하거나 시스템 관리 목적 외의 사용자 계정 로그인 쉘을 제한:
   # usermod -s /sbin/nologin <계정명>""",

    "U-32": """[조치 방법] 계정별 홈 디렉터리 존재 여부 검증
1. 홈 디렉터리가 부재하거나 루트(/)로 할당된 계정 확인
2. 홈 디렉터리 생성 및 소유권 강제 지정:
   # mkdir /home/<계정명> && chown <계정명>:<그룹명> /home/<계정명>""",

    "U-33": """[조치 방법] DNS 서비스 Recursion(재귀적 질의) 통제
1. DNS 주 설정 파일 수정:
   # vi /etc/named.conf
2. options 블록 내 재귀 질의 비활성화 또는 내부망 한정:
   recursion no;  (또는 allow-recursion { localhost; 192.168.200.0/24; };)""",

    "U-34": """[조치 방법] DNS Zone Transfer(영역 전송) 제한
1. DNS 주 설정 파일 수정:
   # vi /etc/named.conf
2. options 또는 개별 zone 블록 내 허가되지 않은 전송 금지 적용:
   allow-transfer { none; }; (또는 allow-transfer { <보조네임서버IP>; };)""",

    "U-35": """[조치 방법] Apache 디렉터리 리스팅(Indexes) 비활성화
1. 아파치 설정 파일 수정:
   # vi /etc/httpd/conf/httpd.conf
2. Directory 지시자 내의 Options 항목에서 Indexes 제거:
   Options FollowSymLinks""",

    "U-36": """[조치 방법] Apache 프로세스 구동 권한 관리자 분리
1. 아파치 설정 파일 수정:
   # vi /etc/httpd/conf/httpd.conf
2. 구동 사용자 및 그룹을 비권한 계정(apache 등)으로 설정:
   User apache
   Group apache""",

    "U-37": """[조치 방법] Apache 디렉터리 및 설정 파일 소유자/권한 설정
1. 아파치 설정 및 웹루트 디렉터리 쓰기 권한 제한:
   # chown -R root:root /etc/httpd
   # chmod -R 755 /etc/httpd""",

    "U-38": """[조치 방법] Apache 불필요한 기본 샘플 및 매뉴얼 파일 제거
1. 웹 서비스 기본 페이지, 매뉴얼 등 불필요 리소스 강제 제거:
   # rm -rf /usr/share/httpd/manual
   # rm -rf /var/www/html/usage""",

    "U-39": """[조치 방법] Apache 상위 디렉터리 외부 링크 참조 금지
1. 아파치 설정 파일 수정:
   # vi /etc/httpd/conf/httpd.conf
2. Options 지시자에서 FollowSymLinks 대신 SymLinksIfOwnerMatch 사용""",

    "U-40": """[조치 방법] Apache 웹 서비스 파일 업로드/다운로드 용량 제한
1. 아파치 설정 파일 수정:
   # vi /etc/httpd/conf/httpd.conf
2. LimitRequestBody 지시자를 추가하여 파일 업로드 용량 제한 (예: 5MB):
   LimitRequestBody 5242880""",

    "U-41": """[조치 방법] 불필요한 automountd 서비스 제거
1. autofs 서비스 데몬 구동 여부 검사
2. 사용하지 않는 경우 데몬 중지 및 비활성화:
   # systemctl stop autofs
   # systemctl disable autofs""",

    "U-42": """[조치 방법] 불필요한 RPC 서비스 비활성화
1. 미사용 중인 RPC 관련 서비스(rpc-statd, rpc-gssd 등) 비활성화:
   # systemctl stop rpc-statd.service
   # systemctl mask rpc-statd.service""",

    "U-43": """[조치 방법] 불필요한 NIS 서비스 비활성화
1. ypserv, ypbind 등 NIS 네트워크 정보 서비스 데몬 정지:
   # systemctl disable --now ypserv ypbind""",

    "U-44": """[조치 방법] 불필요한 tftp, talk, ntalk 서비스 제거
1.inetd/systemd 기반의 취약 서비스 소켓 및 데몬 제거:
   # systemctl disable --now tftp.socket talk.socket ntalk.socket""",

    "U-45": """[조치 방법] SMTP 서비스(Sendmail/Postfix) 보안 취약점 업데이트
1. 최신 보안 릴리즈 버전의 postfix/sendmail 패키지 업데이트:
   # dnf update postfix (또는 sendmail)""",

    "U-46": """[조치 방법] SMTP 서비스 vrfy, expn 명령어 차단
1. 메일 설정 파일 수정:
   # vi /etc/postfix/main.cf  -->  disable_vrfy_command = yes
   # vi /etc/mail/sendmail.cf -->  O PrivacyOptions=noexpn,novrfy
2. 메일 서비스 구성 재검토 및 재시작""",

    "U-47": """[조치 방법] SMTP 스팸 메일 릴레이 차단
1. 메일 설정 파일 수정:
   # vi /etc/postfix/main.cf
2. mynetworks 파라미터를 내부 로컬 호스트만 허용하도록 한정:
   mynetworks = 127.0.0.0/8""",

    "U-48": """[조치 방법] SMTP 메일 서비스 발송 차단 정책 적용
1. 시스템 중요 정보 노출 방지를 위해 root 및 시스템 계정 메일 포워딩/수신 정책 수립 조치""",

    "U-50": """[조치 방법] DNS Zone Transfer(영역 전송) 제한
1. DNS named.conf 설정 파일 수정:
   # vi /etc/named.conf
2. options 에 allow-transfer { none; }; 또는 특정 보조 네임서버 IP 대역만 지정""",

    "U-51": """[조치 방법] DNS 캐시 포이즈닝 방지 및 Recursion 차단
1. DNS named.conf 설정 파일 수정:
   # vi /etc/named.conf
2. recursion 설정을 localhost 및 내부망 대역으로만 제한:
   allow-recursion { localhost; };""",

    "U-52": """[조치 방법] 취약한 Telnet 서비스 비활성화
1. 텔넷 서비스 중지 및 마스킹:
   # systemctl stop telnet.socket
   # systemctl disable --now telnet.socket""",

    "U-53": """[조치 방법] FTP 서비스 접속 배너 정보 노출 제한
1. vsftpd 설정 파일 수정:
   # vi /etc/vsftpd/vsftpd.conf
2. ftpd_banner 지시자에 OS 및 버전을 나타내지 않는 문구 입력:
   ftpd_banner=Welcome to FTP service""",

    "U-54": """[조치 방법] FTP 서비스 비활성화
1. vsftpd 데몬 서비스 사용 여부 확인
2. 미사용 시 데몬 중지 및 비활성화:
   # systemctl stop vsftpd
   # systemctl disable --now vsftpd""",

    "U-55": """[조치 방법] FTP 기본 시스템 계정 로그인 쉘 차단
1. ftp 사용자의 기본 셸을 로그인 불가 셸로 설정:
   # usermod -s /sbin/nologin ftp""",

    "U-56": """[조치 방법] FTP 서비스의 root 계정 접속 차단
1. vsftpd 제한 계정 명단 파일 확인:
   # vi /etc/vsftpd/user_list
2. root 계정이 파일에 등록되어 있는지 확인 및 누락 시 추가 차단""",

    "U-57": """[조치 방법] FTP 서비스 익명(anonymous) 접속 차단
1. vsftpd 설정 파일 수정:
   # vi /etc/vsftpd/vsftpd.conf
2. 익명 접속 차단 옵션 적용:
   anonymous_enable=NO""",

    "U-58": """[조치 방법] Apache 상위 디렉터리 접근 제어 및 오버라이드 제한
1. 아파치 설정 파일 수정:
   # vi /etc/httpd/conf/httpd.conf
2. 루트 디렉터리(<Directory />) 설정 확인 및 오버라이드 불허가 적용:
   AllowOverride None
   Require all denied""",

    "U-59": """[조치 방법] 불필요한 활성 서비스 포트 중지
1. 현재 listen 중인 소켓/서비스 확인:
   # netstat -tulnp (또는 # ss -tulnp)
2. 비표준이거나 운영 정책상 불필요한 서비스 프로세스 중지 및 disable""",

    "U-60": """[조치 방법] SNMP Community String 보안 강화
1. SNMP 설정 파일 수정:
   # vi /etc/snmp/snmpd.conf
2. 기본값(public/private) 대신 식별하기 어려운 복잡한 문자열로 변경:
   com2sec notConfigUser default <복잡한문자열>""",

    "U-61": """[조치 방법] SNMP 서비스 접근 통제 설정
1. SNMP(UDP 161) 접근을 신뢰할 수 있는 관리자 시스템(NMS 등) 대역만 허용하도록 방화벽 룰 또는 hosts.allow 파일 구성""",

    "U-62": """[조치 방법] 원격 접속 로그인 배너 경고 설정
1. 시스템 원격 로그인 정보 파일 수정:
   # vi /etc/motd
   # vi /etc/issue
2. 비인가 사용자의 무단 접속 시 형사 책임을 명시하는 경고 문안 입력""",

    "U-63": """[조치 방법] sudoers 파일 내 불필요한 권한 제한
1. sudoers 파일 확인 및 무차별 권한 점검:
   # visudo
2. 특정 계정에 NOPASSWD: ALL 등 무조건적인 관리자 권한이 부여된 내역 차단 및 조정""",

    "U-64": """[조치 방법] SSH 프로토콜 v2 지정 및 안전하지 않은 암호 제한
1. sshd 설정 파일 수정:
   # vi /etc/ssh/sshd_config
2. Protocol 2 단독 지정 및 약한 Ciphers, MACs 알고리즘 배제 조치""",

    "U-65": """[조치 방법] 시간 동기화(NTP) 서비스 구성
1. chrony 시간 동기화 설정 파일 수정:
   # vi /etc/chrony.conf
2. 신뢰할 수 있는 시간 동기화 서버 주소 등록:
   server time.bora.net iburst
3. chronyd 데몬 활성화: # systemctl enable --now chronyd""",

    "U-66": """[조치 방법] 보안 로그 기록 및 모니터링 데몬(auditd) 활성화
1. auditd 감사 데몬 활성화 및 실행:
   # systemctl enable --now auditd
2. KISA 보안 감사 가이드 규칙 기반 감사 룰 파일 구성 적용""",

    "U-67": """[조치 방법] 주요 로그 파일(messages 등) 소유자 및 권한 설정
1. syslog/rsyslog가 기록하는 주요 로그 파일의 권한을 640 이하로 조치:
   # chown root:root /var/log/messages
   # chmod 600 /var/log/messages  (또는 640)"""
}
