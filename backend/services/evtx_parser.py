"""
Windows 事件日志 (.evtx) 及主机采集包 (.zip) 核心解析服务
支持安全解压采集包，使用 python-evtx 解析二进制 .evtx 日志（兼容导出的 .xml/.json 快照），
针对关键安全事件 ID (4624, 4625, 4688, 7045, 4720) 进行字段提取、威胁启发式评分并写入 host_artifacts 表。
"""

import asyncio
import base64
import json
import logging
import os
import re
import shutil
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from Evtx.Evtx import Evtx
from sqlalchemy.ext.asyncio import AsyncSession

from database import AsyncSessionLocal, CaseHost, HostArtifact, IOCIntelligence

logger = logging.getLogger("windfir.evtx_parser")

# 重点关注的 Windows Event ID 集合
TARGET_EVENT_IDS = {4624, 4625, 4688, 7045, 4720}

# Windows 登录类型映射表
LOGON_TYPE_MAP = {
    "2": "Interactive (本地交互登录)",
    "3": "Network (网络登录/SMB/RPC)",
    "4": "Batch (计划任务批处理登录)",
    "5": "Service (服务启动登录)",
    "7": "Unlock (屏幕解锁)",
    "8": "NetworkCleartext (网络明文凭据登录)",
    "9": "NewCredentials (RunAs带/netonly登录)",
    "10": "RemoteInteractive (RDP远程桌面登录)",
    "11": "CachedInteractive (域缓存凭据登录)",
}

# 高危命令行特征正则规则库 (正则, 风险等级, 威胁标签, MITRE ATT&CK 编号)
SUSPICIOUS_CMD_RULES: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"powershell.*(-enc|-encodedcommand|-w\s+hidden|-windowstyle\s+hidden|frombase64string|downloadstring|iex\b|invoke-expression)", re.I),
        "critical",
        "PowerShell混淆/无文件执行",
        "T1059.001",
    ),
    (
        re.compile(r"(mimikatz|sekurlsa|lsadump|procdump.*lsass|comsvcs\.dll.*minidump)", re.I),
        "critical",
        "凭据转储与LSASS内存窃取",
        "T1003.001",
    ),
    (
        re.compile(r"(certutil.*-urlcache|bitsadmin.*\/transfer|mshta\s+http|regsvr32.*\/i:http|rundll32.*javascript)", re.I),
        "high",
        "LOLBAS系统白利用下载/执行",
        "T1105",
    ),
    (
        re.compile(r"(wevtutil\s+cl|vssadmin\s+delete\s+shadows|wbadmin\s+delete|bcdedit.*recoveryenabled\s+no)", re.I),
        "critical",
        "防取证日志清理/卷影副本删除(勒索软件特征)",
        "T1070.001",
    ),
    (
        re.compile(r"(net\s+user\s+.*\/add|net\s+localgroup\s+administrators\s+.*\/add|net1\s+user)", re.I),
        "high",
        "命令行创建账户或提权加入管理员组",
        "T1136.001",
    ),
    (
        re.compile(r"(whoami\s+\/all|nltest\s+\/domain_trusts|net\s+group\s+\"domain\s+admins\"|ipconfig\s+\/all|tasklist\s+\/svc|quser|qwinsta)", re.I),
        "medium",
        "内网主机与域环境信息收集探测",
        "T1033",
    ),
    (
        re.compile(r"(schtasks.*\/create|reg\s+add.*\\currentversion\\run|sc\s+create)", re.I),
        "high",
        "计划任务/注册表/服务持久化驻留",
        "T1053.005",
    ),
    (
        re.compile(r"(\.mallox\b|mallox|\.locked\b|\.phobos\b|\.lockbit\b|Restore-My-Files\.txt)", re.I),
        "critical",
        "勒索病毒家族加密载荷特征(Mallox/LockBit/Phobos)",
        "T1486",
    ),
    (
        re.compile(r"(SunloginClient\.exe|ToDesk\.exe|AnyDesk\.exe|\/cgi-bin\/rpc|check\?cmd=ping)", re.I),
        "high",
        "第三方远控软件跳板/向日葵RCE特征",
        "T1219",
    ),
    (
        re.compile(r"(\$\{jndi:(ldap|rmi)|bsh\.servlet\.BshServlet|xmrig|supportxmr|c3pool)", re.I),
        "critical",
        "高危漏洞POC注入或XMRig挖矿木马特征",
        "T1190",
    ),
]

# Web中间件进程列表（若其拉起 cmd.exe / powershell.exe 则极可能为 WebShell 执行）
WEB_SERVER_PROCESSES = {
    "w3wp.exe",
    "php-cgi.exe",
    "php.exe",
    "tomcat.exe",
    "java.exe",
    "javaw.exe",
    "httpd.exe",
    "nginx.exe",
    "node.exe",
}


class EvtxParseError(Exception):
    """自定义日志解析异常"""
    pass


def _strip_ns(tag: str) -> str:
    """移除 XML 命名空间前缀"""
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


_PS_B64_PATTERN = re.compile(
    r"(?:-[eE][nN]?[cC]?(?:[oO][dD][eE][dD][cC][oO][mM][mM][aA][nN][dD])?|FromBase64String\s*\(\s*['\"])\s*([A-Za-z0-9+/=]{12,})",
    re.IGNORECASE,
)


def _decode_ps_base64(text: Optional[str]) -> Optional[str]:
    """
    自动提取并解码 PowerShell -enc / -encodedcommand 的 Base64 载荷
    优先尝试 Windows PowerShell 默认的 UTF-16LE 编码，兼容 UTF-8
    """
    if not text:
        return None
    match = _PS_B64_PATTERN.search(text)
    if not match:
        return None
    b64_str = match.group(1).strip()
    missing_padding = len(b64_str) % 4
    if missing_padding:
        b64_str += "=" * (4 - missing_padding)
    try:
        raw_bytes = base64.b64decode(b64_str, validate=False)
        if b"\x00" in raw_bytes:
            decoded = raw_bytes.decode("utf-16le", errors="ignore").strip()
            if decoded:
                return decoded
        decoded_utf8 = raw_bytes.decode("utf-8", errors="ignore").strip()
        if decoded_utf8:
            return decoded_utf8
    except Exception:
        return None
    return None


def _parse_event_time(time_str: Optional[str]) -> Optional[datetime]:
    """解析 Windows Event SystemTime 字符串为 Python datetime (UTC)"""
    if not time_str:
        return None
    cleaned = time_str.strip().rstrip("Z")
    # 处理纳秒级精度（截断至微秒 6 位小数）
    if "." in cleaned:
        main_part, frac_part = cleaned.split(".", 1)
        # 移除可能附带的 +00:00 时区尾缀
        if "+" in frac_part:
            frac_part = frac_part.split("+", 1)[0]
        elif "-" in frac_part:
            frac_part = frac_part.split("-", 1)[0]
        cleaned = f"{main_part}.{frac_part[:6]}"
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(cleaned, fmt)
        except ValueError:
            continue
    return None


def _safe_extract_zip(zip_path: Path, extract_to: Path) -> list[Path]:
    """
    安全解压 .zip 文件并防范 Zip Slip 目录穿越漏洞
    返回解压出的所有文件绝对路径列表
    """
    if not zip_path.exists() or not zip_path.is_file():
        raise EvtxParseError(f"采集包文件不存在: {zip_path}")

    if not zipfile.is_zipfile(zip_path):
        raise EvtxParseError(f"文件不是合法的 ZIP 压缩包格式: {zip_path.name}")

    extracted_files: list[Path] = []
    extract_root = extract_to.resolve()

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for member in zf.infolist():
                if member.is_dir():
                    continue
                # 防御 Zip Slip 路径穿越攻击
                target_path = (extract_root / member.filename).resolve()
                if not str(target_path).startswith(str(extract_root)):
                    logger.warning(f"拦截可疑路径穿越文件: {member.filename}")
                    continue
                target_path.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member, "r") as src, open(target_path, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                extracted_files.append(target_path)
    except zipfile.BadZipFile as exc:
        raise EvtxParseError(f"ZIP 压缩包损坏无法解压: {exc}") from exc
    except Exception as exc:
        raise EvtxParseError(f"解压采集包异常: {exc}") from exc

    return extracted_files


def _parse_xml_record(xml_str: str, source_file: str) -> Optional[dict[str, Any]]:
    """
    将单条 EVTX XML 记录解析为结构化字典，仅保留目标 EventID (4624, 4625, 4688, 7045, 4720)
    并根据安全规则评估风险等级
    """
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    system_node = None
    event_data_node = None

    for child in root:
        tag_name = _strip_ns(child.tag)
        if tag_name == "System":
            system_node = child
        elif tag_name in ("EventData", "UserData"):
            event_data_node = child

    if system_node is None:
        return None

    event_id: Optional[int] = None
    system_time_str: Optional[str] = None
    computer_name: Optional[str] = None
    channel: Optional[str] = None
    provider_name: Optional[str] = None

    for sys_child in system_node:
        stag = _strip_ns(sys_child.tag)
        if stag == "EventID" and sys_child.text:
            try:
                event_id = int(sys_child.text.strip())
            except ValueError:
                return None
        elif stag == "TimeCreated":
            system_time_str = sys_child.attrib.get("SystemTime")
        elif stag == "Computer" and sys_child.text:
            computer_name = sys_child.text.strip()
        elif stag == "Channel" and sys_child.text:
            channel = sys_child.text.strip()
        elif stag == "Provider":
            provider_name = sys_child.attrib.get("Name")

    # 过滤非关键 EventID
    if event_id not in TARGET_EVENT_IDS:
        return None

    # 提取 EventData 键值对
    data_map: dict[str, str] = {}
    if event_data_node is not None:
        for idx, data_elem in enumerate(event_data_node.iter()):
            if data_elem is event_data_node:
                continue
            dtag = _strip_ns(data_elem.tag)
            name_attr = data_elem.attrib.get("Name")
            val_text = (data_elem.text or "").strip()
            if dtag == "Data" and name_attr:
                data_map[name_attr] = val_text
            elif dtag == "Data":
                data_map[f"Data_{idx}"] = val_text
            elif val_text:
                data_map[dtag] = val_text

    event_time = _parse_event_time(system_time_str)
    return _evaluate_security_event(
        event_id=event_id,
        event_time=event_time,
        computer_name=computer_name,
        channel=channel,
        provider_name=provider_name,
        data_map=data_map,
        raw_xml=xml_str,
        source_file=source_file,
    )


def _evaluate_security_event(
    event_id: int,
    event_time: Optional[datetime],
    computer_name: Optional[str],
    channel: Optional[str],
    provider_name: Optional[str],
    data_map: dict[str, str],
    raw_xml: str,
    source_file: str,
) -> Optional[dict[str, Any]]:
    """
    针对 4624 / 4625 / 4688 / 7045 / 4720 提取关键取证字段，并计算风险等级与标签
    """
    risk_level = "low"
    risk_tags: list[str] = []
    is_malicious = False
    artifact_type = "evtx_security"
    summary = ""
    parsed_data: dict[str, Any] = {
        "Computer": computer_name,
        "Channel": channel,
        "Provider": provider_name,
    }
    extracted_ioc: Optional[dict[str, Any]] = None

    # --------------------------------------------------------------------------
    # 1. EventID 4624 (登录成功) & 4625 (登录失败)
    # --------------------------------------------------------------------------
    if event_id in (4624, 4625):
        artifact_type = "evtx_logon"
        logon_type = data_map.get("LogonType", "")
        ip_address = data_map.get("IpAddress", "-")
        ip_port = data_map.get("IpPort", "-")
        target_user = data_map.get("TargetUserName", "-")
        target_domain = data_map.get("TargetDomainName", "-")
        subject_user = data_map.get("SubjectUserName", "-")
        workstation = data_map.get("WorkstationName", "-")
        logon_process = data_map.get("LogonProcessName", "-")
        status = data_map.get("Status", "")
        sub_status = data_map.get("SubStatus", "")

        # 过滤系统内置机器账号本地服务噪音（如 SYSTEM / LOCAL SERVICE / DWM-* / UMFD-* 的 Type 5/0 登录）
        if event_id == 4624 and logon_type in ("0", "5") and ip_address in ("-", "127.0.0.1", "::1", ""):
            return None
        if event_id == 4624 and (target_user.endswith("$") or target_user in ("SYSTEM", "ANONYMOUS LOGON")) and ip_address in ("-", "127.0.0.1", "::1", ""):
            return None

        logon_desc = LOGON_TYPE_MAP.get(logon_type, f"Type {logon_type}")
        parsed_data.update({
            "LogonType": logon_type,
            "LogonTypeDesc": logon_desc,
            "IpAddress": ip_address,
            "IpPort": ip_port,
            "TargetUserName": target_user,
            "TargetDomainName": target_domain,
            "SubjectUserName": subject_user,
            "WorkstationName": workstation,
            "LogonProcessName": logon_process,
            "Status": status,
            "SubStatus": sub_status,
        })

        has_remote_ip = ip_address not in ("-", "", "127.0.0.1", "::1", "0.0.0.0")

        if event_id == 4624:
            summary = f"[登录成功] 账号 {target_domain}\\{target_user} 通过 {logon_desc} 登录 (源IP: {ip_address})"
            if logon_type == "10":  # RDP 远程桌面登录
                risk_level = "high" if has_remote_ip else "medium"
                risk_tags.extend(["T1021.001", "RDP远程桌面登录"])
            elif logon_type in ("3", "8", "9") and has_remote_ip:
                risk_level = "medium"
                risk_tags.extend(["T1021.002", "远程网络登录"])
                if target_user.lower() in ("administrator", "admin", "guest") or target_user.endswith("$"):
                    risk_level = "high"
                    risk_tags.append("高危特权/隐藏账户远程登录")
        else:  # 4625 登录失败
            summary = f"[登录失败] 账号 {target_domain}\\{target_user} 登录被拒绝 ({logon_desc}, 源IP: {ip_address}, 状态码: {status})"
            if has_remote_ip:
                risk_level = "high"
                risk_tags.extend(["T1110", "疑似远程口令暴破", "账户认证失败"])
                extracted_ioc = {
                    "ioc_type": "ip",
                    "ioc_value": ip_address,
                    "threat_level": "suspicious",
                    "tags": ["BruteForce_Candidate", f"Target:{target_user}"],
                }
            elif logon_type in ("3", "10"):
                risk_level = "medium"
                risk_tags.extend(["T1110", "网络/远程登录认证失败"])
            else:
                risk_level = "low"
                risk_tags.append("本地交互登录认证失败")

    # --------------------------------------------------------------------------
    # 2. EventID 4688 (进程创建)
    # --------------------------------------------------------------------------
    elif event_id == 4688:
        artifact_type = "evtx_process"
        new_proc_name = data_map.get("NewProcessName", "")
        new_proc_id = data_map.get("NewProcessId", "")
        command_line = data_map.get("CommandLine", "")
        # 4688 中父进程 ID 字段名为 ProcessId 或 CreatorProcessId
        ppid = data_map.get("ProcessId") or data_map.get("CreatorProcessId") or ""
        parent_proc_name = data_map.get("ParentProcessName", "")
        subject_user = data_map.get("SubjectUserName", "")
        subject_domain = data_map.get("SubjectDomainName", "")
        token_elevation = data_map.get("TokenElevationType", "")

        proc_basename = Path(new_proc_name.replace("\\", "/")).name.lower() if new_proc_name else ""
        parent_basename = Path(parent_proc_name.replace("\\", "/")).name.lower() if parent_proc_name else ""

        parsed_data.update({
            "NewProcessName": new_proc_name,
            "ProcessBaseName": proc_basename,
            "NewProcessId": new_proc_id,
            "CommandLine": command_line,
            "ParentProcessId": ppid,
            "ParentProcessName": parent_proc_name,
            "SubjectUserName": subject_user,
            "SubjectDomainName": subject_domain,
            "TokenElevationType": token_elevation,
        })

        decoded_cmd = _decode_ps_base64(command_line)
        if decoded_cmd:
            parsed_data["DecodedPayload"] = decoded_cmd
            risk_level = "critical"
            is_malicious = True
            risk_tags.extend(["T1027.010", "Base64混淆载荷已解码"])

        summary = f"[进程创建] {new_proc_name} (PID: {new_proc_id}, PPID: {ppid}) CMD: {command_line or '无'}"

        # 规则匹配：检查命令行与进程名是否命中高危规则
        check_target = f"{new_proc_name} {command_line}"
        for pattern, r_level, r_tag, attack_id in SUSPICIOUS_CMD_RULES:
            if pattern.search(check_target):
                risk_tags.extend([attack_id, r_tag])
                if r_level == "critical" or risk_level != "critical":
                    risk_level = r_level
                if r_level in ("high", "critical"):
                    is_malicious = True

        # 检查 Web 服务进程派生 Shell (典型 WebShell 特征)
        if parent_basename in WEB_SERVER_PROCESSES and proc_basename in (
            "cmd.exe", "powershell.exe", "pwsh.exe", "whoami.exe", "net.exe", "net1.exe", "ipconfig.exe", "bash.exe", "sh.exe"
        ):
            risk_level = "critical"
            is_malicious = True
            risk_tags.extend(["T1505.003", f"WebShell异常子进程({parent_basename}->{proc_basename})"])

        # 检查临时目录或用户目录运行可执行文件
        if re.search(r"(\\temp\\|\\appdata\\|\\users\\public\\|\\programdata\\|\\perflogs\\)", new_proc_name, re.I):
            if risk_level == "low":
                risk_level = "high"
            risk_tags.extend(["T1204", "异常目录进程执行"])

    # --------------------------------------------------------------------------
    # 3. EventID 7045 (新安装系统服务 - 持久化后门检查)
    # --------------------------------------------------------------------------
    elif event_id == 7045:
        artifact_type = "evtx_service"
        service_name = data_map.get("ServiceName", "-")
        image_path = data_map.get("ImagePath", "-")
        service_type = data_map.get("ServiceType", "-")
        start_type = data_map.get("StartType", "-")
        account_name = data_map.get("AccountName", "-")

        parsed_data.update({
            "ServiceName": service_name,
            "ImagePath": image_path,
            "ServiceType": service_type,
            "StartType": start_type,
            "AccountName": account_name,
        })

        decoded_svc_cmd = _decode_ps_base64(image_path)
        summary = f"[新安装服务] 服务名: {service_name}, 路径: {image_path} (启动账户: {account_name})"

        # 严格分级过滤 7045：
        # 1. 检查是否包含高危命令解释器、混淆指令、网络请求或命名管道特征 (critical)
        # 2. 检查是否位于临时目录/公共目录/AppData/ProgramData 下的可疑脚本或二进制 (high)
        # 3. 对于位于 System32\drivers、\SystemRoot\、Program Files、WindowsApps 等标准目录的常规服务/驱动，一律标记为 low
        img_norm = (image_path or "").strip()
        is_critical_svc = bool(
            decoded_svc_cmd
            or re.search(
                r"(cmd\.exe|\bcmd\b\s*\/c|%comspec%|powershell|pwsh|-enc\b|-encodedcommand|frombase64string|downloadstring|http:\/\/|https:\/\/|rundll32|regsvr32|mshta|wscript|cscript|\\\\\.\\pipe\\)",
                img_norm,
                re.I,
            )
        )
        is_high_suspicious_path = bool(
            re.search(
                r"(\\users\\public\\|\\appdata\\local\\temp\\|\\windows\\temp\\|\\temp\\|\\perflogs\\|\\programdata\\)",
                img_norm,
                re.I,
            )
            and re.search(r"\.(exe|bat|cmd|vbs|ps1|js|hta)\b", img_norm, re.I)
            and not re.search(r"\\programdata\\(microsoft\\windows defender|package cache)\\", img_norm, re.I)
        )

        if decoded_svc_cmd:
            parsed_data["DecodedPayload"] = decoded_svc_cmd

        if is_critical_svc:
            risk_level = "critical"
            is_malicious = True
            risk_tags.extend(["T1543.003", "T1569.002", "高危恶意服务后门/命令执行持久化"])
            if decoded_svc_cmd:
                risk_tags.extend(["T1027.010", "服务Base64载荷已解码"])
        elif is_high_suspicious_path:
            risk_level = "high"
            is_malicious = True
            risk_tags.extend(["T1543.003", "可疑非标准路径服务安装"])
        else:
            risk_level = "low"
            is_malicious = False
            risk_tags.append("常规系统服务/驱动变更")

    # --------------------------------------------------------------------------
    # 4. EventID 4720 (创建用户账号)
    # --------------------------------------------------------------------------
    elif event_id == 4720:
        artifact_type = "evtx_account"
        target_user = data_map.get("TargetUserName", "-")
        target_domain = data_map.get("TargetDomainName", "-")
        target_sid = data_map.get("TargetSid", "-")
        subject_user = data_map.get("SubjectUserName", "-")
        subject_domain = data_map.get("SubjectDomainName", "-")

        parsed_data.update({
            "TargetUserName": target_user,
            "TargetDomainName": target_domain,
            "TargetSid": target_sid,
            "SubjectUserName": subject_user,
            "SubjectDomainName": subject_domain,
        })

        summary = f"[创建新用户] 操作者 {subject_domain}\\{subject_user} 创建了新账号 {target_domain}\\{target_user} (SID: {target_sid})"
        risk_level = "high"
        risk_tags.extend(["T1136.001", "新建本地/域系统账户"])

        # 检测以 $ 结尾的影子/隐藏账户
        if target_user.endswith("$"):
            risk_level = "critical"
            is_malicious = True
            risk_tags.append("疑似影子隐藏后门账号($)")

        extracted_ioc = {
            "ioc_type": "user_account",
            "ioc_value": f"{target_domain}\\{target_user}",
            "threat_level": "malicious" if is_malicious else "suspicious",
            "tags": risk_tags.copy(),
        }

    # 去重 risk_tags
    unique_tags = list(dict.fromkeys(risk_tags))

    return {
        "artifact_type": artifact_type,
        "source_file": source_file,
        "event_id": event_id,
        "event_time": event_time,
        "summary": summary[:500],
        "parsed_data": parsed_data,
        "raw_data": raw_xml,
        "risk_level": risk_level,
        "risk_tags": unique_tags,
        "is_malicious": is_malicious,
        "extracted_ioc": extracted_ioc,
    }


def _parse_single_evtx_file(evtx_path: Path) -> list[dict[str, Any]]:
    """使用 python-evtx 解析单个 .evtx 二进制日志文件"""
    results: list[dict[str, Any]] = []
    source_name = evtx_path.name
    try:
        with Evtx(str(evtx_path)) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                    # 快速预筛：仅当包含目标 EventID 数字时才进入 XML 解析器，极大提升大文件解析速度
                    if not any(f">{eid}<" in xml_str for eid in TARGET_EVENT_IDS):
                        continue
                    parsed = _parse_xml_record(xml_str, source_name)
                    if parsed:
                        results.append(parsed)
                except Exception as rec_err:
                    logger.debug(f"跳过损坏的单条 EVTX 记录 ({source_name}): {rec_err}")
                    continue
    except Exception as exc:
        logger.error(f"解析 EVTX 文件失败 [{source_name}]: {exc}")
        raise EvtxParseError(f"EVTX 日志文件格式错误或已损坏 ({source_name}): {exc}") from exc

    return results


def _parse_thirdparty_collector_json(
    source_name: str,
    loaded: dict[str, Any],
    snapshot_meta: Optional[dict[str, Any]] = None,
) -> list[dict[str, Any]]:
    """
    深度兼容解析第三方应急采集器（如 WindowsCollecter / Get-Logs-Tool / MXAT）导出的结构化 JSON 文件：
    支持 SystemInformation.json, LogonItems.json, process_info.json, LastActivity.json,
    Defender.json, PowerShell.json, Services.json, TaskSchedule.json, Smb.json, network_connections.json 等。
    """
    results: list[dict[str, Any]] = []
    comp_name = (snapshot_meta or {}).get("hostname") or "WIN-HOST"

    # 1. SystemInformation.json：提取主机名、OS 版本
    if "SystemInformation" in loaded and isinstance(loaded["SystemInformation"], list):
        for info in loaded["SystemInformation"]:
            if not isinstance(info, dict):
                continue
            cname = info.get("ComputerName")
            os_ver = info.get("OSVersion")
            if snapshot_meta is not None:
                if cname:
                    snapshot_meta["hostname"] = str(cname).strip()
                    comp_name = snapshot_meta["hostname"]
                if os_ver:
                    snapshot_meta["os_version"] = f"Windows ({os_ver})"
        return results

    # 2. network_connections.json：自动提取受检主机内网 IP
    if "NetworkConnections" in loaded and isinstance(loaded["NetworkConnections"], list):
        for conn in loaded["NetworkConnections"]:
            if not isinstance(conn, dict):
                continue
            la = str(conn.get("LocalAddress") or "").strip()
            if la and la not in ("0.0.0.0", "127.0.0.1", "::", "::1") and not la.startswith("169.254."):
                if snapshot_meta is not None and not snapshot_meta.get("ip_address"):
                    snapshot_meta["ip_address"] = la
                break
        return results

    # 3. LogonItems.json：注册表 Run / 启动项持久化检测（精准捕获 C:\ProgramData\Synaptics\Synaptics.exe "怪兽" 蠕虫等）
    if "LogonItems" in loaded and isinstance(loaded["LogonItems"], list):
        for item in loaded["LogonItems"]:
            if not isinstance(item, dict):
                continue
            entry = str(item.get("Entry") or "").strip()
            loc = str(item.get("Entry Location") or "").strip()
            img_path = str(item.get("Image Path") or item.get("Launch String") or "").strip()
            company = str(item.get("Company") or "").strip()
            file_hidden = bool(item.get("FileHidden"))
            md5_val = str(item.get("MD5") or "").strip()
            sha256_val = str(item.get("SHA-256") or "").strip()
            t_str = str(item.get("FileCreatedTime") or item.get("Time") or "").strip()
            ev_time = _parse_event_time(t_str) or datetime.utcnow()

            if not img_path or entry.lower() == "desktop.ini":
                continue

            img_lower = img_path.lower()
            is_synaptics_worm = "programdata\\synaptics\\synaptics.exe" in img_lower or company == "怪兽" or entry == "怪兽"
            is_suspicious_path = any(
                p in img_lower
                for p in ("c:\\programdata\\", "users\\public", "appdata\\local\\temp", "\\temp\\", "wscript", "mshta", "powershell")
            )

            if is_synaptics_worm or is_suspicious_path or file_hidden:
                risk_level = "critical" if (is_synaptics_worm or file_hidden) else "high"
                tags = ["T1547.001", "注册表Run启动项持久化"]
                if is_synaptics_worm:
                    tags.extend(["Win32.Worm.Synaptics蠕虫木马", "伪装Synaptics驱动签名(怪兽)", "隐藏文件属性驻留"])
                elif file_hidden:
                    tags.append("隐藏文件属性自启动")

                summary = (
                    f"[注册表自启动后门] 启动项名: {entry} (厂商: {company or '未知'}), "
                    f"路径: {img_path}, 注册表位置: {loc}, 隐藏属性: {file_hidden}, MD5: {md5_val}"
                )
                ev_dict: dict[str, Any] = {
                    "artifact_type": "evtx_service",
                    "source_file": source_name,
                    "event_id": 7045,
                    "event_time": ev_time,
                    "summary": summary,
                    "parsed_data": {
                        "Computer": comp_name,
                        "ServiceName": f"RunKey:{entry}",
                        "ImagePath": img_path,
                        "EntryLocation": loc,
                        "Company": company,
                        "FileHidden": file_hidden,
                        "MD5": md5_val,
                        "SHA256": sha256_val,
                        "CommandLine": f'reg add "{loc}" /v "{entry}" /d "{img_path}"',
                    },
                    "raw_data": json.dumps(item, ensure_ascii=False),
                    "risk_level": risk_level,
                    "risk_tags": tags,
                    "is_malicious": True,
                }
                if sha256_val or md5_val:
                    ev_dict["extracted_ioc"] = {
                        "ioc_type": "hash",
                        "ioc_value": sha256_val or md5_val,
                        "threat_level": "malicious",
                        "tags": ["Win32.Worm.Synaptics", "Autorun_Persistence_Binary", f"MD5:{md5_val}"],
                    }
                results.append(ev_dict)
        return results

    # 4. process_info.json：活跃进程树排查
    if "ProcessInfo" in loaded and isinstance(loaded["ProcessInfo"], list):
        for proc in loaded["ProcessInfo"]:
            if not isinstance(proc, dict):
                continue
            pname = str(proc.get("Name") or "").strip()
            ppath = str(proc.get("Path") or "").strip()
            cmd = str(proc.get("CommandLine") or ppath).strip()
            pid = proc.get("PID")
            ppid = proc.get("PPID")
            parent = str(proc.get("Parent") or "").strip()
            md5_val = str(proc.get("MD5") or "").strip()
            ev_time = _parse_event_time(str(proc.get("Time") or "")) or datetime.utcnow()

            if not ppath and not cmd:
                continue

            path_lower = ppath.lower()
            is_synaptics_worm = "programdata\\synaptics\\synaptics.exe" in path_lower
            is_programdata_proc = path_lower.startswith("c:\\programdata\\") and not is_synaptics_worm
            matched_rules = [r for r in SUSPICIOUS_CMD_RULES if r[0].search(f"{ppath} {cmd}")]

            if is_synaptics_worm or matched_rules or is_programdata_proc:
                if is_synaptics_worm:
                    risk_level = "critical"
                    tags = ["T1036.005", "T1204.002", "活跃恶意进程驻留(Synaptics蠕虫)", "PE感染型木马进程"]
                    is_mal = True
                elif matched_rules:
                    risk_level = "critical" if any(r[3] == "critical" for r in matched_rules) else "high"
                    tags = list({r[1] for r in matched_rules} | {r[2] for r in matched_rules})
                    is_mal = True
                else:
                    risk_level = "medium"
                    tags = ["ProgramData非标准目录驻留进程"]
                    is_mal = False

                summary = (
                    f"[活跃进程审计] 进程: {pname} (PID: {pid}, PPID: {ppid} {parent}), "
                    f"路径: {ppath}, 命令行: {cmd[:180]}, MD5: {md5_val}"
                )
                ev_dict = {
                    "artifact_type": "evtx_process",
                    "source_file": source_name,
                    "event_id": 4688,
                    "event_time": ev_time,
                    "summary": summary,
                    "parsed_data": {
                        "Computer": comp_name,
                        "NewProcessName": ppath or pname,
                        "NewProcessId": str(pid or ""),
                        "ParentProcessId": str(ppid or ""),
                        "ParentProcessName": parent,
                        "CommandLine": cmd,
                        "MD5": md5_val,
                    },
                    "raw_data": json.dumps(proc, ensure_ascii=False),
                    "risk_level": risk_level,
                    "risk_tags": tags,
                    "is_malicious": is_mal,
                }
                if is_synaptics_worm and md5_val:
                    ev_dict["extracted_ioc"] = {
                        "ioc_type": "hash",
                        "ioc_value": md5_val.upper(),
                        "threat_level": "malicious",
                        "tags": ["Win32.Worm.Synaptics_MD5", "Active_Malware_Process"],
                    }
                results.append(ev_dict)
        return results

    # 5. LastActivity.json：Prefetch / UserAssist / Amcache 历史执行痕迹还原
    if "LastActivity" in loaded and isinstance(loaded["LastActivity"], list):
        seen_exec: set[str] = set()
        for act in loaded["LastActivity"]:
            if not isinstance(act, dict):
                continue
            action_type = str(act.get("Action") or "").strip()
            fname = str(act.get("FileName") or "").strip().replace("\x00", "")
            fpath = str(act.get("FilePath") or act.get("TargetPath") or "").strip().replace("\x00", "")
            comment = str(act.get("Comment") or "").strip().replace("\x00", "")
            t_str = str(act.get("Time") or "").strip()
            ev_time = _parse_event_time(t_str)

            fp_lower = fpath.lower()
            fn_lower = fname.lower()

            is_worm_cache = fn_lower.startswith("._cache_") or "\\._cache_" in fp_lower
            is_synaptics_exec = "programdata\\synaptics\\synaptics.exe" in fp_lower
            is_crack_carrier = any(
                k in fp_lower for k in ("xf-adsk", "patchxtract", "crackxtract", "dxf2xtract.exe")
            ) and action_type in ("Run executable file", "User assist", "用户打开应用程序")

            if is_worm_cache or is_synaptics_exec or is_crack_carrier:
                dedup_key = f"{t_str}:{fn_lower}:{fp_lower}"
                if dedup_key in seen_exec:
                    continue
                seen_exec.add(dedup_key)

                if is_synaptics_exec:
                    risk_level = "critical"
                    tags = ["T1036.005", "Synaptics蠕虫母体执行(Prefetch)", "恶意程序落地运行"]
                    summary = f"[恶意程序执行痕迹] 蠕虫母体 {fpath} 被触发运行 ({action_type}: {comment})"
                    is_mal = True
                elif is_worm_cache:
                    risk_level = "critical"
                    tags = ["T1204.002", "T1036.005", "._cache_感染型蠕虫释放原程序痕迹", "PE文件感染实锤"]
                    summary = (
                        f"[PE感染型蠕虫活动实锤] 检出蠕虫隐藏宿主缓存程序执行: {fname} "
                        f"(路径: {fpath}, 来源: {comment}) —— 证明原可执行文件已被 Synaptics(怪兽) 蠕虫感染寄生！"
                    )
                    is_mal = True
                else:
                    risk_level = "high"
                    tags = ["T1204.002", "疑似带毒破解工具/注册机初始投递源"]
                    summary = f"[带毒载体执行记录] 用户运行了疑似携带蠕虫的破解补丁/工程工具: {fname} (路径: {fpath})"
                    is_mal = True

                results.append(
                    {
                        "artifact_type": "evtx_process",
                        "source_file": source_name,
                        "event_id": 4688,
                        "event_time": ev_time,
                        "summary": summary,
                        "parsed_data": {
                            "Computer": comp_name,
                            "NewProcessName": fpath or fname,
                            "ParentProcessName": "explorer.exe (UserExecution)",
                            "CommandLine": fpath or fname,
                            "ActionType": action_type,
                            "ForensicSource": comment,
                        },
                        "raw_data": json.dumps(act, ensure_ascii=False).replace("\x00", ""),
                        "risk_level": risk_level,
                        "risk_tags": tags,
                        "is_malicious": is_mal,
                    }
                )
        return results

    # 6. Defender.json：Windows Defender 实时保护关闭与告警日志
    if "Defender" in loaded and isinstance(loaded["Defender"], list):
        for d in loaded["Defender"]:
            if not isinstance(d, dict):
                continue
            eid_str = str(d.get("EventId") or "5001")
            dtype = str(d.get("Type") or "")
            desc = str(d.get("Description") or "")
            t_str = str(d.get("Time") or "")
            ev_time = _parse_event_time(t_str)
            cname = str(d.get("Computer") or comp_name)
            risk_level = "high" if eid_str in ("5001", "1116", "1117") else "medium"
            tags = ["T1562.001", f"Defender_{dtype or eid_str}", "削弱安全防御/关闭实时保护"]

            results.append(
                {
                    "artifact_type": "evtx_process",
                    "source_file": source_name,
                    "event_id": 4688,
                    "event_time": ev_time,
                    "summary": f"[Windows Defender 安全告警 Event {eid_str}] {dtype}: {desc}",
                    "parsed_data": {
                        "Computer": cname,
                        "NewProcessName": "MsMpEng.exe (Windows Defender)",
                        "CommandLine": f"Defender Event {eid_str} ({dtype}): {desc}",
                        "DefenderData": d.get("Data"),
                    },
                    "raw_data": json.dumps(d, ensure_ascii=False),
                    "risk_level": risk_level,
                    "risk_tags": tags,
                    "is_malicious": risk_level == "high",
                }
            )
        return results

    # 7. Smb.json：本机对外发起的 SMB 认证失败 / 连接异常聚合
    if "Smb" in loaded and isinstance(loaded["Smb"], list):
        peer_Map: dict[str, dict[str, Any]] = {}
        for s in loaded["Smb"]:
            if not isinstance(s, dict):
                continue
            peer = str(s.get("PeerName") or s.get("PeerAddress") or s.get("PrincipalName") or "").strip().lstrip("\\")
            if not peer:
                continue
            if peer not in peer_Map:
                peer_Map[peer] = {
                    "count": 0,
                    "first_time": s.get("Time"),
                    "last_time": s.get("Time"),
                    "types": set(),
                    "sample": s,
                }
            peer_Map[peer]["count"] += 1
            peer_Map[peer]["last_time"] = s.get("Time")
            peer_Map[peer]["types"].add(str(s.get("Type") or s.get("EventId") or ""))

        for peer, info in peer_Map.items():
            cnt = info["count"]
            types_str = ", ".join(sorted(info["types"]))
            is_auth_fail = "SessionSetupFailed" in types_str
            risk_level = "high" if is_auth_fail else "medium"
            ev_time = _parse_event_time(str(info["last_time"] or info["first_time"] or ""))
            results.append(
                {
                    "artifact_type": "evtx_logon",
                    "source_file": source_name,
                    "event_id": 4625,
                    "event_time": ev_time,
                    "summary": (
                        f"[SMB 异常连接/认证审计] 本机向内网节点 {peer} 发起 SMB 通信失败共 {cnt} 次 "
                        f"(类型: {types_str}) —— 需排查蠕虫局域网共享感染探测或凭据协商异常"
                    ),
                    "parsed_data": {
                        "Computer": comp_name,
                        "IpAddress": peer,
                        "TargetUserName": "SMB_Client_Session",
                        "LogonType": "3",
                        "LogonTypeDesc": f"SMB ({types_str})",
                        "FailureCount": cnt,
                    },
                    "raw_data": json.dumps(info["sample"], ensure_ascii=False),
                    "risk_level": risk_level,
                    "risk_tags": ["T1021.002", "SMB共享连接异常", f"累计失败{cnt}次"],
                    "is_malicious": is_auth_fail,
                }
            )
        return results

    # 8. PowerShell.json：提取可疑 Bypass / Hidden / Temp 脚本执行记录（去重防刷屏）
    if "PowerShell" in loaded and isinstance(loaded["PowerShell"], list):
        seen_ps: set[str] = set()
        for ps in loaded["PowerShell"]:
            if not isinstance(ps, dict):
                continue
            host_app = str(ps.get("HostApplication") or "").strip()
            script_blk = str(ps.get("ScriptBlock") or "").strip()
            combined = f"{host_app} {script_blk}".strip()
            if not combined:
                continue
            if not re.search(r"(bypass|hidden|-enc|frombase64|downloadstring|temp\\|new-eventlog|remove-appxpackage)", combined, re.I):
                continue
            norm_key = re.sub(r"probe\d+_\d+", "probe_PID_RAND", combined)
            if norm_key in seen_ps:
                continue
            seen_ps.add(norm_key)

            ev_time = _parse_event_time(str(ps.get("Time") or ""))
            is_high = bool(re.search(r"(-enc|frombase64|downloadstring|iex\b)", combined, re.I))
            results.append(
                {
                    "artifact_type": "evtx_process",
                    "source_file": source_name,
                    "event_id": 4688,
                    "event_time": ev_time,
                    "summary": f"[PowerShell 脚本审计] {combined[:220]}",
                    "parsed_data": {
                        "Computer": comp_name,
                        "NewProcessName": "powershell.exe",
                        "CommandLine": combined,
                    },
                    "raw_data": json.dumps(ps, ensure_ascii=False),
                    "risk_level": "high" if is_high else "medium",
                    "risk_tags": ["T1059.001", "PowerShell_ExecutionPolicy_Bypass"],
                    "is_malicious": is_high,
                }
            )
        return results

    return results


def _parse_linux_snapshot_json(
    source_name: str,
    loaded: dict[str, Any],
    snapshot_meta: Optional[dict[str, Any]] = None,
) -> list[dict[str, Any]]:
    """
    深度解析 `linux_collector.sh` 生成的 `linux_snapshot.json` 抗命令篡改取证包：
    1. 校验被篡改的系统命令 (`tampered_binaries`: RPM/DPKG 哈希失配、非 ELF 脚本调包、Inode ctime!=mtime 时间戳伪造)
    2. 识别 `/proc` 隐藏进程 (`hidden_from_ps`)、已删除无文件木马 (`(deleted)`)、LD_PRELOAD 环境变量劫持
    3. 识别 `/proc/net/tcp` 异常外连与 C2 通信
    4. 识别 12 大持久化后门 (`ld.so.preload`、Cron、Systemd、Shell Profile、UID=0 克隆账户、SSH 公钥) 与 `lsattr +i/+a` 防删锁
    """
    results: list[dict[str, Any]] = []
    comp_name = str(loaded.get("hostname") or "LINUX-SERVER").strip()
    ip_addr = str(loaded.get("ip_address") or "").strip()
    os_ver = str(loaded.get("os_version") or "Linux Server").strip()
    snap_time = _parse_event_time(str(loaded.get("collected_at") or "")) or datetime.utcnow()

    if snapshot_meta is not None:
        if comp_name:
            snapshot_meta["hostname"] = comp_name
        if ip_addr:
            snapshot_meta["ip_address"] = ip_addr
        if os_ver:
            snapshot_meta["os_version"] = os_ver

    # 1. 被篡改的 Linux 系统命令与时间戳伪造 (tampered_binaries)
    for tb in loaded.get("tampered_binaries") or []:
        if not isinstance(tb, dict):
            continue
        bpath = str(tb.get("path") or "").strip()
        vstatus = str(tb.get("verify_status") or "HASH_MISMATCH").strip()
        ctime_s = str(tb.get("ctime") or "").strip()
        mtime_s = str(tb.get("mtime") or "").strip()
        sha256_s = str(tb.get("sha256") or "").strip()
        timestomped = bool(tb.get("timestomped"))
        ev_time = _parse_event_time(ctime_s) or snap_time

        tags = ["T1014", "T1036.005", "Linux系统命令被篡改(Rootkit)", vstatus]
        if timestomped:
            tags.append("T1070.006_时间戳伪造(ctime与mtime背离)")

        summary = (
            f"[Linux 系统命令篡改实锤] 核心命令 {bpath} 校验异常 ({vstatus})！"
            f"真实 Inode 变更时间(ctime): {ctime_s} vs 表面修改时间(mtime): {mtime_s}, SHA256: {sha256_s[:32]}..."
        )
        ev_dict: dict[str, Any] = {
            "artifact_type": "linux_rootkit_binary",
            "source_file": source_name,
            "event_id": 7045,
            "event_time": ev_time,
            "summary": summary,
            "parsed_data": {
                "Computer": comp_name,
                "ServiceName": f"TamperedBinary:{bpath}",
                "ImagePath": bpath,
                "VerifyStatus": vstatus,
                "InodeCtime": ctime_s,
                "ForgedMtime": mtime_s,
                "Timestomped": timestomped,
                "SHA256": sha256_s,
                "CommandLine": f"rpm -Vf {bpath} -> {vstatus} (ctime={ctime_s}, mtime={mtime_s})",
            },
            "raw_data": json.dumps(tb, ensure_ascii=False),
            "risk_level": "critical",
            "risk_tags": tags,
            "is_malicious": True,
        }
        if sha256_s:
            ev_dict["extracted_ioc"] = {
                "ioc_type": "hash",
                "ioc_value": sha256_s,
                "threat_level": "malicious",
                "tags": ["Linux_Trojanized_Binary", bpath],
            }
        results.append(ev_dict)

    # 2. 12 大持久化后门与 /etc/ld.so.preload 劫持 (persistence_items)
    for item in loaded.get("persistence_items") or []:
        if not isinstance(item, dict):
            continue
        cat = str(item.get("category") or "linux_persistence")
        ppath = str(item.get("path") or "")
        content = str(item.get("content") or "")
        ctime_s = str(item.get("ctime") or "")
        mtime_s = str(item.get("mtime") or "")
        sev = str(item.get("severity") or "critical")
        ev_time = _parse_event_time(ctime_s) or snap_time

        eid = 4720 if cat == "uid0_clone_user" else 7045
        tags = ["T1053.003", f"Linux持久化_{cat}"]
        if cat == "ld_so_preload_rootkit":
            tags = ["T1574.006", "ld.so.preload动态库劫持Rootkit", "全局隐藏进程与端口"]

        summary = f"[Linux 持久化后门: {cat}] 路径: {ppath} | 内容: {content} (Inode ctime: {ctime_s})"
        results.append(
            {
                "artifact_type": "linux_persistence",
                "source_file": source_name,
                "event_id": eid,
                "event_time": ev_time,
                "summary": summary,
                "parsed_data": {
                    "Computer": comp_name,
                    "ServiceName": f"{cat}:{ppath}",
                    "ImagePath": ppath,
                    "CommandLine": content,
                    "TargetUserName": content.split(":")[0] if eid == 4720 else "root",
                    "InodeCtime": ctime_s,
                    "ForgedMtime": mtime_s,
                },
                "raw_data": json.dumps(item, ensure_ascii=False),
                "risk_level": sev if sev in ("critical", "high", "medium") else "critical",
                "risk_tags": tags,
                "is_malicious": True,
            }
        )

    # 3. lsattr +i / +a 不可变防删锁检测 (immutable_files)
    for im in loaded.get("immutable_files") or []:
        if not isinstance(im, dict):
            continue
        fpath = str(im.get("path") or "")
        attr = str(im.get("attributes") or "")
        results.append(
            {
                "artifact_type": "linux_immutable_lock",
                "source_file": source_name,
                "event_id": 7045,
                "event_time": snap_time,
                "summary": f"[chattr 防删锁告警] 文件 {fpath} 被恶意添加不可变属性 ({attr})，导致 root 无法直接修改或清除！",
                "parsed_data": {
                    "Computer": comp_name,
                    "ServiceName": f"ImmutableLock:{fpath}",
                    "ImagePath": fpath,
                    "Attributes": attr,
                    "CommandLine": f"chattr +i {fpath} (lsattr: {attr})",
                },
                "raw_data": json.dumps(im, ensure_ascii=False),
                "risk_level": "critical",
                "risk_tags": ["T1222.002", "chattr_+i_防删锁", "顽固木马防清除机制"],
                "is_malicious": True,
            }
        )

    # 4. /proc 内核直读隐藏进程、无文件 deleted 进程与异常守护进程 (processes)
    for proc in loaded.get("processes") or []:
        if not isinstance(proc, dict):
            continue
        pid = proc.get("pid")
        ppid = proc.get("ppid")
        comm = str(proc.get("comm") or "")
        exe = str(proc.get("exe") or "")
        cmd = str(proc.get("cmdline") or "")
        hidden = bool(proc.get("hidden_from_ps"))
        deleted = bool(proc.get("is_deleted_binary"))
        ld_pre = str(proc.get("ld_preload") or "")
        st_time = _parse_event_time(str(proc.get("start_time") or "")) or snap_time

        combined = f"{comm} {exe} {cmd} {ld_pre}".lower()
        is_susp_linux = any(
            k in combined
            for k in ("/tmp/", "/dev/shm/", "/var/tmp/", "/dev/tcp/", "xmrig", "kdevtmpfsi", "kinsing", "cryptonight", "stratum+tcp", "base64 -d", "curl ", "wget ")
        )
        if hidden or deleted or ld_pre or is_susp_linux:
            tags = ["T1059.004"]
            if hidden:
                tags.append("T1014_Rootkit隐藏进程(ps不可见但/proc存在)")
            if deleted:
                tags.append("T1070.004_无文件内存驻留(二进制已删除deleted)")
            if ld_pre:
                tags.append("T1574.006_LD_PRELOAD进程注入")
            if is_susp_linux:
                tags.append("Linux恶意载荷/挖矿或远控守护进程")

            summary = (
                f"[/proc 内核直读异常进程] PID: {pid} (PPID: {ppid}), 进程名: {comm}, "
                f"真实路径: {exe or '无'}, 隐藏于ps: {hidden}, 已删文件: {deleted}, 命令行: {cmd}"
            )
            results.append(
                {
                    "artifact_type": "linux_proc_process",
                    "source_file": source_name,
                    "event_id": 4688,
                    "event_time": st_time,
                    "summary": summary,
                    "parsed_data": {
                        "Computer": comp_name,
                        "NewProcessName": exe or comm,
                        "NewProcessId": str(pid or ""),
                        "ParentProcessId": str(ppid or ""),
                        "CommandLine": cmd,
                        "HiddenFromPs": hidden,
                        "DeletedBinary": deleted,
                        "LD_PRELOAD": ld_pre,
                    },
                    "raw_data": json.dumps(proc, ensure_ascii=False),
                    "risk_level": "critical" if (hidden or deleted or is_susp_linux) else "high",
                    "risk_tags": tags,
                    "is_malicious": True,
                }
            )

    # 5. /proc/net/tcp 异常外连与 C2 通信 (network_connections)
    for conn in loaded.get("network_connections") or []:
        if not isinstance(conn, dict):
            continue
        rip = str(conn.get("remote_ip") or "")
        rport = conn.get("remote_port")
        state = str(conn.get("state") or "")
        pid = conn.get("pid")
        comm = str(conn.get("comm") or "")
        exe = str(conn.get("exe") or "")
        cmd = str(conn.get("cmdline") or "")
        if rip in ("0.0.0.0", "127.0.0.1", "::", "::1", "") or state == "LISTEN":
            continue
        is_susp_conn = any(
            k in f"{comm} {exe} {cmd}".lower()
            for k in ("(deleted)", "/tmp/", "/dev/shm", "xmrig", "kdevtmpfsi", "kinsing", "bash", "sh", "python", "nc", "curl")
        ) or rport in (3333, 4444, 5555, 6666, 7777, 8888, 9999, 14444)
        if is_susp_conn:
            ev_dict = {
                "artifact_type": "linux_proc_net",
                "source_file": source_name,
                "event_id": 4624,
                "event_time": snap_time,
                "summary": (
                    f"[/proc/net/tcp 隐藏外连捕获] 进程 {comm} (PID: {pid}, 路径: {exe}) "
                    f"正在连接外部地址 {rip}:{rport} (状态: {state})"
                ),
                "parsed_data": {
                    "Computer": comp_name,
                    "IpAddress": rip,
                    "RemotePort": rport,
                    "ProcessName": comm,
                    "PID": pid,
                    "ImagePath": exe,
                    "CommandLine": cmd,
                    "LogonType": "3",
                    "LogonTypeDesc": f"TCP_{state}_C2",
                    "TargetUserName": "root",
                },
                "raw_data": json.dumps(conn, ensure_ascii=False),
                "risk_level": "critical",
                "risk_tags": ["T1071", "Linux_C2_或矿池外连(/proc/net/tcp)"],
                "is_malicious": True,
                "extracted_ioc": {
                    "ioc_type": "ip",
                    "ioc_value": rip,
                    "threat_level": "malicious",
                    "tags": ["Linux_C2_or_MiningPool", f"Port:{rport}", f"Proc:{comm}"],
                },
            }
            results.append(ev_dict)

    return results


def _parse_exported_json_or_xml(
    file_path: Path,
    snapshot_meta: Optional[dict[str, Any]] = None,
) -> list[dict[str, Any]]:
    """
    兼容解析采集包中导出的 JSON / JSONL / XML 格式事件快照
    """
    results: list[dict[str, Any]] = []
    suffix = file_path.suffix.lower()
    source_name = file_path.name

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore").strip()
        if not content:
            return results

        if suffix == ".xml" and "<Event" in content:
            # 支持包含多个 <Event>...</Event> 节点的 XML 导出文件
            event_blocks = re.findall(r"<Event\b.*?</Event>", content, flags=re.DOTALL)
            for xml_block in event_blocks:
                parsed = _parse_xml_record(xml_block, source_name)
                if parsed:
                    results.append(parsed)

        elif suffix in (".json", ".jsonl"):
            records: list[dict[str, Any]] = []
            if suffix == ".jsonl":
                for line in content.splitlines():
                    if line.strip():
                        records.append(json.loads(line))
            else:
                loaded = json.loads(content)
                if isinstance(loaded, list):
                    records = [r for r in loaded if isinstance(r, dict)]
                elif isinstance(loaded, dict):
                    # 1. 优先检测是否为 Linux 抗篡改采集包 (linux_snapshot.json)
                    if loaded.get("os_family") == "linux" or "tampered_binaries" in loaded:
                        return _parse_linux_snapshot_json(source_name, loaded, snapshot_meta)
                    # 2. 检测是否为第三方采集器 (WindowsCollecter / Get-Logs-Tool) 结构化 JSON
                    thirdparty_keys = {
                        "SystemInformation",
                        "LogonItems",
                        "ProcessInfo",
                        "LastActivity",
                        "Defender",
                        "Smb",
                        "PowerShell",
                        "NetworkConnections",
                    }
                    if any(k in loaded for k in thirdparty_keys):
                        return _parse_thirdparty_collector_json(source_name, loaded, snapshot_meta)
                    # 兼容采集器生成的 system_snapshot.json 结构
                    if "processes" in loaded or "network_connections" in loaded or "hostname" in loaded:
                        snap_host = loaded.get("hostname") or loaded.get("Hostname") or "UNKNOWN-HOST"
                        snap_time = _parse_event_time(loaded.get("collected_at")) or datetime.utcnow()
                        for proc in loaded.get("processes", []):
                            cmd = str(proc.get("command_line") or "")
                            pname = str(proc.get("name") or proc.get("executable") or "")
                            if not cmd and not pname:
                                continue
                            # 仅将命中可疑特征的实时进程转为 4688 伪影事件
                            if any(r[0].search(f"{pname} {cmd}") for r in SUSPICIOUS_CMD_RULES):
                                ev_p = _evaluate_security_event(
                                    event_id=4688,
                                    event_time=snap_time,
                                    computer_name=snap_host,
                                    channel="LiveSnapshot/Process",
                                    provider_name="WinDFIR-Collector",
                                    data_map={
                                        "NewProcessName": str(proc.get("executable") or pname),
                                        "NewProcessId": str(proc.get("pid") or ""),
                                        "ProcessId": str(proc.get("ppid") or ""),
                                        "CommandLine": cmd,
                                        "SubjectUserName": str(proc.get("username") or "SYSTEM"),
                                    },
                                    raw_xml=json.dumps(proc, ensure_ascii=False),
                                    source_file=source_name,
                                )
                                if ev_p:
                                    results.append(ev_p)
                        return results
                    records = [loaded]

            for item in records:
                raw_eid = item.get("EventID") or item.get("event_id")
                if isinstance(raw_eid, dict):
                    raw_eid = raw_eid.get("#text") or raw_eid.get("Value")
                try:
                    eid = int(raw_eid)
                except (TypeError, ValueError):
                    continue
                if eid not in TARGET_EVENT_IDS:
                    continue

                time_str = (
                    item.get("TimeCreated")
                    or item.get("SystemTime")
                    or item.get("event_time")
                    or item.get("@timestamp")
                )
                event_data = item.get("EventData") or item.get("event_data") or item
                data_map = {str(k): str(v) for k, v in event_data.items() if v is not None}

                parsed = _evaluate_security_event(
                    event_id=eid,
                    event_time=_parse_event_time(str(time_str)) if time_str else None,
                    computer_name=item.get("Computer") or item.get("Hostname"),
                    channel=item.get("Channel", "ExportedJSON"),
                    provider_name=item.get("Provider", "JSONSnapshot"),
                    data_map=data_map,
                    raw_xml=json.dumps(item, ensure_ascii=False),
                    source_file=source_name,
                )
                if parsed:
                    results.append(parsed)
    except Exception as exc:
        logger.warning(f"跳过非标准格式快照文件 [{source_name}]: {exc}")

    return results


def _extract_and_parse_archive_sync(archive_path_str: str) -> dict[str, Any]:
    """
    在工作线程中执行同步解压与 EVTX 遍历解析，避免阻塞 FastAPI 主事件循环
    """
    path_obj = Path(archive_path_str)
    if not path_obj.exists():
        raise EvtxParseError(f"指定的采集包或日志路径不存在: {archive_path_str}")

    all_events: list[dict[str, Any]] = []
    parsed_files: list[str] = []
    parse_errors: list[str] = []
    snapshot_meta: dict[str, Any] = {}

    def _try_read_snapshot_meta(fpath: Path) -> None:
        if fpath.name.lower() == "system_snapshot.json":
            try:
                data = json.loads(fpath.read_text(encoding="utf-8", errors="ignore"))
                if isinstance(data, dict):
                    snapshot_meta.update({
                        "hostname": data.get("hostname") or data.get("Hostname"),
                        "ip_address": data.get("ip_address") or data.get("IPAddress"),
                        "os_version": data.get("os_version") or data.get("OSVersion"),
                    })
                    if fpath.name not in parsed_files:
                        parsed_files.append(fpath.name)
            except Exception:
                pass

    # 若直接传入单个 .evtx 文件也兼容处理
    if path_obj.is_file() and path_obj.suffix.lower() == ".evtx":
        events = _parse_single_evtx_file(path_obj)
        all_events.extend(events)
        parsed_files.append(path_obj.name)
    elif path_obj.is_file() and path_obj.suffix.lower() == ".zip":
        with tempfile.TemporaryDirectory(prefix="windfir_extract_") as tmp_dir:
            extracted_paths = _safe_extract_zip(path_obj, Path(tmp_dir))
            # 优先解析 SystemInformation.json / network_connections.json / system_snapshot.json 获取真实主机名与内网 IP
            extracted_paths.sort(
                key=lambda p: (
                    0
                    if p.name.lower() in ("systeminformation.json", "network_connections.json", "system_snapshot.json")
                    else 1,
                    p.name.lower(),
                )
            )
            for fpath in extracted_paths:
                ext = fpath.suffix.lower()
                if ext == ".evtx":
                    try:
                        events = _parse_single_evtx_file(fpath)
                        all_events.extend(events)
                        parsed_files.append(fpath.name)
                    except EvtxParseError as err:
                        parse_errors.append(str(err))
                elif ext in (".xml", ".json", ".jsonl"):
                    _try_read_snapshot_meta(fpath)
                    events = _parse_exported_json_or_xml(fpath, snapshot_meta)
                    if events or fpath.name.lower() in ("systeminformation.json", "network_connections.json"):
                        all_events.extend(events)
                        if fpath.name not in parsed_files:
                            parsed_files.append(fpath.name)
    elif path_obj.is_dir():
        # 支持直接指定包含 .evtx 的解压目录
        for fpath in path_obj.rglob("*"):
            if not fpath.is_file():
                continue
            ext = fpath.suffix.lower()
            if ext == ".evtx":
                try:
                    events = _parse_single_evtx_file(fpath)
                    all_events.extend(events)
                    parsed_files.append(fpath.name)
                except EvtxParseError as err:
                    parse_errors.append(str(err))
            elif ext in (".xml", ".json", ".jsonl"):
                events = _parse_exported_json_or_xml(fpath)
                if events:
                    all_events.extend(events)
                    parsed_files.append(fpath.name)
    else:
        raise EvtxParseError(f"不支持的采集包文件格式: {path_obj.suffix}，请上传 .zip 或 .evtx 文件")

    if not parsed_files and parse_errors:
        raise EvtxParseError("; ".join(parse_errors))

    return {
        "events": all_events,
        "parsed_files": parsed_files,
        "parse_errors": parse_errors,
        "snapshot_meta": snapshot_meta,
    }


def _calculate_host_risk(events: list[dict[str, Any]]) -> tuple[int, str, str]:
    """
    根据提取到的高危事件列表计算主机综合风险评分 (0-100)、风险等级及失陷摘要
    """
    if not events:
        return 0, "low", "未在日志中检出目标高危安全事件 (EventID: 4624/4625/4688/7045/4720)。"

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    event_id_stats: dict[int, int] = {}

    for ev in events:
        lvl = ev.get("risk_level", "low")
        counts[lvl] = counts.get(lvl, 0) + 1
        eid = ev.get("event_id", 0)
        event_id_stats[eid] = event_id_stats.get(eid, 0) + 1

    # 仅统计远程/高危 4625 登录失败次数用于暴力破解加权
    remote_4625_count = sum(
        1 for ev in events if ev.get("event_id") == 4625 and ev.get("risk_level") in ("high", "critical")
    )
    brute_force_bonus = 25 if remote_4625_count >= 5 else 0

    score = min(
        100,
        counts["critical"] * 35
        + counts["high"] * 15
        + counts["medium"] * 5
        + min(5, counts["low"])
        + brute_force_bonus,
    )

    if counts["critical"] > 0 or score >= 80:
        risk_level = "critical"
    elif counts["high"] > 0 or score >= 50:
        risk_level = "high"
    elif counts["medium"] > 0 or score >= 20:
        risk_level = "medium"
    else:
        risk_level = "low"

    summary = (
        f"共提取关键事件 {len(events)} 条 "
        f"(严重: {counts['critical']}, 高危: {counts['high']}, 中危: {counts['medium']}, 低危: {counts['low']})。"
        f"按 EventID 分布: {json.dumps(event_id_stats, ensure_ascii=False)}"
    )
    return score, risk_level, summary


async def parse_host_evtx_archive(
    case_id: int,
    host_id: int,
    archive_path: str,
    db: Optional[AsyncSession] = None,
) -> dict[str, Any]:
    """
    核心异步解析入口函数：
    1. 更新主机状态为 parsing
    2. 在后台线程池中解压 .zip 采集包并提取 4624/4625/4688/7045/4720 事件
    3. 将提取出的事件批量入库到 `host_artifacts` 表，可疑 IOC 存入 `ioc_intelligence` 表
    4. 更新 `case_hosts` 表的风险等级、风险分值与解析摘要
    """
    own_session = False
    if db is None:
        db = AsyncSessionLocal()
        own_session = True

    try:
        host_obj = await db.get(CaseHost, host_id)
        if not host_obj:
            raise EvtxParseError(f"未找到 ID={host_id} 的涉案主机记录")

        host_obj.parse_status = "parsing"
        await db.commit()

        # 使用 asyncio.to_thread 将密集型解压和二进制 EVTX 解析卸载到线程池
        parse_result = await asyncio.to_thread(_extract_and_parse_archive_sync, archive_path)
        events: list[dict[str, Any]] = parse_result["events"]
        parsed_files: list[str] = parse_result["parsed_files"]
        snapshot_meta: dict[str, Any] = parse_result.get("snapshot_meta") or {}

        artifact_objects: list[HostArtifact] = []
        ioc_cache: dict[tuple[str, str], IOCIntelligence] = {}

        for ev in events:
            artifact_objects.append(
                HostArtifact(
                    case_id=case_id,
                    host_id=host_id,
                    artifact_type=ev["artifact_type"],
                    source_file=ev["source_file"],
                    event_id=ev["event_id"],
                    event_time=ev["event_time"],
                    summary=ev["summary"],
                    parsed_data=ev["parsed_data"],
                    raw_data=ev["raw_data"],
                    risk_level=ev["risk_level"],
                    risk_tags=ev["risk_tags"],
                    is_malicious=ev["is_malicious"],
                )
            )

            # 提取衍生 IOC 指标
            ioc_info = ev.get("extracted_ioc")
            if ioc_info and ioc_info.get("ioc_value"):
                key = (ioc_info["ioc_type"], ioc_info["ioc_value"])
                if key not in ioc_cache:
                    ioc_cache[key] = IOCIntelligence(
                        case_id=case_id,
                        host_id=host_id,
                        ioc_type=ioc_info["ioc_type"],
                        ioc_value=ioc_info["ioc_value"],
                        threat_level=ioc_info.get("threat_level", "suspicious"),
                        confidence=75 if ev["is_malicious"] else 50,
                        source=f"EVTX_Event_{ev['event_id']}",
                        tags=ioc_info.get("tags", []),
                        first_seen=ev["event_time"],
                        last_seen=ev["event_time"],
                    )
                else:
                    existing_ioc = ioc_cache[key]
                    if ev["event_time"]:
                        if not existing_ioc.last_seen or ev["event_time"] > existing_ioc.last_seen:
                            existing_ioc.last_seen = ev["event_time"]

        if artifact_objects:
            db.add_all(artifact_objects)
        if ioc_cache:
            db.add_all(list(ioc_cache.values()))

        # 计算主机综合风险并更新主机状态
        risk_score, risk_level, summary_text = _calculate_host_risk(events)

        # 若上传时未填写主机名或 IP，自动从 system_snapshot.json 或 EVTX <Computer> 字段中提取回填
        if not host_obj.hostname or host_obj.hostname in ("自动识别中...", "未知主机"):
            if snapshot_meta.get("hostname"):
                host_obj.hostname = str(snapshot_meta["hostname"]).strip()
            else:
                for ev in events:
                    comp = (ev.get("parsed_data") or {}).get("Computer")
                    if comp and str(comp).strip():
                        host_obj.hostname = str(comp).strip()
                        break
                else:
                    host_obj.hostname = f"WIN-HOST-{host_id}"

        if not host_obj.ip_address or not host_obj.ip_address.strip():
            if snapshot_meta.get("ip_address"):
                host_obj.ip_address = str(snapshot_meta["ip_address"]).strip()
            else:
                host_obj.ip_address = "自动识别 (内网受控节点)"

        if snapshot_meta.get("os_version") and (
            not host_obj.os_version or host_obj.os_version in ("Windows Server 2019", "Windows Server 2019 Datacenter")
        ):
            host_obj.os_version = str(snapshot_meta["os_version"]).strip()

        host_obj.parse_status = "completed"
        host_obj.risk_score = risk_score
        host_obj.risk_level = risk_level
        host_obj.compromise_summary = summary_text

        await db.commit()

        return {
            "host_id": host_id,
            "case_id": case_id,
            "hostname": host_obj.hostname,
            "ip_address": host_obj.ip_address,
            "parse_status": "completed",
            "parsed_files": parsed_files,
            "total_parsed_events": len(artifact_objects),
            "total_artifacts_saved": len(artifact_objects),
            "total_iocs_extracted": len(ioc_cache),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "summary": summary_text,
        }

    except Exception as exc:
        logger.exception(f"解析主机(host_id={host_id})日志采集包失败: {exc}")
        await db.rollback()
        try:
            host_obj = await db.get(CaseHost, host_id)
            if host_obj:
                host_obj.parse_status = "failed"
                host_obj.compromise_summary = f"日志解析失败: {str(exc)}"
                await db.commit()
        except Exception:
            pass
        raise EvtxParseError(str(exc)) from exc
    finally:
        if own_session:
            await db.close()
