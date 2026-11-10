"""
AI 大模型安全研判与攻击链还原服务 (services/ai_analyzer.py)
核心能力：
1. 自动解码 PowerShell Base64 (-enc / -EncodedCommand) 混淆指令，提取明文 Payload 及内嵌 URL/IP
2. 从 `llm_configs` 表（或环境变量）读取当前激活的大模型配置（支持 DeepSeek / OpenAI / Qwen / Ollama）
3. 对 `host_artifacts` 中的高危事件生成深度研判分析并写入 `ai_analysis` 字段
4. 串联全案时间线、涉案主机与 IOC 威胁情报，生成结构化 Markdown 应急响应报告并写入 `cases.ai_summary`
5. 提供无 API Key 时的本地 DFIR 专家推理兜底引擎，确保离线/未配 Key 环境下仍可完整跑通与演示
"""

import base64
import json
import logging
import os
import re
from typing import Any, Optional

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import Case, CaseHost, HostArtifact, IOCIntelligence, LLMConfig
from services.ti_service import enrich_case_iocs

logger = logging.getLogger("windfir.ai_analyzer")

# 默认 DFIR 应急响应专家系统提示词
DEFAULT_DFIR_SYSTEM_PROMPT = (
    "你是一位拥有 15 年实战经验的国家级 Windows 数字取证与应急响应 (DFIR) 首席专家。"
    "请基于提供的 Windows EVTX 高危事件记录、已解码的命令行载荷以及 IOC 威胁情报，"
    "精准还原黑客的完整攻击链路 (Kill Chain)，映射 MITRE ATT&CK 战术与技术编号，"
    "并结合客户所属行业场景（医院医疗卫健 / 政企集团内网 / 高校科研机构）的业务连续性红线，"
    "输出结构清晰、可直接交付给安全运营团队执行的 Markdown 格式应急响应研判报告。"
)

# 客户行业场景画像与差异化加固指导字典
INDUSTRY_PROFILES: dict[str, dict[str, Any]] = {
    "hospital": {
        "label": "医院/医疗卫健 (严禁中断HIS/核心业务，微隔离与防勒索优先)",
        "short_label": "🏥 医院/医疗卫健",
        "precautions_md": (
            "### 🏥 医疗卫健行业专属安全加固与业务连续性红线 (Hospital / Healthcare)\n"
            "1. **严禁盲目断网或重启 HIS/LIS/PACS 核心服务**：处置过程中严禁直接拔除核心数据库或挂号/医嘱中间件网线，不得直接 Kill `oracle.exe` / `sqlservr.exe` / `w3wp.exe(HIS业务池)`，防止造成门诊停摆或医疗事故。\n"
            "2. **主机级微隔离精准阻断**：优先采用 Windows 高级防火墙规则仅针对外部恶意 IP 及高危横向端口（445/135/3389）做双向阻断，放行院内诊疗业务端口白名单。\n"
            "3. **防勒索与卷影副本 (VSS) 紧急保护**：医疗行业系勒索软件头号目标，请立即核查卷影副本服务 (`vssadmin list shadows`) 状态，对患者电子病历 (EMR) 与 HIS 数据库执行离线冷备。"
        ),
    },
    "enterprise": {
        "label": "政企/集团内网 (重点保护AD域控、防横向渗透与商业机密泄露)",
        "short_label": "🏢 政企/集团内网",
        "precautions_md": (
            "### 🏢 政企/集团内网专属安全加固注意事项 (Enterprise / AD Domain)\n"
            "1. **AD 域控安全与黄金票据清理**：重点排查域控 `ntds.dit` 是否被卷影拷贝导出，立即审计域管账户变更记录，建议执行两次 `krbtgt` 账户密码重置以吊销潜在的 Kerberos 黄金票据 (Golden Ticket)。\n"
            "2. **阻断内网横向移动通道**：在办公网与核心生产网之间严格收敛 SMB (445)、RPC/WMI (135) 与 WinRM (5985/5986) 权限，启用 LAPS（本地管理员密码解决方案）防止哈希传递 (Pass-the-Hash)。\n"
            "3. **商业机密与数据防泄漏排查**：审计失陷主机是否存在 `7z.exe` / `rar.exe` 批量打包行为及向境外云存储/C2 传输大体积加密压缩包的流量记录。"
        ),
    },
    "university": {
        "label": "高校/科研机构 (重点排查挖矿木马、Webshell暗链与弱口令)",
        "short_label": "🎓 高校/科研机构",
        "precautions_md": (
            "### 🎓 高校/科研机构专属安全加固注意事项 (University / Research Institute)\n"
            "1. **站群系统 WebShell 与暗链全面清查**：针对二级学院网站、教务及课题组自建 Web 容器（IIS/Tomcat/Apache），深度扫描篡改页面、SEO 博彩暗链及内存马，启用网站目录脚本执行权限白名单。\n"
            "2. **算力服务器挖矿木马根除**：重点排查实验室 GPU/HPC 节点是否存在伪装成系统服务的门罗币 (`xmrig`) 挖矿程序、计划任务定时拉起脚本以及 WMI 持久化事件订阅。\n"
            "3. **校园网暴露面收敛与弱口令整改**：关闭课题组服务器非必要的公网 IP 直连映射（统一纳入校园 VPN + 堡垒机管控），强制清退默认口令与弱口令账户。"
        ),
    },
}

# 匹配 PowerShell -enc / -encodedcommand 后的 Base64 参数
PS_BASE64_PATTERN = re.compile(
    r"(?:-e|-enc|-encodedcommand)\s+([A-Za-z0-9+/=]{16,})",
    re.IGNORECASE,
)


def decode_powershell_base64(text: str) -> Optional[str]:
    """
    自动提取并解码 PowerShell -EncodedCommand (UTF-16LE / UTF-8) Base64 载荷
    """
    if not text:
        return None
    match = PS_BASE64_PATTERN.search(text)
    if not match:
        return None

    b64_str = match.group(1).strip()
    # 补齐 Base64 padding
    missing_padding = len(b64_str) % 4
    if missing_padding:
        b64_str += "=" * (4 - missing_padding)

    try:
        raw_bytes = base64.b64decode(b64_str)
        # PowerShell -EncodedCommand 标准使用 UTF-16LE 编码
        if b"\x00" in raw_bytes:
            decoded = raw_bytes.decode("utf-16le", errors="ignore").strip()
        else:
            decoded = raw_bytes.decode("utf-8", errors="ignore").strip()
        return decoded if decoded else None
    except Exception as exc:
        logger.debug(f"Base64 解码失败: {exc}")
        return None


def _build_local_artifact_analysis(artifact: HostArtifact, decoded_payload: Optional[str]) -> str:
    """
    针对单条事件生成精准、动态的技术研判结论（严格依据真实 ImagePath / CommandLine / IpAddress / RiskLevel，绝不硬编码）
    """
    eid = artifact.event_id
    pdata = artifact.parsed_data or {}
    risk = (artifact.risk_level or "low").lower()
    tags_str = ", ".join(artifact.risk_tags or []) or "通用安全事件"

    if eid == 4625:
        ip = str(pdata.get("IpAddress") or "-").strip()
        user = pdata.get("TargetUserName", "-")
        ltype = pdata.get("LogonTypeDesc", pdata.get("LogonType", "-"))
        status_code = pdata.get("Status", "-")
        is_local_ip = ip in ("-", "", "127.0.0.1", "::1", "0.0.0.0")
        if is_local_ip and risk == "low":
            return (
                f"【本地登录认证失败】账户 `{user}` 在本机通过 `{ltype}` 登录失败 "
                f"(源地址: `{ip}`, 状态码: `{status_code}`)。未见外部远程异常 IP，通常为本地交互输入口令错误或历史凭据过期。"
            )
        return (
            f"【暴力破解/认证失败告警】检测到源 IP `{ip}` 针对账户 `{user}` 发起 `{ltype}` 认证失败 "
            f"(状态码: `{status_code}`)。结合标签 `{tags_str}`，需警惕口令喷洒或字典暴破行为。"
        )

    if eid == 4624:
        ip = str(pdata.get("IpAddress") or "-").strip()
        user = pdata.get("TargetUserName", "-")
        ltype = pdata.get("LogonTypeDesc", pdata.get("LogonType", "-"))
        is_local_ip = ip in ("-", "", "127.0.0.1", "::1", "0.0.0.0")
        if is_local_ip and risk == "low":
            return (
                f"【常规本地会话登录】账户 `{user}` 通过 `{ltype}` 完成本机登录 (源地址: `{ip}`)，"
                "无外部远程网络源 IP 介入，属于正常本地交互或系统会话。"
            )
        return (
            f"【高危远程登录成功】外部源 IP `{ip}` 成功通过 `{ltype}` 登录账户 `{user}` (`{tags_str}`)。"
            "若此前伴随 4625 认证失败事件，表明攻击者已突破口令防线或利用有效凭据建立远程会话。"
        )

    if eid == 4688:
        proc = pdata.get("NewProcessName", "-")
        parent = pdata.get("ParentProcessName", "-")
        cmd = pdata.get("CommandLine", "-")
        if risk == "low":
            return (
                f"【常规进程创建】父进程 `{parent or '系统进程'}` 启动了 `{proc}` "
                f"(PID: `{pdata.get('NewProcessId', '-')}`)，命令行参数未见混淆或高危攻击特征。"
            )
        analysis = (
            f"【高危进程执行】父进程 `{parent or '未知'}` (PPID: `{pdata.get('ParentProcessId', '-')}`) "
            f"派生了子进程 `{proc}` (PID: `{pdata.get('NewProcessId', '-')}`)，命中标签: `{tags_str}`。"
        )
        if parent and any(w in parent.lower() for w in ("w3wp.exe", "tomcat", "php-cgi", "httpd", "nginx")):
            analysis += f"\n- **WebShell 实锤特征**：Web 容器进程 `{parent}` 直接拉起命令行解释器，证明攻击者已通过 Web 漏洞或 WebShell 执行远程指令。"
        if decoded_payload:
            analysis += (
                f"\n- **Base64 载荷自动解码结果**：`{decoded_payload}`"
                "\n- **载荷意图分析**：攻击者利用 PowerShell `-enc` 参数隐藏明文指令，请重点核查解码出的内嵌 URL/IP 或无文件内存加载行为。"
            )
        elif cmd and cmd != "-":
            analysis += f"\n- **原始命令行**：`{cmd}`"
        return analysis

    if eid == 7045:
        svc_name = pdata.get("ServiceName", "-")
        img_path = str(pdata.get("ImagePath") or "-").strip()
        acct = pdata.get("AccountName", "-")
        if risk in ("low", "medium") and not artifact.is_malicious:
            return (
                f"【常规系统服务/驱动变更】系统注册了服务/驱动 `{svc_name}`，文件路径为 `{img_path}` "
                f"(启动身份: `{acct}`)。路径位于标准系统驱动或常规软件目录，未检出命令行解释器调用或混淆载荷，属于正常驱动/软件服务安装。"
            )
        analysis = (
            f"【高危服务持久化告警】系统以 `{acct}` 权限注册了可疑服务 `{svc_name}` "
            f"(命中 `{tags_str}`)，服务可执行文件路径为：`{img_path}`。"
        )
        if decoded_payload:
            analysis += f"\n- **服务内嵌 Base64 解码明文**：`{decoded_payload}`"
        if re.search(r"(cmd\.exe|%comspec%|powershell|pwsh)", img_path, re.I):
            analysis += f"\n- **定性结论**：该服务直接调用命令行解释器 (`{img_path}`) 实现高权限持久化驻留，系典型恶意后门服务特征，建议立即停止并卸载该服务。"
        else:
            analysis += f"\n- **定性结论**：该服务可执行文件位于非标准高危目录 (`{img_path}`)，存在木马服务驻留风险，请立即核查文件签名与哈希。"
        return analysis

    if eid == 4720:
        target_user = pdata.get("TargetUserName", "-")
        subject_user = pdata.get("SubjectUserName", "-")
        analysis = (
            f"【新账户创建审计】操作账户 `{subject_user}` 创建了新本地/域账户 `{target_user}` "
            f"(SID: `{pdata.get('TargetSid', '-')}`，命中 `{tags_str}`)。"
        )
        if str(target_user).endswith("$"):
            analysis += (
                f"\n- **影子账户告警**：账户名 `{target_user}` 以 `$` 结尾，属于典型隐藏后门账户，"
                "用于规避日常管理员 `net user` 巡检并维持长期后门访问权限。"
            )
        return analysis

    return f"检测到系统安全事件 (EventID: {eid})，当前风险评级: {risk.upper()}，标签: {tags_str}。"


async def get_active_llm_config(db: AsyncSession) -> Optional[LLMConfig]:
    """从数据库查询当前激活的 LLM 配置；若无则尝试从环境变量读取"""
    stmt = select(LLMConfig).where(LLMConfig.is_active == True).order_by(LLMConfig.updated_at.desc())
    cfg = (await db.execute(stmt)).scalars().first()
    if cfg:
        return cfg

    env_api_key = os.getenv("LLM_API_KEY", "").strip()
    env_base_url = os.getenv("LLM_BASE_URL", "").strip()
    env_model = os.getenv("LLM_MODEL", "").strip()
    if env_api_key or env_base_url:
        return LLMConfig(
            config_name="Env-Default-LLM",
            provider=os.getenv("LLM_PROVIDER", "openai"),
            base_url=env_base_url or "https://api.deepseek.com/v1",
            api_key=env_api_key,
            model_name=env_model or "deepseek-chat",
            temperature=0.2,
            max_tokens=4096,
            system_prompt=DEFAULT_DFIR_SYSTEM_PROMPT,
            is_active=True,
        )
    return None


async def _call_openai_compatible_llm(
    llm_cfg: LLMConfig,
    user_prompt: str,
) -> Optional[str]:
    """
    调用兼容 OpenAI Chat Completions 规范的大模型接口（支持 DeepSeek / OpenAI / Qwen / Ollama）
    """
    base_url = llm_cfg.base_url.rstrip("/")
    url = f"{base_url}/chat/completions"
    headers = {"Content-Type": "application/json"}
    if llm_cfg.api_key:
        headers["Authorization"] = f"Bearer {llm_cfg.api_key}"

    payload = {
        "model": llm_cfg.model_name,
        "temperature": llm_cfg.temperature,
        "max_tokens": llm_cfg.max_tokens,
        "messages": [
            {
                "role": "system",
                "content": llm_cfg.system_prompt or DEFAULT_DFIR_SYSTEM_PROMPT,
            },
            {
                "role": "user",
                "content": user_prompt,
            },
        ],
    }

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            return content.strip()
    except Exception as exc:
        logger.warning(f"调用外部大模型 API ({llm_cfg.config_name} @ {url}) 失败，将自动切换本地专家引擎兜底: {exc}")
        return None


def _generate_expert_markdown_report(
    case_obj: Case,
    hosts: list[CaseHost],
    artifacts: list[HostArtifact],
    iocs: list[dict[str, Any]],
    engine_label: str,
) -> str:
    """
    基于当前案件真实提取并解码的取证证据链，动态生成结构化 Markdown 应急响应分析报告（绝不硬编码特定样本数据）
    """
    sorted_artifacts = sorted(
        artifacts,
        key=lambda x: (x.event_time is None, x.event_time or x.created_at),
    )

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    decoded_payloads: list[dict[str, Any]] = []
    high_risk_artifacts: list[HostArtifact] = []
    low_risk_artifacts: list[HostArtifact] = []

    remote_ips: list[str] = []
    malicious_svcs: list[str] = []
    suspicious_procs: list[str] = []
    created_users: list[str] = []

    for art in sorted_artifacts:
        lvl = (art.risk_level or "low").lower()
        counts[lvl] = counts.get(lvl, 0) + 1
        pdata = art.parsed_data or {}

        if pdata.get("DecodedPayload"):
            t_str = art.event_time.strftime("%Y-%m-%d %H:%M:%S UTC") if art.event_time else "未知时间"
            decoded_payloads.append({
                "event_id": art.event_id,
                "time": t_str,
                "raw": pdata.get("CommandLine") or pdata.get("ImagePath"),
                "decoded": pdata["DecodedPayload"],
            })

        if lvl in ("critical", "high", "medium"):
            high_risk_artifacts.append(art)
        else:
            low_risk_artifacts.append(art)

        if lvl in ("critical", "high"):
            if art.event_id in (4624, 4625):
                ip = str(pdata.get("IpAddress") or "").strip()
                if ip and ip not in ("-", "127.0.0.1", "::1", "0.0.0.0") and ip not in remote_ips:
                    remote_ips.append(ip)
            elif art.event_id == 4688:
                pname = str(pdata.get("NewProcessName") or "").split("\\")[-1]
                if pname and pname not in suspicious_procs:
                    suspicious_procs.append(pname)
            elif art.event_id == 7045:
                sname = str(pdata.get("ServiceName") or "").strip()
                if sname and sname not in malicious_svcs:
                    malicious_svcs.append(sname)
            elif art.event_id == 4720:
                uname = str(pdata.get("TargetUserName") or "").strip()
                if uname and uname not in created_users:
                    created_users.append(uname)

    # 构建浓缩时间线表格：优先展示全部中高危事件；若无中高危事件则展示最近 15 条常规事件摘要
    display_artifacts = high_risk_artifacts if high_risk_artifacts else low_risk_artifacts[:15]
    timeline_lines: list[str] = []
    for idx, art in enumerate(display_artifacts[:50], start=1):
        t_str = art.event_time.strftime("%Y-%m-%d %H:%M:%S UTC") if art.event_time else "未知时间"
        tags = art.risk_tags or []
        timeline_lines.append(
            f"| {idx} | `{t_str}` | **EventID {art.event_id}** | `{art.risk_level.upper()}` | {art.summary} | `{', '.join(tags)}` |"
        )

    omitted_note = ""
    if len(low_risk_artifacts) > 0 and high_risk_artifacts:
        omitted_note = f"\n\n> 💡 **注**：已自动过滤并折叠其余 **{len(low_risk_artifacts)} 条 `LOW` 级常规系统基线事件**（如正常驱动加载、本地交互登录等），仅在表中聚焦展示中高危威胁事件。"
    elif not high_risk_artifacts and len(low_risk_artifacts) > 15:
        omitted_note = f"\n\n> 💡 **注**：当前主机共采集到 **{len(low_risk_artifacts)} 条 `LOW` 级常规事件**，上表仅展示前 15 条代表性基线记录。"

    timeline_table = (
        "| 序号 | 发生时间 (UTC) | 事件类型 | 风险等级 | 事件详情摘要 | ATT&CK / 风险标签 |\n"
        "| :---: | :--- | :--- | :---: | :--- | :--- |\n"
        + ("\n".join(timeline_lines) if timeline_lines else "| - | - | 暂无事件记录 | - | - | - |")
        + omitted_note
    )

    ioc_lines: list[str] = []
    for ioc in iocs:
        ti_desc = (ioc.get("intel_detail") or {}).get("ti_summary", "内部规则提取")
        ioc_lines.append(
            f"- **`{ioc['ioc_value']}`** (类型: `{ioc['ioc_type']}`, 威胁等级: **`{ioc['threat_level'].upper()}`**, 置信度: `{ioc['confidence']}%`)\n"
            f"  - 标签: `{', '.join(ioc.get('tags') or [])}`\n"
            f"  - 情报研判: {ti_desc}"
        )
    ioc_section = "\n".join(ioc_lines) if ioc_lines else "- 暂未提取到外部高危 IOC 指标。"

    decoded_section_lines: list[str] = []
    for dp in decoded_payloads:
        decoded_section_lines.append(
            f"- **事件 `EventID {dp['event_id']}` ({dp['time']})**\n"
            f"  - 原始混淆命令: `{dp['raw']}`\n"
            f"  - **自动 Base64 解码明文**: `{dp['decoded']}`"
        )
    decoded_section = "\n".join(decoded_section_lines) if decoded_section_lines else "- 未检出 PowerShell Base64 (`-enc`) 编码混淆命令。"

    host_names = ", ".join(f"{h.hostname} ({h.ip_address or '未知IP'})" for h in hosts) or "未关联主机"
    max_score = max((h.risk_score or 0 for h in hosts), default=0)
    industry_key = getattr(case_obj, "industry_type", "enterprise") or "enterprise"
    ind_profile = INDUSTRY_PROFILES.get(industry_key, INDUSTRY_PROFILES["enterprise"])

    # 动态生成第一章：失陷定性与攻击链综述
    if counts["critical"] > 0 or counts["high"] > 0:
        verdict_level = "CRITICAL (严重失陷)" if counts["critical"] > 0 else "HIGH (高危风险)"
        chain_bullets: list[str] = []
        if remote_ips:
            chain_bullets.append(
                f"1. **外部访问与登录异常 (Initial Access)**：检测到来自 `{', '.join(remote_ips)}` 的远程登录或口令暴破行为 (`EventID 4624/4625`)。"
            )
        if suspicious_procs:
            chain_bullets.append(
                f"2. **高危进程与载荷执行 (Execution)**：主机派生了可疑进程 `{', '.join(suspicious_procs)}` (`EventID 4688`)"
                + (f"，并检出 **{len(decoded_payloads)} 条 Base64 编码混淆载荷**。" if decoded_payloads else "。")
            )
        if malicious_svcs or created_users:
            pers_items = []
            if malicious_svcs:
                pers_items.append(f"恶意/可疑系统服务 `{', '.join(malicious_svcs)}` (`EventID 7045`)")
            if created_users:
                pers_items.append(f"新建可疑后门账户 `{', '.join(created_users)}` (`EventID 4720`)")
            chain_bullets.append(
                f"3. **持久化驻留 (Persistence)**：检测到 {'；'.join(pers_items)}。"
            )
        chain_md = "\n".join(chain_bullets) if chain_bullets else "- 检出高危安全事件，请结合下方时间线核查具体命令与登录上下文。"
        overview_section = (
            f"综合涉案主机 Windows 事件日志与威胁情报分析，当前主机最高风险评分为 **{max_score}/100 ({verdict_level})**，"
            f"共提取事件 **{len(sorted_artifacts)}** 条（极危 `{counts['critical']}` 条、高危 `{counts['high']}` 条、中危 `{counts['medium']}` 条、常规低危 `{counts['low']}` 条）：\n\n"
            f"{chain_md}"
        )
    else:
        overview_section = (
            f"综合涉案主机 Windows 事件日志全量排查，当前主机最高风险评分为 **{max_score}/100 (LOW - 未见高危失陷特征)**。\n\n"
            f"- 共扫描提取日志事件 **{len(sorted_artifacts)}** 条（其中中危 `{counts['medium']}` 条、常规低危 `{counts['low']}` 条，**极危与高危事件均为 `0` 条**）。\n"
            f"- 日志中的 `EventID 7045` 均为常规系统驱动（如 `\\SystemRoot\\System32\\drivers\\`）或正常软件服务安装，未检出 `%COMSPEC%` / `powershell` 等恶意持久化后门。\n"
            f"- 日志中的 `EventID 4624/4625` 均为本机交互登录，未发现外部攻击源 IP 远程暴破或影子账户 (`4720`) 创建行为。"
        )

    # 动态生成第五章通用遏制建议
    remediation_bullets: list[str] = []
    if remote_ips:
        remediation_bullets.append(
            f"1. **网络隔离与攻击源封禁**：在防火墙立即阻断外部异常 IP `{', '.join(remote_ips)}` 的入站与出站连接。"
        )
    if malicious_svcs:
        svc_cmds = " / ".join(f"`sc stop {s} & sc delete {s}`" for s in malicious_svcs[:5])
        remediation_bullets.append(
            f"2. **清除恶意持久化服务**：以管理员权限停止并卸载高危服务：{svc_cmds}。"
        )
    if created_users:
        usr_cmds = " / ".join(f"`net user {u} /delete`" for u in created_users[:5])
        remediation_bullets.append(
            f"3. **查杀可疑后门账号**：立即禁用并删除异常创建的账户：{usr_cmds}。"
        )
    if not remediation_bullets:
        remediation_bullets.append(
            "1. **常态化安全基线加固**：当前主机未检出高危后门服务或外部入侵 IP，建议保持开启 PowerShell 脚本块日志审计 (EventID 4104) 与进程命令行审计 (EventID 4688)。\n"
            "2. **最小权限与补丁管理**：定期核查特权管理员组成员，收敛非必要的 SMB (445) 与 RDP (3389) 端口暴露面。"
        )
    remediation_md = "\n".join(remediation_bullets)

    # 提取攻击 POC/EXP 与 CVE 漏洞智能匹配 + 勒索/远控排查
    from services.vuln_matcher import detect_ransomware_and_rats, extract_and_match_cves

    cve_matches = extract_and_match_cves(artifacts, hosts)
    ransom_rat_alerts = detect_ransomware_and_rats(artifacts, hosts)

    cve_md_lines: list[str] = []
    for cve in cve_matches:
        cve_md_lines.append(
            f"- **`{cve['cve_id']}` · {cve['vuln_name']}** (CVSS: `{cve['cvss_score']}`, 涉案主机: `{cve['hostname']}`)\n"
            f"  - **受影响组件**: `{cve['component']}`\n"
            f"  - **提取的原始 POC/EXP 载荷**: `{cve['poc_payload']}`\n"
            f"  - **漏洞利用原理**: {cve['principle']}\n"
            f"  - **补丁与 WAF 封堵建议**: {cve['remediation'].replace(chr(10), ' ')}"
        )
    cve_section_md = "\n".join(cve_md_lines) if cve_md_lines else "- 当前日志中未检出已知高危 CVE/CNVD 漏洞利用载荷。"

    rr_md_lines: list[str] = []
    for al in ransom_rat_alerts:
        rr_md_lines.append(
            f"- **🚨 `{al['name']}`** (主机: `{al['hostname']}`, EventID: `{al['event_id']}`)\n"
            f"  - **捕获证据**: `{al['evidence']}`\n"
            f"  - **解密/风险研判**: {al['status_note']}\n"
            f"  - **处置要求**: {al['advice'].replace(chr(10), ' ')}"
        )
    rr_section_md = "\n\n### 🔍 勒索病毒家族与非授权远控排查\n" + "\n".join(rr_md_lines) if rr_md_lines else ""

    return f"""# 🛡️ WinDFIR-AI 应急响应深度研判报告

> **案件编号**: `{case_obj.case_code}` | **案件名称**: {case_obj.case_name}  
> **客户行业场景**: **{ind_profile['label']}**  
> **涉案主机**: {host_names} | **研判引擎**: `{engine_label}`

---

## 一、 事件定性与失陷综述

{overview_section}{rr_section_md}

---

## 二、 攻击时间线还原 (Attack Kill Chain)

{timeline_table}

---

## 三、 漏洞利用链与攻击 POC 载荷还原 (CVE & Exploit Matching)

{cve_section_md}

---

## 四、 混淆载荷自动解码分析 (Payload Deobfuscation)

{decoded_section}

---

## 五、 IOC 威胁情报关联分析

{ioc_section}

---

## 六、 应急处置与行业定制化加固建议 (Remediation Playbook)

{ind_profile['precautions_md']}

### 🛠️ 针对本案证据链的处置步骤
{remediation_md}
"""


async def run_case_ai_analysis(
    case_id: int,
    db: AsyncSession,
) -> dict[str, Any]:
    """
    执行全案 AI 深度研判：
    1. 对案件关联的所有 IOC 进行威胁情报富化
    2. 对案件下所有高危 HostArtifact 自动解码 Base64 载荷并生成单条 `ai_analysis`
    3. 调用激活的大模型（或本地 DFIR 专家引擎兜底）生成全案 Markdown 研判报告并更新 `Case.ai_summary`
    """
    case_obj = await db.get(Case, case_id)
    if not case_obj:
        raise ValueError(f"未找到 ID={case_id} 的应急案件")

    # 1. 富化案件 IOC 威胁情报
    enriched_iocs = await enrich_case_iocs(case_id, db)

    # 2. 获取涉案主机与所有事件伪影
    hosts_stmt = select(CaseHost).where(CaseHost.case_id == case_id)
    hosts = list((await db.execute(hosts_stmt)).scalars().all())

    artifacts_stmt = (
        select(HostArtifact)
        .where(HostArtifact.case_id == case_id)
        .order_by(HostArtifact.event_time.asc(), HostArtifact.id.asc())
    )
    artifacts = list((await db.execute(artifacts_stmt)).scalars().all())

    decoded_count = 0
    for art in artifacts:
        pdata = dict(art.parsed_data or {})
        raw_cmd = pdata.get("CommandLine") or pdata.get("ImagePath") or ""
        decoded_str = decode_powershell_base64(raw_cmd)
        if decoded_str:
            pdata["DecodedPayload"] = decoded_str
            art.parsed_data = pdata
            decoded_count += 1
        # 为每条高危伪影填充单条研判说明
        art.ai_analysis = _build_local_artifact_analysis(art, decoded_str)

    # 3. 检查是否配置了可用的外部大模型 API
    llm_cfg = await get_active_llm_config(db)
    used_engine = "WinDFIR-AI 本地专家推理引擎 (未配置外部 LLM API Key，自动启用内置规则+载荷解码引擎)"
    ai_report_md: Optional[str] = None

    if llm_cfg and (llm_cfg.api_key or llm_cfg.provider.lower() == "ollama"):
        # 组装精简结构化上下文发送给大模型（避免原始 XML 撑爆 Token）
        compact_events = [
            {
                "event_id": a.event_id,
                "event_time": str(a.event_time) if a.event_time else None,
                "risk_level": a.risk_level,
                "risk_tags": a.risk_tags,
                "summary": a.summary,
                "parsed_data": a.parsed_data,
            }
            for a in artifacts
        ]
        industry_key = getattr(case_obj, "industry_type", "enterprise") or "enterprise"
        ind_profile = INDUSTRY_PROFILES.get(industry_key, INDUSTRY_PROFILES["enterprise"])
        user_prompt = (
            f"请对以下 Windows 应急响应案件进行深度研判并输出完整 Markdown 报告：\n"
            f"- 案件名称：{case_obj.case_name} ({case_obj.case_code})\n"
            f"- 客户行业场景：{ind_profile['label']}\n"
            f"- 行业加固红线要求：\n{ind_profile['precautions_md']}\n"
            f"- 案件描述：{case_obj.description or '无'}\n"
            f"- 高危事件时间线 JSON：\n```json\n{json.dumps(compact_events, ensure_ascii=False, indent=2)}\n```\n"
            f"- IOC 威胁情报 JSON：\n```json\n{json.dumps(enriched_iocs, ensure_ascii=False, indent=2)}\n```\n"
            "请包含：1. 事件定性与失陷综述；2. 攻击时间线还原表；3. 恶意载荷解码与行为分析；4. ATT&CK 战术映射；5. 针对该客户行业场景的差异化安全加固注意事项与具体可执行的应急处置命令。"
        )
        llm_response = await _call_openai_compatible_llm(llm_cfg, user_prompt)
        if llm_response:
            ai_report_md = llm_response
            used_engine = f"外部大模型 API ({llm_cfg.config_name} / {llm_cfg.model_name})"

    # 若未配置外部大模型或调用失败，使用内置专家推理引擎生成完整报告
    if not ai_report_md:
        ai_report_md = _generate_expert_markdown_report(
            case_obj=case_obj,
            hosts=hosts,
            artifacts=artifacts,
            iocs=enriched_iocs,
            engine_label=used_engine,
        )

    case_obj.ai_summary = ai_report_md
    case_obj.status = "completed"
    await db.commit()

    return {
        "case_id": case_id,
        "case_code": case_obj.case_code,
        "status": case_obj.status,
        "engine_used": used_engine,
        "analyzed_artifacts_count": len(artifacts),
        "decoded_base64_payloads_count": decoded_count,
        "enriched_iocs_count": len(enriched_iocs),
        "ai_summary_markdown": ai_report_md,
    }
