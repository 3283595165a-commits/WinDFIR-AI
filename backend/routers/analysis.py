"""
阶段二：威胁情报联动、大模型配置与 AI 深度研判接口路由 (routers/analysis.py)
提供以下核心接口：
- POST /api/llm-configs : 新增或更新大模型配置 (支持 DeepSeek / OpenAI / Qwen / Ollama)
- GET  /api/llm-configs : 获取所有已配置的大模型列表
- GET  /api/cases/{case_id}/iocs : 获取案件提取出的 IOC 指标列表
- POST /api/cases/{case_id}/iocs/enrich : 一键富化案件下的 IOC 威胁情报
- POST /api/cases/{case_id}/analyze : 一键触发全案 AI 研判（载荷解码 + 情报联动 + 攻击链报告生成）
- GET  /api/cases/{case_id}/report : 获取案件 AI 应急响应报告与完整证据链明细
"""

import html
import os
from datetime import datetime
from typing import Any, Optional
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from database import Case, CaseHost, HostArtifact, IOCIntelligence, LLMConfig, get_db
from services.ai_analyzer import (
    DEFAULT_DFIR_SYSTEM_PROMPT,
    INDUSTRY_PROFILES,
    decode_powershell_base64,
    run_case_ai_analysis,
)
from services.ti_service import enrich_case_iocs
from utils.path_helper import get_app_root

router = APIRouter(tags=["AI Analysis & Threat Intel (AI研判与威胁情报)"])


# ==============================================================================
# Pydantic 请求与响应数据模型
# ==============================================================================
class LLMConfigCreateRequest(BaseModel):
    model_config = {"protected_namespaces": ()}

    config_name: str = Field(
        default="DeepSeek-V3-DFIR",
        description="配置名称（唯一标识）",
        examples=["DeepSeek-V3-DFIR"],
    )
    provider: str = Field(
        default="deepseek",
        description="模型服务商: deepseek / openai / qwen / ollama / custom",
        examples=["deepseek"],
    )
    base_url: str = Field(
        default="https://api.deepseek.com/v1",
        description="OpenAI 兼容接口地址（如 https://api.deepseek.com/v1 或 http://localhost:11434/v1）",
        examples=["https://api.deepseek.com/v1"],
    )
    api_key: Optional[str] = Field(
        default="",
        description="大模型 API Key（若使用本地 Ollama 可留空）",
        examples=["sk-xxxxxxxxxxxxxxxxxxxxxxxx"],
    )
    model_name: str = Field(
        default="deepseek-chat",
        description="模型标识名称（如 deepseek-chat / deepseek-reasoner / gpt-4o / qwen-plus）",
        examples=["deepseek-chat"],
    )
    temperature: float = Field(default=0.2, ge=0.0, le=2.0, description="采样温度")
    max_tokens: int = Field(default=4096, ge=256, le=32768, description="最大生成 Token 数")
    system_prompt: Optional[str] = Field(
        default=DEFAULT_DFIR_SYSTEM_PROMPT,
        description="DFIR 安全专家系统提示词模板",
    )
    is_active: bool = Field(default=True, description="是否设为当前激活配置")
    threatbook_api_key: Optional[str] = Field(
        default=None,
        description="微步在线 (ThreatBook) API Key（可选，留空不修改）",
    )
    vt_api_key: Optional[str] = Field(
        default=None,
        description="VirusTotal API Key（可选，留空不修改）",
    )


def _persist_env_keys(tb_key: Optional[str], vt_key: Optional[str]) -> None:
    """将微步在线与 VirusTotal API Key 同步写入运行时环境变量与外部 .env 文件"""
    if tb_key is not None and tb_key.strip():
        os.environ["THREATBOOK_API_KEY"] = tb_key.strip()
    if vt_key is not None and vt_key.strip():
        os.environ["VT_API_KEY"] = vt_key.strip()

    try:
        env_path = get_app_root() / ".env"
        existing_lines: list[str] = []
        if env_path.exists():
            existing_lines = env_path.read_text(encoding="utf-8").splitlines()
        env_map: dict[str, str] = {}
        for line in existing_lines:
            if "=" in line and not line.strip().startswith("#"):
                k, v = line.split("=", 1)
                env_map[k.strip()] = v.strip()
        if tb_key is not None and tb_key.strip():
            env_map["THREATBOOK_API_KEY"] = tb_key.strip()
        if vt_key is not None and vt_key.strip():
            env_map["VT_API_KEY"] = vt_key.strip()
        new_content = "\n".join(f"{k}={v}" for k, v in env_map.items()) + "\n"
        env_path.write_text(new_content, encoding="utf-8")
    except Exception:
        pass


# ==============================================================================
# 1. 大模型配置管理接口 (/api/llm-configs)
# ==============================================================================
@router.post(
    "/api/llm-configs",
    status_code=status.HTTP_201_CREATED,
    summary="新增或更新 AI 大模型配置 (DeepSeek / OpenAI / Ollama)",
)
async def upsert_llm_config(
    payload: LLMConfigCreateRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """
    新增或更新大模型配置（写入 `llm_configs` 表）。
    当 `is_active=True` 时，自动将其他配置置为非激活状态，使当前配置生效。
    """
    if payload.is_active:
        await db.execute(update(LLMConfig).values(is_active=False))

    stmt = select(LLMConfig).where(LLMConfig.config_name == payload.config_name)
    existing = (await db.execute(stmt)).scalar_one_or_none()

    clean_key = payload.api_key.strip() if payload.api_key and payload.api_key != "sk-xxxxxxxxxxxxxxxxxxxxxxxx" else None

    if existing:
        existing.provider = payload.provider
        existing.base_url = payload.base_url
        if clean_key is not None:
            existing.api_key = clean_key
        existing.model_name = payload.model_name
        existing.temperature = payload.temperature
        existing.max_tokens = payload.max_tokens
        existing.system_prompt = payload.system_prompt
        existing.is_active = payload.is_active
        cfg_obj = existing
    else:
        cfg_obj = LLMConfig(
            config_name=payload.config_name,
            provider=payload.provider,
            base_url=payload.base_url,
            api_key=clean_key,
            model_name=payload.model_name,
            temperature=payload.temperature,
            max_tokens=payload.max_tokens,
            system_prompt=payload.system_prompt,
            is_active=payload.is_active,
        )
        db.add(cfg_obj)

    await db.commit()
    await db.refresh(cfg_obj)

    # 同步保存微步在线与 VirusTotal API Key（如前端传入）
    _persist_env_keys(payload.threatbook_api_key, payload.vt_api_key)

    masked_key = (
        f"{cfg_obj.api_key[:6]}...{cfg_obj.api_key[-4:]}"
        if cfg_obj.api_key and len(cfg_obj.api_key) > 10
        else ("已配置" if cfg_obj.api_key else "未配置(将使用本地专家引擎兜底)")
    )

    return {
        "message": "大模型与威胁情报 API 配置保存成功",
        "config": {
            "id": cfg_obj.id,
            "config_name": cfg_obj.config_name,
            "provider": cfg_obj.provider,
            "base_url": cfg_obj.base_url,
            "model_name": cfg_obj.model_name,
            "api_key_status": masked_key,
            "is_active": cfg_obj.is_active,
            "has_threatbook_key": bool(os.getenv("THREATBOOK_API_KEY", "").strip()),
            "has_vt_key": bool(os.getenv("VT_API_KEY", "").strip()),
        },
    }


@router.get("/api/llm-configs", summary="获取已配置的大模型列表")
async def list_llm_configs(db: AsyncSession = Depends(get_db)) -> list[dict[str, Any]]:
    stmt = select(LLMConfig).order_by(LLMConfig.is_active.desc(), LLMConfig.updated_at.desc())
    configs = (await db.execute(stmt)).scalars().all()
    has_tb = bool(os.getenv("THREATBOOK_API_KEY", "").strip())
    has_vt = bool(os.getenv("VT_API_KEY", "").strip())
    return [
        {
            "id": c.id,
            "config_name": c.config_name,
            "provider": c.provider,
            "base_url": c.base_url,
            "model_name": c.model_name,
            "has_api_key": bool(c.api_key),
            "has_threatbook_key": has_tb,
            "has_vt_key": has_vt,
            "temperature": c.temperature,
            "max_tokens": c.max_tokens,
            "is_active": c.is_active,
            "updated_at": c.updated_at,
        }
        for c in configs
    ]


# ==============================================================================
# 2. IOC 威胁情报查询与富化接口 (/api/cases/{case_id}/iocs)
# ==============================================================================
@router.get("/api/cases/{case_id}/iocs", summary="查询案件提取的所有 IOC 威胁指标")
async def get_case_iocs(
    case_id: int,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    stmt = select(IOCIntelligence).where(IOCIntelligence.case_id == case_id)
    iocs = (await db.execute(stmt)).scalars().all()
    return {
        "case_id": case_id,
        "total_iocs": len(iocs),
        "iocs": [
            {
                "id": i.id,
                "host_id": i.host_id,
                "ioc_type": i.ioc_type,
                "ioc_value": i.ioc_value,
                "threat_level": i.threat_level,
                "confidence": i.confidence,
                "source": i.source,
                "tags": i.tags,
                "intel_detail": i.intel_detail,
                "first_seen": i.first_seen,
                "last_seen": i.last_seen,
            }
            for i in iocs
        ],
    }


@router.post("/api/cases/{case_id}/iocs/enrich", summary="一键触发案件 IOC 威胁情报富化查询")
async def trigger_ioc_enrichment(
    case_id: int,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    case_obj = await db.get(Case, case_id)
    if not case_obj:
        raise HTTPException(status_code=404, detail=f"未找到 ID={case_id} 的应急案件")

    enriched = await enrich_case_iocs(case_id, db)
    return {
        "message": f"已完成 {len(enriched)} 条 IOC 指标的威胁情报富化。",
        "case_id": case_id,
        "enriched_iocs": enriched,
    }


# ==============================================================================
# 3. AI 深度研判与攻击链报告接口 (/api/cases/{case_id}/analyze & /report)
# ==============================================================================
@router.post(
    "/api/cases/{case_id}/analyze",
    summary="一键执行全案 AI 深度研判（Base64载荷解码 + 情报关联 + 攻击链报告生成）",
)
async def analyze_case_with_ai(
    case_id: int,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """
    对指定案件执行阶段二完整智能研判流水线：
    1. 自动富化 `ioc_intelligence` 表中的高危 IP 与后门账号情报；
    2. 自动识别并解码 `4688`/`7045` 中的 PowerShell `-enc` Base64 加密命令，写入每条事件的 `ai_analysis`；
    3. 若已在 `/api/llm-configs` 配置外部大模型 API Key，则调用大模型生成报告；若未配置，则自动使用内置 DFIR 专家引擎生成完整 Markdown 应急响应报告并存入 `cases.ai_summary`。
    """
    try:
        result = await run_case_ai_analysis(case_id=case_id, db=db)
        return {
            "message": "全案 AI 深度研判与攻击链还原完成！",
            **result,
        }
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"AI 研判执行异常: {exc}") from exc


@router.get(
    "/api/cases/{case_id}/report",
    summary="获取案件完整 AI 应急响应报告及单条伪影研判明细",
)
async def get_case_ai_report(
    case_id: int,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    case_obj = await db.get(Case, case_id)
    if not case_obj:
        raise HTTPException(status_code=404, detail=f"未找到 ID={case_id} 的应急案件")

    art_stmt = (
        select(HostArtifact)
        .where(HostArtifact.case_id == case_id)
        .order_by(HostArtifact.event_time.asc(), HostArtifact.id.asc())
    )
    artifacts = (await db.execute(art_stmt)).scalars().all()

    return {
        "case_id": case_obj.id,
        "case_code": case_obj.case_code,
        "case_name": case_obj.case_name,
        "status": case_obj.status,
        "severity": case_obj.severity,
        "ai_summary_markdown": case_obj.ai_summary or "尚未执行 AI 研判，请先调用 POST /api/cases/{case_id}/analyze",
        "timeline_artifacts": [
            {
                "id": a.id,
                "event_id": a.event_id,
                "event_time": a.event_time,
                "risk_level": a.risk_level,
                "risk_tags": a.risk_tags,
                "summary": a.summary,
                "decoded_payload": (a.parsed_data or {}).get("DecodedPayload"),
                "ai_analysis": a.ai_analysis,
            }
            for a in artifacts
        ],
    }


# ==============================================================================
# 4. 攻击拓扑图 (AntV G6)、0号病人画像与人工审核修复命令卡片 (/api/cases/{case_id}/topology)
# ==============================================================================
@router.get(
    "/api/cases/{case_id}/topology",
    summary="获取案件横向移动拓扑图数据 (AntV G6)、0号病人画像与人工审核修复脚本卡片",
)
async def get_case_topology_and_remediation(
    case_id: int,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    case_obj = await db.get(Case, case_id)
    if not case_obj:
        raise HTTPException(status_code=404, detail=f"未找到 ID={case_id} 的应急案件")

    hosts = (
        await db.execute(
            select(CaseHost).where(CaseHost.case_id == case_id).order_by(CaseHost.risk_score.desc(), CaseHost.id.asc())
        )
    ).scalars().all()

    artifacts = (
        await db.execute(
            select(HostArtifact)
            .where(HostArtifact.case_id == case_id)
            .order_by(HostArtifact.event_time.asc(), HostArtifact.id.asc())
        )
    ).scalars().all()

    iocs = (
        await db.execute(select(IOCIntelligence).where(IOCIntelligence.case_id == case_id))
    ).scalars().all()

    # 1. 判定0号病人主机（最早出现外网爆破/登录或风险最高的主机）
    patient_zero_host: Optional[CaseHost] = hosts[0] if hosts else None

    # 2. 构建 AntV G6 节点与边
    nodes_map: dict[str, dict[str, Any]] = {}
    edges_list: list[dict[str, Any]] = []
    seen_edges: set[str] = set()

    def add_node(node_id: str, label: str, node_type: str, risk: str = "high", meta: Optional[dict] = None):
        if node_id not in nodes_map:
            nodes_map[node_id] = {
                "id": node_id,
                "label": label,
                "nodeType": node_type,  # attacker / host / process / service / account
                "risk": risk,
                "meta": meta or {},
            }

    def add_edge(source: str, target: str, label: str, risk: str = "high"):
        if source == target:
            return
        # 若同一对节点间已存在边，则智能合并或升级标签，避免 G6 双边与文字重叠
        for existing in edges_list:
            if existing["source"] == source and existing["target"] == target:
                if label not in existing["label"]:
                    # 若同时存在 4625 爆破和 4624 登录成功，统一展示为 "4624 RDP登录/爆破"
                    if ("4625" in existing["label"] and "4624" in label) or (
                        "4624" in existing["label"] and "4625" in label
                    ):
                        existing["label"] = label
                    else:
                        existing["label"] = f"{existing['label']} / {label}"
                if risk == "critical":
                    existing["risk"] = "critical"
                return
        edge_key = f"{source}->{target}:{label}"
        if edge_key not in seen_edges:
            seen_edges.add(edge_key)
            edges_list.append(
                {
                    "source": source,
                    "target": target,
                    "label": label,
                    "risk": risk,
                }
            )

    host_id_map: dict[int, CaseHost] = {}
    for h in hosts:
        host_id_map[h.id] = h
        is_pz = bool(patient_zero_host and h.id == patient_zero_host.id and (h.risk_score or 0) >= 40)
        h_label = f"{'👑 [0号病人] ' if is_pz else '🛡️ [受检主机] '}{h.hostname}\n({h.ip_address or '内网主机'})"
        add_node(
            node_id=f"host_{h.id}",
            label=h_label,
            node_type="patient_zero" if is_pz else "host",
            risk="critical" if (h.risk_score or 0) >= 80 else ("high" if (h.risk_score or 0) >= 40 else "low"),
            meta={"hostname": h.hostname, "ip": h.ip_address, "risk_score": h.risk_score},
        )

    attacker_ips: list[str] = []
    backdoor_accounts: list[str] = []
    malicious_services: list[dict[str, str]] = []
    suspicious_processes: list[dict[str, str]] = []
    entry_vectors_detected: list[str] = []
    has_4625_bruteforce = False
    first_compromise_time = None

    # 拓扑图同类型高危节点限流阈值（超过 8 个自动折叠为聚合节点，防止 100+ 节点挤压成一条竖线）
    MAX_NODES_PER_TYPE = 8
    shown_counts = {"attacker": 0, "process": 0, "service": 0, "account": 0}
    overflow_counts = {"attacker": 0, "process": 0, "service": 0, "account": 0}
    overflow_host_id = patient_zero_host.id if patient_zero_host else None

    for art in artifacts:
        # 严格过滤：仅将 critical 和 high 级别的高危事件纳入拓扑图与处置脚本生成
        if art.risk_level not in ("critical", "high"):
            continue

        pdata = art.parsed_data or {}
        h_node = f"host_{art.host_id}"
        if h_node not in nodes_map:
            add_node(h_node, f"Host-{art.host_id}", "host", "high")
        if overflow_host_id is None:
            overflow_host_id = art.host_id

        if art.event_time and (first_compromise_time is None or art.event_time < first_compromise_time):
            first_compromise_time = art.event_time

        if art.event_id in (4624, 4625):
            # 兼容 evtx_parser 的 IpAddress/TargetUserName 与旧快照的 SourceIP/TargetUser
            src_ip = str(pdata.get("IpAddress") or pdata.get("SourceIP") or "").strip()
            target_user = str(pdata.get("TargetUserName") or pdata.get("TargetUser") or "Administrator").strip()
            target_domain = str(pdata.get("TargetDomainName") or "").strip()
            logon_type = str(pdata.get("LogonType") or "")
            full_user = f"{target_domain}\\{target_user}" if target_domain and target_domain != "-" else target_user

            if art.event_id == 4625:
                has_4625_bruteforce = True

            if src_ip and src_ip not in ("-", "127.0.0.1", "::1", "0.0.0.0"):
                if src_ip not in attacker_ips:
                    attacker_ips.append(src_ip)
                att_node = f"ip_{src_ip}"
                if att_node in nodes_map or shown_counts["attacker"] < MAX_NODES_PER_TYPE:
                    if att_node not in nodes_map:
                        shown_counts["attacker"] += 1
                    add_node(
                        att_node,
                        f"🚨 外部攻击源 IP\n{src_ip}",
                        "attacker",
                        "critical" if art.event_id == 4624 else "high",
                        {"ip": src_ip, "user": full_user},
                    )
                    if art.event_id == 4624:
                        nodes_map[att_node]["risk"] = "critical"

                    edge_lbl = (
                        f"4624 RDP登录/爆破 ({target_user})"
                        if (art.event_id == 4624 or has_4625_bruteforce)
                        else f"4625 RDP远程爆破 ({target_user})"
                    )
                    add_edge(att_node, h_node, edge_lbl, "critical" if art.event_id == 4624 else "high")
                else:
                    overflow_counts["attacker"] += 1

                if art.event_id == 4624:
                    entry_vectors_detected = [
                        v for v in entry_vectors_detected if not v.startswith(f"RDP 远程口令暴力破解 ({src_ip}")
                    ]
                    vec_desc = (
                        f"RDP 暴力破解与远程登录 ({src_ip} -> {full_user})"
                        if (logon_type == "10" or has_4625_bruteforce)
                        else f"外部网络认证突破 Type={logon_type} ({src_ip} -> {full_user})"
                    )
                    if vec_desc not in entry_vectors_detected:
                        entry_vectors_detected.append(vec_desc)
                elif art.event_id == 4625 and not entry_vectors_detected:
                    vec_desc = f"RDP 远程口令暴力破解 ({src_ip} -> {full_user})"
                    if vec_desc not in entry_vectors_detected:
                        entry_vectors_detected.append(vec_desc)

        elif art.event_id == 4688:
            new_proc = str(pdata.get("NewProcessName") or "powershell.exe")
            proc_short = new_proc.replace("/", "\\").split("\\")[-1]
            parent_proc = str(pdata.get("ParentProcessName") or "")
            parent_short = parent_proc.replace("/", "\\").split("\\")[-1].lower()
            cmd_line = str(pdata.get("CommandLine") or "")
            decoded = pdata.get("DecodedPayload") or decode_powershell_base64(cmd_line)
            proc_node = f"proc_{art.id}"
            if shown_counts["process"] < MAX_NODES_PER_TYPE:
                shown_counts["process"] += 1
                add_node(
                    proc_node,
                    f"高危进程 [4688]\n{proc_short}",
                    "process",
                    "critical" if decoded else art.risk_level,
                    {"command": cmd_line, "decoded": decoded},
                )
                add_edge(h_node, proc_node, "4688 派生进程" + (" (-enc载荷)" if decoded else ""), "critical" if decoded else "high")
            else:
                overflow_counts["process"] += 1

            suspicious_processes.append(
                {
                    "hostname": host_id_map[art.host_id].hostname if art.host_id in host_id_map else "目标主机",
                    "process": proc_short,
                    "full_path": new_proc,
                    "command_line": cmd_line,
                    "decoded": decoded or "",
                }
            )
            # 检测 Web 容器派生命令执行 (WebShell 突破口)
            if parent_short in ("w3wp.exe", "tomcat.exe", "java.exe", "javaw.exe", "php-cgi.exe", "httpd.exe", "nginx.exe"):
                vec_web = f"Web容器漏洞/Webshell命令执行 ({parent_short} -> {proc_short})"
                if vec_web not in entry_vectors_detected:
                    entry_vectors_detected.append(vec_web)

        elif art.event_id == 7045:
            svc_name = str(pdata.get("ServiceName") or "MaliciousSvc")
            img_path = str(pdata.get("ImagePath") or "")
            decoded_svc = pdata.get("DecodedPayload") or decode_powershell_base64(img_path)
            svc_node = f"svc_{svc_name}"
            if svc_node in nodes_map or shown_counts["service"] < MAX_NODES_PER_TYPE:
                if svc_node not in nodes_map:
                    shown_counts["service"] += 1
                add_node(
                    svc_node,
                    f"高危服务 [7045]\n{svc_name}",
                    "service",
                    art.risk_level,
                    {"service_name": svc_name, "image_path": img_path, "decoded": decoded_svc},
                )
                add_edge(h_node, svc_node, "7045 注册高危服务", art.risk_level)
            else:
                overflow_counts["service"] += 1

            if not any(s["service_name"] == svc_name for s in malicious_services):
                malicious_services.append(
                    {
                        "hostname": host_id_map[art.host_id].hostname if art.host_id in host_id_map else "目标主机",
                        "service_name": svc_name,
                        "image_path": img_path,
                    }
                )

        elif art.event_id == 4720:
            sam_acc = str(
                pdata.get("TargetUserName")
                or pdata.get("SamAccountName")
                or pdata.get("TargetAccount")
                or "support$"
            ).strip()
            target_dom = str(pdata.get("TargetDomainName") or "").strip()
            display_acc = f"{target_dom}\\{sam_acc}" if target_dom and target_dom != "-" else sam_acc
            if display_acc not in backdoor_accounts:
                backdoor_accounts.append(display_acc)
            acc_node = f"acc_{sam_acc}"
            if acc_node in nodes_map or shown_counts["account"] < MAX_NODES_PER_TYPE:
                if acc_node not in nodes_map:
                    shown_counts["account"] += 1
                add_node(
                    acc_node,
                    f"影子后门账号 [4720]\n{sam_acc}",
                    "account",
                    "critical",
                    {"account": display_acc},
                )
                add_edge(h_node, acc_node, "4720 创建隐藏账户", "critical")
            else:
                overflow_counts["account"] += 1

    # 若同类型高危节点超过 8 个，添加折叠汇总节点
    if overflow_host_id is not None:
        target_h_node = f"host_{overflow_host_id}"
        if overflow_counts["attacker"] > 0:
            ov_id = "ip_overflow_summary"
            add_node(ov_id, f"📦 其余 {overflow_counts['attacker']} 个攻击源IP\n(已折叠聚合)", "attacker", "high")
            add_edge(ov_id, target_h_node, f"其余 {overflow_counts['attacker']} 次爆破/登录", "high")
        if overflow_counts["process"] > 0:
            ov_id = "proc_overflow_summary"
            add_node(ov_id, f"📦 其余 {overflow_counts['process']} 个高危进程\n(已折叠聚合)", "process", "high")
            add_edge(target_h_node, ov_id, f"其余 {overflow_counts['process']} 个 4688 进程", "high")
        if overflow_counts["service"] > 0:
            ov_id = "svc_overflow_summary"
            add_node(ov_id, f"📦 其余 {overflow_counts['service']} 个高危服务\n(已折叠聚合)", "service", "high")
            add_edge(target_h_node, ov_id, f"其余 {overflow_counts['service']} 个 7045 服务", "high")
        if overflow_counts["account"] > 0:
            ov_id = "acc_overflow_summary"
            add_node(ov_id, f"📦 其余 {overflow_counts['account']} 个异常账户\n(已折叠聚合)", "account", "high")
            add_edge(target_h_node, ov_id, f"其余 {overflow_counts['account']} 个 4720 账户", "high")

    # 汇总初始突破口 (Entry Vector)，杜绝在有明确入侵事件时显示“未知突破口”
    if entry_vectors_detected:
        entry_vector = " + ".join(entry_vectors_detected)
    elif suspicious_processes:
        entry_vector = f"恶意载荷投递与进程执行 ({suspicious_processes[0]['process']})"
    elif malicious_services:
        entry_vector = f"高危系统服务安装执行 ({malicious_services[0]['service_name']})"
    elif artifacts:
        entry_vector = "未检出高危外部入侵突破口 (常规系统日志基线)"
    else:
        entry_vector = "待上传更多安全审计日志进一步确认"

    # 若当前有多台主机，补充主机间横向移动边
    if len(hosts) > 1 and patient_zero_host:
        pz_node = f"host_{patient_zero_host.id}"
        for h in hosts:
            if h.id != patient_zero_host.id:
                add_edge(pz_node, f"host_{h.id}", "内网横向移动 (SMB/WMI)", "critical")

    # 3. 构建 0号病人画像 (Patient Zero Profile)
    industry_key = getattr(case_obj, "industry_type", "enterprise") or "enterprise"
    ind_profile = INDUSTRY_PROFILES.get(industry_key, INDUSTRY_PROFILES["enterprise"])

    detected_tactics: list[str] = []
    if attacker_ips or has_4625_bruteforce:
        detected_tactics.append("TA0001 Initial Access (T1110 暴力破解 / T1078 有效账户)")
    if suspicious_processes:
        detected_tactics.append("TA0002 Execution (T1059 命令与脚本解释器执行)")
    if malicious_services or backdoor_accounts:
        detected_tactics.append("TA0003 Persistence (T1543.003 Windows 服务 / T1136.001 账户创建)")
    if any(p.get("decoded") for p in suspicious_processes):
        detected_tactics.append("TA0005 Defense Evasion (T1027.010 Base64 命令混淆)")
    if not detected_tactics:
        detected_tactics.append("未检出高危 ATT&CK 攻击战术 (常规基线日志)")

    patient_zero_profile = {
        "hostname": patient_zero_host.hostname if patient_zero_host else "暂未上传主机证据",
        "ip_address": (patient_zero_host.ip_address if patient_zero_host else None) or "内网主机",
        "os_version": (patient_zero_host.os_version if patient_zero_host else None) or "Windows",
        "risk_score": patient_zero_host.risk_score if patient_zero_host else 0,
        "industry_type": industry_key,
        "industry_label": ind_profile["label"],
        "industry_short": ind_profile["short_label"],
        "first_compromise_time": first_compromise_time.strftime("%Y-%m-%d %H:%M:%S UTC") if first_compromise_time else "未检出高危失陷时间",
        "entry_vector": entry_vector,
        "attacker_ips": attacker_ips,
        "backdoor_accounts": backdoor_accounts,
        "malicious_services": [s["service_name"] for s in malicious_services],
        "mitre_tactics": detected_tactics,
    }

    # 4. 动态生成人工审核修复命令卡片 (支持一键复制 CMD / PowerShell，结合客户行业场景输出差异化加固脚本)
    remediation_cards: list[dict[str, Any]] = []

    if industry_key == "hospital":
        remediation_cards.append(
            {
                "id": "industry_hospital_guard",
                "category": "医疗卫健专属加固 (HIS/防勒索优先)",
                "severity": "critical",
                "title": "【医院场景红线】保持 HIS 业务连续性、开启微隔离与防勒索卷影保护",
                "description": "医院场景严禁直接中断 HIS/LIS/PACS 核心服务或盲目断网。优先仅封禁高危横向端口(445/135)并检查开启 VSS 卷影副本防勒索保护。",
                "cmd": 'vssadmin list shadows & sc.exe config vss start= demand & net start vss & netsh advfirewall firewall add rule name="WinDFIR_Hospital_MicroSeg_SMB" dir=in action=block protocol=TCP localport=445',
                "powershell": 'Get-Service vss | Set-Service -StartupType Manual -PassThru | Start-Service; New-NetFirewallRule -DisplayName "WinDFIR_Hospital_Block_SMB_445" -Direction Inbound -Protocol TCP -LocalPort 445,135 -Action Block',
            }
        )
    elif industry_key == "university":
        remediation_cards.append(
            {
                "id": "industry_university_guard",
                "category": "高校科研专属加固 (挖矿/暗链/弱口令)",
                "severity": "high",
                "title": "【高校场景专项】排查门罗币挖矿进程/计划任务、Web站群暗链与弱口令",
                "description": "针对高校科研算力节点与站群服务器，重点排查高 CPU 占用挖矿木马(xmrig)、恶意定时任务及 IIS/Tomcat 目录下近期篡改的脚本。",
                "cmd": 'schtasks /query /fo LIST /v | findstr /i "powershell cmd http temp xmrig" & net accounts /minpwlen:12 /lockoutthreshold:5',
                "powershell": 'Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } | Select-Object TaskName,TaskPath,@{N="Actions";E={$_.Actions.Execute + " " + $_.Actions.Arguments}} | Where-Object { $_.Actions -match "powershell|cmd|http|temp|xmrig" }; Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name,Id,CPU,Path',
            }
        )
    else:
        remediation_cards.append(
            {
                "id": "industry_enterprise_guard",
                "category": "政企集团专属加固 (AD域控/防横向/防泄密)",
                "severity": "critical",
                "title": "【政企内网专项】清理 Kerberos 缓存票据、审计域控特权组与防商业机密外传",
                "description": "针对政企集团内网，立即清除主机缓存的 Kerberos 票据与凭据防止哈希传递(PtH)/票据传递(PtT)，并核查域管理员组成员是否被异常篡改。",
                "cmd": 'klist purge & net group "Domain Admins" /domain & net localgroup administrators',
                "powershell": 'klist purge; Get-LocalGroupMember -Group "Administrators"; Get-ChildItem -Path C:\\Users,C:\\ProgramData,C:\\Windows\\Temp -Include *.7z,*.rar,*.zip -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-3) }',
            }
        )

    for ip in attacker_ips:
        remediation_cards.append(
            {
                "id": f"block_ip_{ip}",
                "category": "网络隔离与封禁",
                "severity": "critical",
                "title": f"封禁外部攻击源 / C2 IP ({ip})",
                "description": f"通过 Windows 高级安全防火墙阻断恶意源 IP {ip} 的入站与出站双向通信，切断 C2 回连通道。",
                "cmd": f'netsh advfirewall firewall add rule name="WinDFIR_Block_{ip}" dir=in action=block remoteip={ip} & netsh advfirewall firewall add rule name="WinDFIR_Block_{ip}_Out" dir=out action=block remoteip={ip}',
                "powershell": f'New-NetFirewallRule -DisplayName "WinDFIR_Block_{ip}_In" -Direction Inbound -RemoteAddress "{ip}" -Action Block; New-NetFirewallRule -DisplayName "WinDFIR_Block_{ip}_Out" -Direction Outbound -RemoteAddress "{ip}" -Action Block',
            }
        )

    for acc in backdoor_accounts:
        clean_acc = acc.split("\\")[-1]
        remediation_cards.append(
            {
                "id": f"del_user_{clean_acc}",
                "category": "后门账号查杀",
                "severity": "critical",
                "title": f"禁用并彻底清除影子后门账户 ({acc})",
                "description": f"事件 4720 监测到攻击者创建了隐藏账户 {acc}，请立即在受控主机或域控上禁用并删除该账户，同时排查 SAM 注册表克隆。",
                "cmd": f'net user "{clean_acc}" /active:no & net user "{clean_acc}" /delete',
                "powershell": f'Disable-LocalUser -Name "{clean_acc}" -ErrorAction SilentlyContinue; Remove-LocalUser -Name "{clean_acc}" -ErrorAction Stop',
            }
        )

    for svc in malicious_services[:8]:
        sname = svc["service_name"]
        remediation_cards.append(
            {
                "id": f"del_svc_{sname}",
                "category": "持久化服务清除",
                "severity": "critical",
                "title": f"停止并卸载恶意持久化服务 ({sname})",
                "description": f"事件 7045 发现高危系统服务 [{sname}]，可执行路径: {svc['image_path']}。建议人工复核后停止服务并从注册表中移除。",
                "cmd": f'sc.exe stop "{sname}" & sc.exe delete "{sname}"',
                "powershell": f'Stop-Service -Name "{sname}" -Force -ErrorAction SilentlyContinue; sc.exe delete "{sname}"; Remove-Item -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\{sname}" -Recurse -Force -ErrorAction SilentlyContinue',
            }
        )

    if suspicious_processes:
        remediation_cards.append(
            {
                "id": "kill_powershell_c2",
                "category": "恶意进程终止",
                "severity": "high",
                "title": "终止驻留内存的可疑 PowerShell / 载荷进程",
                "description": "事件 4688 捕获到带有 -enc Base64 混淆参数的 PowerShell 无文件驻留进程，建议排查并强制结束异常进程树。",
                "cmd": 'taskkill /F /IM powershell.exe /T',
                "powershell": 'Get-CimInstance Win32_Process -Filter "Name = \'powershell.exe\'" | Where-Object { $_.CommandLine -match "-enc|FromBase64String|DownloadString|Hidden" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }',
            }
        )

    if not remediation_cards:
        remediation_cards.append(
            {
                "id": "default_audit_check",
                "category": "应急基线加固",
                "severity": "medium",
                "title": "开启全量 PowerShell 模块与命令行审计策略",
                "description": "当前案件暂无特定 IOC 处置项，建议加固主机安全审计基线。",
                "cmd": 'auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable',
                "powershell": 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord',
            }
        )

    from services.vuln_matcher import (
        build_persistence_checklist,
        detect_ransomware_and_rats,
        extract_and_match_cves,
    )

    cve_matches = extract_and_match_cves(artifacts, hosts)
    ransomware_rat_alerts = detect_ransomware_and_rats(artifacts, hosts)
    persistence_checklist = build_persistence_checklist(artifacts)
    patient_zero_profile["ransomware_rat_alerts"] = ransomware_rat_alerts

    return {
        "case_id": case_id,
        "topology": {
            "nodes": list(nodes_map.values()),
            "edges": edges_list,
        },
        "patient_zero": patient_zero_profile,
        "remediation_cards": remediation_cards,
        "cve_matches": cve_matches,
        "ransomware_rat_alerts": ransomware_rat_alerts,
        "persistence_checklist": persistence_checklist,
    }


# ==============================================================================
# 5. 导出标准应急响应 Word 报告接口 (/api/cases/{case_id}/export-word)
# ==============================================================================
@router.get(
    "/api/cases/{case_id}/export-word",
    summary="一键导出案件完整应急响应溯源 Word 报告 (.doc)",
)
async def export_case_word_report(
    case_id: int,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """
    生成兼容 Microsoft Word / WPS 直接打开的标准 `.doc` 应急响应溯源报告文件，
    包含：案件概况、0号病人画像、IOC 威胁情报表格、高危事件时间线（含 Base64 解码明文）、AI 溯源分析与修复命令。
    """
    case_obj = await db.get(Case, case_id)
    if not case_obj:
        raise HTTPException(status_code=404, detail=f"未找到 ID={case_id} 的应急案件")

    topo_data = await get_case_topology_and_remediation(case_id, db)
    pz = topo_data["patient_zero"]
    rem_cards = topo_data["remediation_cards"]
    cve_matches = topo_data.get("cve_matches", [])
    rr_alerts = topo_data.get("ransomware_rat_alerts", [])

    cve_rows_html = ""
    for idx, cve in enumerate(cve_matches, 1):
        cve_rows_html += f"""
        <tr>
            <td>{idx}</td>
            <td><b style="color:#b91c1c;">{html.escape(str(cve.get('cve_id', '')))}</b><br/><span>CVSS: {cve.get('cvss', '')}</span></td>
            <td><b>{html.escape(str(cve.get('vuln_name', '')))}</b><br/><span style="color:#475569;">组件: {html.escape(str(cve.get('component', '')))}</span></td>
            <td style="font-family:Consolas,monospace;font-size:8.5pt;color:#991b1b;background:#fef2f2;">{html.escape(str(cve.get('extracted_poc', '')))}</td>
            <td style="font-size:9pt;"><b>原理:</b> {html.escape(str(cve.get('principle', '')))}<br/><b>修复建议:</b> {html.escape(str(cve.get('remediation', '')))}</td>
        </tr>
        """

    rr_alert_html = ""
    for alert in rr_alerts:
        rr_alert_html += f"""
        <div style="margin-bottom:8px;padding:8px;border:1px solid #f87171;background:#fef2f2;">
            <p style="margin:0 0 4px 0;font-weight:bold;color:#b91c1c;">[{html.escape(str(alert.get('type', '')).upper())}] {html.escape(str(alert.get('name', '')))} (涉案主机: {html.escape(str(alert.get('host', '')))})</p>
            <p style="margin:0 0 4px 0;font-size:9pt;color:#7f1d1d;"><b>关键情报提示:</b> {html.escape(str(alert.get('decryptor_info', '')))}</p>
            <p style="margin:0;font-family:Consolas,monospace;font-size:8.5pt;color:#334155;"><b>证据载荷:</b> {html.escape(str(alert.get('evidence', '')))}</p>
        </div>
        """

    artifacts = (
        await db.execute(
            select(HostArtifact)
            .where(HostArtifact.case_id == case_id)
            .order_by(HostArtifact.event_time.asc(), HostArtifact.id.asc())
        )
    ).scalars().all()

    iocs = (
        await db.execute(select(IOCIntelligence).where(IOCIntelligence.case_id == case_id))
    ).scalars().all()

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    ioc_rows_html = ""
    for idx, ioc in enumerate(iocs, 1):
        tags_str = ", ".join(ioc.tags) if isinstance(ioc.tags, list) else str(ioc.tags or "")
        ioc_rows_html += f"""
        <tr>
            <td>{idx}</td>
            <td><b>{html.escape(str(ioc.ioc_type).upper())}</b></td>
            <td style="color:#b91c1c;font-family:Consolas,monospace;">{html.escape(str(ioc.ioc_value))}</td>
            <td>{html.escape(str(ioc.threat_level).upper())} ({ioc.confidence}%)</td>
            <td>{html.escape(tags_str)}</td>
            <td>{html.escape(str(ioc.source or 'Local DFIR Engine'))}</td>
        </tr>
        """

    timeline_rows_html = ""
    for idx, art in enumerate(artifacts, 1):
        pdata = art.parsed_data or {}
        decoded = (
            pdata.get("DecodedPayload")
            or decode_powershell_base64(str(pdata.get("CommandLine") or pdata.get("ImagePath") or art.summary or ""))
            or ""
        )
        t_str = art.event_time.strftime("%Y-%m-%d %H:%M:%S") if art.event_time else "N/A"
        decoded_block = (
            f"<div style='margin-top:4px;padding:4px;background:#fef2f2;border:1px solid #f87171;color:#991b1b;font-family:Consolas,monospace;font-size:9pt;'>"
            f"<b>[Base64 解码明文]:</b> {html.escape(str(decoded))}</div>"
            if decoded
            else ""
        )
        ai_block = (
            f"<div style='margin-top:4px;color:#1e3a8a;font-size:9pt;'><b>[AI 研判]:</b> {html.escape(str(art.ai_analysis))}</div>"
            if art.ai_analysis
            else ""
        )
        timeline_rows_html += f"""
        <tr>
            <td>{idx}</td>
            <td style="font-family:Consolas,monospace;">{t_str}</td>
            <td><b>Event {art.event_id}</b></td>
            <td>{html.escape(str(art.risk_level).upper())}</td>
            <td>{html.escape(str(art.summary or ''))}{decoded_block}{ai_block}</td>
        </tr>
        """

    rem_rows_html = ""
    for card in rem_cards:
        rem_rows_html += f"""
        <div style="margin-bottom:12px;padding:10px;border:1px solid #cbd5e1;background:#f8fafc;">
            <p style="margin:0 0 4px 0;font-weight:bold;color:#0f172a;">[{html.escape(card['category'])}] {html.escape(card['title'])}</p>
            <p style="margin:0 0 6px 0;font-size:9.5pt;color:#475569;">{html.escape(card['description'])}</p>
            <p style="margin:0 0 4px 0;font-family:Consolas,monospace;font-size:9pt;background:#e2e8f0;padding:4px;"><b>CMD:</b> {html.escape(card['cmd'])}</p>
            <p style="margin:0;font-family:Consolas,monospace;font-size:9pt;background:#dbeafe;padding:4px;"><b>PowerShell:</b> {html.escape(card['powershell'])}</p>
        </div>
        """

    ai_summary_escaped = html.escape(case_obj.ai_summary or "尚未触发 AI 研判总结。").replace("\n", "<br/>")

    word_html = f"""<html xmlns:o='urn:schemas-microsoft-com:office:office' xmlns:w='urn:schemas-microsoft-com:office:word' xmlns='http://www.w3.org/TR/REC-html40'>
<head>
<meta charset="utf-8">
<title>{html.escape(case_obj.case_code)} 应急响应溯源报告</title>
<style>
    body {{ font-family: "Microsoft YaHei", "SimSun", sans-serif; font-size: 10.5pt; color: #1e293b; line-height: 1.6; }}
    h1 {{ font-size: 18pt; color: #0f172a; text-align: center; border-bottom: 2px solid #0f172a; padding-bottom: 10px; }}
    h2 {{ font-size: 13.5pt; color: #1d4ed8; border-left: 4px solid #1d4ed8; padding-left: 8px; margin-top: 20px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 8px; margin-bottom: 14px; font-size: 9.5pt; }}
    th, td {{ border: 1px solid #94a3b8; padding: 6px 8px; text-align: left; vertical-align: top; }}
    th {{ background-color: #e2e8f0; font-weight: bold; color: #0f172a; }}
</style>
</head>
<body>
    <h1>WinDFIR-AI 网络安全应急响应与溯源分析报告</h1>
    <p style="text-align:center;color:#64748b;font-size:9.5pt;">
        案件编号：{html.escape(case_obj.case_code)} &nbsp;|&nbsp; 报告生成时间：{now_str} &nbsp;|&nbsp; 严重级别：{html.escape(str(case_obj.severity).upper())}
    </p>

    <h2>一、 应急案件概况与 0号病人画像</h2>
    <table>
        <tr><th width="20%">案件名称</th><td width="30%">{html.escape(case_obj.case_name)}</td><th width="20%">指挥官/分析员</th><td width="30%">{html.escape(case_obj.analyst or 'DFIR-Admin')}</td></tr>
        <tr><th>客户行业场景</th><td colspan="3"><b style="color:#0369a1;">{html.escape(str(pz.get('industry_label', '政企/集团内网')))}</b></td></tr>
        <tr><th>0号病人主机</th><td><b>{html.escape(str(pz['hostname']))}</b> ({html.escape(str(pz['ip_address']))})</td><th>主机风险评分</th><td><b style="color:#dc2626;">{pz['risk_score']} / 100</b></td></tr>
        <tr><th>首次失陷时间</th><td>{html.escape(str(pz['first_compromise_time']))}</td><th>初始突破口</th><td>{html.escape(str(pz['entry_vector']))}</td></tr>
        <tr><th>涉案攻击源 IP</th><td>{html.escape(', '.join(pz['attacker_ips']) or '无')}</td><th>植入后门账户</th><td>{html.escape(', '.join(pz['backdoor_accounts']) or '无')}</td></tr>
    </table>
    {rr_alert_html}

    <h2>二、 漏洞利用链与攻击 POC 载荷还原 (CVE & Exploit Matching)</h2>
    <table>
        <thead>
            <tr><th width="5%">序号</th><th width="15%">CVE/CNVD 编号</th><th width="20%">漏洞名称与受影响组件</th><th width="30%">提取的原始攻击 POC / Exploit 载荷</th><th width="30%">漏洞原理与官方修复/WAF封堵建议</th></tr>
        </thead>
        <tbody>
            {cve_rows_html or '<tr><td colspan="5">未检出已知高危漏洞利用 POC 载荷</td></tr>'}
        </tbody>
    </table>

    <h2>三、 威胁情报与失陷指标 (IOCs) 清单</h2>
    <table>
        <thead>
            <tr><th width="6%">序号</th><th width="10%">类型</th><th width="22%">IOC 指标值</th><th width="16%">威胁等级</th><th width="28%">威胁情报标签</th><th width="18%">情报源</th></tr>
        </thead>
        <tbody>
            {ioc_rows_html or '<tr><td colspan="6">暂无 IOC 记录</td></tr>'}
        </tbody>
    </table>

    <h2>三、 浓缩攻击时间轴与加密载荷还原 (Timeline)</h2>
    <table>
        <thead>
            <tr><th width="6%">序号</th><th width="18%">事件时间 (UTC)</th><th width="12%">Event ID</th><th width="10%">风险等级</th><th width="54%">事件摘要、Base64 解码明文与 AI 研判</th></tr>
        </thead>
        <tbody>
            {timeline_rows_html or '<tr><td colspan="5">暂无高危事件记录</td></tr>'}
        </tbody>
    </table>

    <h2>四、 人工审核应急处置与修复脚本 (CMD / PowerShell)</h2>
    {rem_rows_html}

    <h2>五、 AI 深度溯源总结报告</h2>
    <div style="padding:12px;border:1px solid #cbd5e1;background:#f8fafc;font-size:10pt;">
        {ai_summary_escaped}
    </div>
</body>
</html>"""

    filename = f"WinDFIR_Report_{case_obj.case_code}.doc"
    encoded_filename = quote(filename)
    return Response(
        content=word_html.encode("utf-8"),
        media_type="application/msword; charset=utf-8",
        headers={
            "Content-Disposition": f"attachment; filename=\"{filename}\"; filename*=UTF-8''{encoded_filename}"
        },
    )
