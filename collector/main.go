// WinDFIR-AI 阶段四：Windows 终端单文件自动取证采集器 (collector/main.go)
// 零第三方依赖（纯 Go 标准库实现），可直接交叉编译或本地编译为免安装单文件 WinDFIR-Collector.exe：
//   go build -ldflags="-s -w" -o WinDFIR-Collector.exe main.go
//
// 核心采集能力：
// 1. 主机基础画像：Hostname、内网 IPv4 列表、OS 版本、架构、当前用户 -> system_snapshot.json
// 2. 实时活动进程：枚举 PID、PPID、进程名、可执行路径、完整命令行参数，并自动计算可执行文件 SHA256
// 3. 实时网络连接：采集活动 TCP/UDP 外联与监听连接（含协议、本地地址、远程地址、状态、关联 PID）
// 4. 持久化驻留项：枚举系统计划任务 (Scheduled Tasks) 与注册表 Run / RunOnce 启动项
// 5. 核心安全日志：自动调用 wevtutil epl 导出（失败则回退直接拷贝）Security.evtx、System.evtx、PowerShell_Operational.evtx
//
// 双模式运行支持：
// - 离线模式（默认双击运行或无参运行）：在当前目录打包生成 Forensic_<Hostname>_<Timestamp>.zip
// - 在线回传模式：WinDFIR-Collector.exe --server http://127.0.0.1:8000 --case-id 1 [--industry enterprise]
//   自动通过 HTTP Multipart POST 上传至作战台对应案件并触发 EVTX 解析与威胁评分。

package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ProcessInfo 活动进程结构与 SHA256 哈希
type ProcessInfo struct {
	PID         int    `json:"pid"`
	PPID        int    `json:"ppid"`
	Name        string `json:"name"`
	Executable  string `json:"executable"`
	CommandLine string `json:"command_line"`
	SHA256      string `json:"sha256,omitempty"`
}

// NetConnectionInfo 活动 TCP/UDP 网络连接
type NetConnectionInfo struct {
	Protocol    string `json:"protocol"`
	LocalAddr   string `json:"local_address"`
	RemoteAddr  string `json:"remote_address"`
	State       string `json:"state"`
	OwningPID   int    `json:"pid"`
	IsExternal  bool   `json:"is_external"`
}

// ScheduledTaskInfo 计划任务持久化项
type ScheduledTaskInfo struct {
	TaskName string `json:"task_name"`
	NextRun  string `json:"next_run_time"`
	Status   string `json:"status"`
	Command  string `json:"command,omitempty"`
}

// RegistryRunItem 注册表自启动项
type RegistryRunItem struct {
	HiveKey string `json:"hive_key"`
	Name    string `json:"name"`
	Value   string `json:"value"`
}

// SystemSnapshot 主机全景取证快照 (system_snapshot.json)
type SystemSnapshot struct {
	CollectorVersion   string              `json:"collector_version"`
	CollectedAt        string              `json:"collected_at"`
	Hostname           string              `json:"hostname"`
	IPAddress          string              `json:"ip_address"`
	AllIPv4Addresses   []string            `json:"all_ipv4_addresses"`
	OSVersion          string              `json:"os_version"`
	Architecture       string              `json:"architecture"`
	IsAdmin            bool                `json:"is_admin"`
	ExportedEvtxFiles  []string            `json:"exported_evtx_files"`
	Processes          []ProcessInfo       `json:"processes"`
	NetworkConnections []NetConnectionInfo `json:"network_connections"`
	ScheduledTasks     []ScheduledTaskInfo `json:"scheduled_tasks"`
	RegistryRunItems   []RegistryRunItem   `json:"registry_run_items"`
}

func main() {
	serverURL := flag.String("server", "", "作战台后端服务地址 (例如 http://127.0.0.1:8000)，留空则为纯离线打包模式")
	caseID := flag.String("case-id", "1", "在线回传关联的应急案件 ID 或案件编号 (例如 1 或 IR-20261021-21CEDA 或 20261021-21CEDA)")
	flag.StringVar(caseID, "CaseId", "1", "在线回传关联的应急案件 ID 或案件编号 (PowerShell 风格别名)")
	outputDir := flag.String("out", ".", "取证 ZIP 压缩包输出目录 (默认当前目录)")
	flag.Parse()

	printBanner()

	startTime := time.Now()
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "WIN-UNKNOWN"
	}
	primaryIP, allIPs := getInternalIPv4List()
	osVer := getWindowsOSVersion()
	isAdmin := checkAdminPrivilege()

	fmt.Printf("[*] 目标主机名   : %s\n", hostname)
	fmt.Printf("[*] 内网 IPv4    : %s (全部: %v)\n", primaryIP, allIPs)
	fmt.Printf("[*] 操作系统版本 : %s (%s)\n", osVer, runtime.GOARCH)
	fmt.Printf("[*] 管理员权限   : %v\n", isAdmin)
	if !isAdmin {
		fmt.Println("[!] 警告: 当前未以管理员权限运行，Security.evtx 导出可能受限，建议右键「以管理员身份运行」！")
	}

	// 创建临时工作目录存放待打包的取证文件
	workDir, err := os.MkdirTemp("", "windfir_collect_*")
	if err != nil {
		fmt.Printf("[-] 创建临时采集目录失败: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(workDir)

	// 1. 采集活动进程（含 PID、PPID、命令行与可执行文件 SHA256）
	fmt.Println("\n[1/5] 正在枚举活动进程、命令行参数并计算映像 SHA256...")
	processes := collectProcesses()
	fmt.Printf("  [+] 共采集活动进程 %d 个\n", len(processes))

	// 2. 采集活动 TCP/UDP 网络连接
	fmt.Println("[2/5] 正在采集活动 TCP/UDP 外联网络连接...")
	netConns := collectNetworkConnections()
	fmt.Printf("  [+] 共采集活动网络连接 %d 条\n", len(netConns))

	// 3. 采集计划任务与注册表 Run 启动项
	fmt.Println("[3/5] 正在采集计划任务与注册表 Run/RunOnce 持久化启动项...")
	tasks := collectScheduledTasks()
	regRuns := collectRegistryRunKeys()
	fmt.Printf("  [+] 计划任务 %d 项，注册表启动项 %d 项\n", len(tasks), len(regRuns))

	// 4. 导出 Windows 核心事件日志 (.evtx)
	fmt.Println("[4/5] 正在导出 Windows 核心事件日志 (Security / System / PowerShell)...")
	exportedEvtx := exportEvtxLogs(workDir)
	fmt.Printf("  [+] 成功导出 .evtx 日志文件 %d 个: %v\n", len(exportedEvtx), exportedEvtx)

	// 5. 生成 system_snapshot.json 并打包为 Forensic_主机名_时间戳.zip
	fmt.Println("[5/5] 正在生成 system_snapshot.json 并封装取证 ZIP 压缩包...")
	snapshot := SystemSnapshot{
		CollectorVersion:   "WinDFIR-Collector v2.0 (Go Native)",
		CollectedAt:        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Hostname:           hostname,
		IPAddress:          primaryIP,
		AllIPv4Addresses:   allIPs,
		OSVersion:          osVer,
		Architecture:       runtime.GOARCH,
		IsAdmin:            isAdmin,
		ExportedEvtxFiles:  exportedEvtx,
		Processes:          processes,
		NetworkConnections: netConns,
		ScheduledTasks:     tasks,
		RegistryRunItems:   regRuns,
	}

	snapshotBytes, _ := json.MarshalIndent(snapshot, "", "  ")
	snapshotFile := filepath.Join(workDir, "system_snapshot.json")
	_ = os.WriteFile(snapshotFile, snapshotBytes, 0644)

	ts := time.Now().Format("20060102_150405")
	safeHost := sanitizeFilename(hostname)
	zipFilename := fmt.Sprintf("Forensic_%s_%s.zip", safeHost, ts)
	finalZipPath := filepath.Join(*outputDir, zipFilename)

	if err := createZipArchive(workDir, finalZipPath); err != nil {
		fmt.Printf("[-] 打包 ZIP 取证文件失败: %v\n", err)
		os.Exit(1)
	}

	zipStat, _ := os.Stat(finalZipPath)
	sizeKB := float64(0)
	if zipStat != nil {
		sizeKB = float64(zipStat.Size()) / 1024.0
	}

	fmt.Println("========================================================================")
	fmt.Printf("[+] 离线取证包生成完毕 (耗时 %s):\n", time.Since(startTime).Round(time.Millisecond))
	fmt.Printf("    文件路径: %s (%.1f KB)\n", finalZipPath, sizeKB)
	fmt.Println("========================================================================")

	// 若指定了 --server 参数，执行在线自动回传模式
	cleanServer := strings.TrimSpace(*serverURL)
	cleanCaseID := strings.TrimSpace(*caseID)
	if cleanServer != "" && cleanCaseID != "" {
		fmt.Printf("\n[*] 检测到在线回传参数，正在上传取证包至 %s (Case: %s)...\n", cleanServer, cleanCaseID)
		err := uploadArchiveToServer(strings.TrimRight(cleanServer, "/"), cleanCaseID, hostname, primaryIP, osVer, finalZipPath)
		if err != nil {
			fmt.Printf("[-] 在线上传失败: %v\n", err)
			fmt.Println("[!] 离线取证包已保留在本地，您仍可直接将其拖拽至作战台网页上传。")
			os.Exit(1)
		}
	} else {
		fmt.Println("[💡 提示] 您可直接将生成的 .zip 文件拖拽至 WinDFIR-AI 作战台左下角完成导入解析，")
		fmt.Println("         或使用在线模式自动上传: WinDFIR-Collector.exe --server http://127.0.0.1:8000 --case-id IR-20261021-XXXXXX")
	}
}

func printBanner() {
	fmt.Println("========================================================================")
	fmt.Println("   🛡️  WinDFIR-AI Windows 应急响应自动化取证采集器 v2.0")
	fmt.Println("   支持：主机快照 / 进程SHA256 / 网络连接 / 持久化项 / EVTX全量导出")
	fmt.Println("========================================================================")
}

// checkAdminPrivilege 检测当前进程是否具备 Windows 管理员权限
func checkAdminPrivilege() bool {
	if runtime.GOOS != "windows" {
		return os.Geteuid() == 0
	}
	cmd := exec.Command("net", "session")
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

// getInternalIPv4List 获取本机非回环 IPv4 地址列表
func getInternalIPv4List() (string, []string) {
	var ips []string
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					ipStr := ip4.String()
					if !strings.HasPrefix(ipStr, "169.254.") {
						ips = append(ips, ipStr)
					}
				}
			}
		}
	}
	if len(ips) == 0 {
		return "127.0.0.1", []string{"127.0.0.1"}
	}
	return ips[0], ips
}

// getWindowsOSVersion 获取 Windows 操作系统版本名称
func getWindowsOSVersion() string {
	if runtime.GOOS != "windows" {
		return fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
	}
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-CimInstance Win32_OperatingSystem).Caption").Output()
	if err == nil && len(bytes.TrimSpace(out)) > 0 {
		return strings.TrimSpace(string(out))
	}
	outVer, err := exec.Command("cmd", "/c", "ver").Output()
	if err == nil {
		return strings.TrimSpace(string(outVer))
	}
	return "Windows"
}

// collectProcesses 枚举当前活动进程（含 PID、PPID、命令行与 SHA256）
func collectProcesses() []ProcessInfo {
	var results []ProcessInfo
	if runtime.GOOS != "windows" {
		return results
	}

	psScript := `Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Json -Compress`
	out, err := exec.Command("powershell", "-NoProfile", "-Command", psScript).Output()
	if err != nil || len(out) == 0 {
		return results
	}

	type rawWinProc struct {
		ProcessId       int    `json:"ProcessId"`
		ParentProcessId int    `json:"ParentProcessId"`
		Name            string `json:"Name"`
		ExecutablePath  string `json:"ExecutablePath"`
		CommandLine     string `json:"CommandLine"`
	}

	var rawList []rawWinProc
	trimmed := bytes.TrimSpace(out)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		_ = json.Unmarshal(trimmed, &rawList)
	} else if len(trimmed) > 0 && trimmed[0] == '{' {
		var single rawWinProc
		if json.Unmarshal(trimmed, &single) == nil {
			rawList = append(rawList, single)
		}
	}

	hashCache := make(map[string]string)
	for _, rp := range rawList {
		sha := ""
		exePath := strings.TrimSpace(rp.ExecutablePath)
		if exePath != "" {
			if cached, ok := hashCache[exePath]; ok {
				sha = cached
			} else {
				sha = computeFileSHA256(exePath, 32*1024*1024) // 仅对 <=32MB 的二进制计算哈希以保证极速采集
				hashCache[exePath] = sha
			}
		}
		results = append(results, ProcessInfo{
			PID:         rp.ProcessId,
			PPID:        rp.ParentProcessId,
			Name:        rp.Name,
			Executable:  exePath,
			CommandLine: rp.CommandLine,
			SHA256:      sha,
		})
	}
	return results
}

func computeFileSHA256(path string, maxBytes int64) string {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() > maxBytes {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// collectNetworkConnections 解析 netstat -ano 获取活动 TCP/UDP 连接
func collectNetworkConnections() []NetConnectionInfo {
	var conns []NetConnectionInfo
	if runtime.GOOS != "windows" {
		return conns
	}
	out, err := exec.Command("netstat", "-ano").Output()
	if err != nil {
		return conns
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 4 {
			continue
		}
		proto := strings.ToUpper(fields[0])
		if proto != "TCP" && proto != "UDP" {
			continue
		}
		localAddr := fields[1]
		remoteAddr := fields[2]
		state := "STATELESS"
		pidStr := fields[3]
		if proto == "TCP" && len(fields) >= 5 {
			state = fields[3]
			pidStr = fields[4]
		}
		pid, _ := strconv.Atoi(pidStr)
		isExt := isExternalAddress(remoteAddr)
		conns = append(conns, NetConnectionInfo{
			Protocol:   proto,
			LocalAddr:  localAddr,
			RemoteAddr: remoteAddr,
			State:      state,
			OwningPID:  pid,
			IsExternal: isExt,
		})
	}
	return conns
}

func isExternalAddress(addrPort string) bool {
	host, _, err := net.SplitHostPort(addrPort)
	if err != nil {
		return false
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return false
	}
	return true
}

// collectScheduledTasks 枚举非微软内置或活动计划任务
func collectScheduledTasks() []ScheduledTaskInfo {
	var tasks []ScheduledTaskInfo
	if runtime.GOOS != "windows" {
		return tasks
	}
	out, err := exec.Command("schtasks", "/query", "/fo", "CSV", "/nh").Output()
	if err != nil {
		return tasks
	}
	reader := csv.NewReader(bytes.NewReader(out))
	records, _ := reader.ReadAll()
	for _, rec := range records {
		if len(rec) < 3 {
			continue
		}
		tName := strings.TrimSpace(rec[0])
		if tName == "" || strings.HasPrefix(tName, "\\Microsoft\\Windows\\") {
			continue
		}
		tasks = append(tasks, ScheduledTaskInfo{
			TaskName: tName,
			NextRun:  strings.TrimSpace(rec[1]),
			Status:   strings.TrimSpace(rec[2]),
		})
		if len(tasks) >= 60 {
			break
		}
	}
	return tasks
}

// collectRegistryRunKeys 采集 HKLM 与 HKCU 下的 Run / RunOnce 启动项
func collectRegistryRunKeys() []RegistryRunItem {
	var items []RegistryRunItem
	if runtime.GOOS != "windows" {
		return items
	}
	keys := []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
	}
	for _, k := range keys {
		out, err := exec.Command("reg", "query", k).Output()
		if err != nil {
			continue
		}
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "HKEY_") {
				continue
			}
			parts := strings.Fields(trimmed)
			if len(parts) >= 3 && strings.HasPrefix(parts[1], "REG_") {
				val := strings.Join(parts[2:], " ")
				items = append(items, RegistryRunItem{
					HiveKey: k,
					Name:    parts[0],
					Value:   val,
				})
			}
		}
	}
	return items
}

// exportEvtxLogs 使用 wevtutil epl 导出或从 System32\winevt\Logs 拷贝三大核心 EVTX 日志
func exportEvtxLogs(destDir string) []string {
	var exported []string
	targets := []struct {
		Channel  string
		FileName string
		RawFile  string
	}{
		{"Security", "Security.evtx", `C:\Windows\System32\winevt\Logs\Security.evtx`},
		{"System", "System.evtx", `C:\Windows\System32\winevt\Logs\System.evtx`},
		{"Microsoft-Windows-PowerShell/Operational", "PowerShell_Operational.evtx", `C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx`},
	}

	for _, t := range targets {
		outPath := filepath.Join(destDir, t.FileName)
		// 方式 1：调用系统 wevtutil epl 安全导出活动日志
		cmd := exec.Command("wevtutil", "epl", t.Channel, outPath, "/ow:true")
		if err := cmd.Run(); err == nil {
			if st, err := os.Stat(outPath); err == nil && st.Size() > 0 {
				exported = append(exported, t.FileName)
				fmt.Printf("    [√] 已通过 wevtutil 导出: %s (%.1f KB)\n", t.FileName, float64(st.Size())/1024.0)
				continue
			}
		}
		// 方式 2：若 wevtutil 失败则尝试直接读取原始文件拷贝
		if err := copyFile(t.RawFile, outPath); err == nil {
			if st, err := os.Stat(outPath); err == nil && st.Size() > 0 {
				exported = append(exported, t.FileName)
				fmt.Printf("    [√] 已通过文件流拷贝: %s (%.1f KB)\n", t.FileName, float64(st.Size())/1024.0)
				continue
			}
		}
		fmt.Printf("    [!] 未能导出 %s (可能需要管理员权限)\n", t.FileName)
	}
	return exported
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func createZipArchive(sourceDir, zipFilePath string) error {
	zf, err := os.Create(zipFilePath)
	if err != nil {
		return err
	}
	defer zf.Close()

	zw := zip.NewWriter(zf)
	defer zw.Close()

	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		fullPath := filepath.Join(sourceDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			continue
		}
		header.Name = entry.Name()
		header.Method = zip.Deflate

		writer, err := zw.CreateHeader(header)
		if err != nil {
			return err
		}
		f, err := os.Open(fullPath)
		if err != nil {
			return err
		}
		_, _ = io.Copy(writer, f)
		f.Close()
	}
	return nil
}

// uploadArchiveToServer 在线回传模式：通过 HTTP POST 上传取证包到指定案件并触发解析
func uploadArchiveToServer(serverURL string, caseID string, hostname, ipAddr, osVer, zipPath string) error {
	file, err := os.Open(zipPath)
	if err != nil {
		return err
	}
	defer file.Close()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("hostname", hostname)
	_ = writer.WriteField("ip_address", ipAddr)
	_ = writer.WriteField("os_version", osVer)
	_ = writer.WriteField("sync_parse", "true")

	part, err := writer.CreateFormFile("file", filepath.Base(zipPath))
	if err != nil {
		return err
	}
	if _, err := io.Copy(part, file); err != nil {
		return err
	}
	writer.Close()

	apiURL := fmt.Sprintf("%s/api/cases/%s/hosts", serverURL, url.PathEscape(caseID))
	req, err := http.NewRequest("POST", apiURL, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBytes))
	}

	fmt.Println("[+] 在线回传并解析成功！服务端返回摘要：")
	fmt.Println(string(respBytes))
	return nil
}

func sanitizeFilename(name string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_", " ", "_")
	return replacer.Replace(name)
}
