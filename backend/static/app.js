/**
 * WinDFIR-AI 阶段三：前端可视化应急响应作战台核心逻辑 (static/app.js)
 * 技术栈：Vue 3 Global Build + Tailwind CSS + AntV G6 + Marked.js
 * 支持纯离线内网环境运行，完整对接 FastAPI 后端接口
 */

const { createApp, ref, reactive, computed, onMounted, nextTick, watch } = Vue;

const app = createApp({
  setup() {
    // =========================================================================
    // 1. 全局状态与当前选中案件
    // =========================================================================
    const loading = reactive({
      cases: false,
      hosts: false,
      artifacts: false,
      topology: false,
      analyzing: false,
      uploading: false,
      enriching: false,
      savingConfig: false,
      simulating: false,
    });

    const toast = reactive({
      show: false,
      type: "info", // info | success | error
      message: "",
    });

    const showToast = (message, type = "info", duration = 3800) => {
      toast.message = message;
      toast.type = type;
      toast.show = true;
      setTimeout(() => {
        toast.show = false;
      }, duration);
    };

    const cases = ref([]);
    const currentCaseId = ref(null);
    const hosts = ref([]);
    const selectedHostId = ref(null); // null 表示查看全案所有主机
    const artifacts = ref([]);
    const iocs = ref([]);
    const patientZero = ref({});
    const remediationCards = ref([]);
    const cveMatches = ref([]);
    const ransomwareRatAlerts = ref([]);
    const persistenceChecklist = ref([]);
    const simMenuOpen = ref(false);
    const aiSummaryMarkdown = ref("");
    const topologyData = ref({ nodes: [], edges: [] });

    // 时间轴筛选与分页条件
    const filterEventId = ref("");
    const filterRiskLevel = ref("");
    const searchKeyword = ref("");
    const hideLowBaseline = ref(false);
    const timelinePage = ref(1);
    const timelinePageSize = ref(15);

    // 5 大独立全屏页面导航: 'cases' (默认首页) | 'topology' | 'timeline' | 'ai_report' | 'remediation'
    const currentPage = ref("cases");
    const workspaceTab = ref("overview");
    const rightTab = ref("profile");

    const switchPage = async (pageName) => {
      currentPage.value = pageName;
      if (pageName === "topology") {
        await nextTick();
        setTimeout(() => renderG6Topology(), 40);
      }
    };

    const switchWorkspaceTab = async (tabName) => {
      await switchPage(tabName === "overview" ? "topology" : (tabName === "ai_intel" ? "ai_report" : tabName));
    };

    // 弹窗开关
    const modals = reactive({
      newCase: false,
      upload: false,
      settings: false,
      eventDetail: false,
    });

    const activeArtifact = ref(null);

    // 新建案件表单
    const newCaseForm = reactive({
      case_name: "",
      severity: "critical",
      industry_type: "enterprise",
      analyst: "DFIR-Commander",
      description: "",
    });

    const industryMap = {
      hospital: "🏥 医院/医疗卫健",
      enterprise: "🏢 政企/集团内网",
      university: "🎓 高校/科研机构",
    };

    // 上传取证包表单（主机名与 IP 均为选填，留空则由后端从 EVTX <Computer> 或快照自动提取）
    const uploadForm = reactive({
      hostname: "",
      ip_address: "",
      os_version: "Windows Server 2019 Datacenter",
      collector_type: "EVTX_PACKAGE",
      file: null,
      isDragging: false,
    });

    // 前端兜底 PowerShell Base64 解码函数（兼容 Windows PowerShell UTF-16LE 与 UTF-8）
    const decodePsBase64 = (rawText) => {
      if (!rawText || typeof rawText !== "string") return null;
      const match = rawText.match(/(?:-[eE][nN]?[cC]?(?:[oO][dD][eE][dD][cC][oO][mM][mM][aA][nN][dD])?|FromBase64String\s*\(\s*['"])\s*([A-Za-z0-9+/=]{12,})/i);
      if (!match) return null;
      let b64 = match[1].trim();
      while (b64.length % 4 !== 0) b64 += "=";
      try {
        const binaryStr = window.atob(b64);
        const bytes = new Uint8Array(binaryStr.length);
        let nullCount = 0;
        for (let i = 0; i < binaryStr.length; i++) {
          bytes[i] = binaryStr.charCodeAt(i);
          if (bytes[i] === 0) nullCount++;
        }
        // Windows PowerShell -enc 默认使用 UTF-16LE (每两个字节含一个 \x00)
        if (nullCount > bytes.length / 4) {
          return new TextDecoder("utf-16le").decode(bytes).replace(/\0/g, "").trim();
        }
        return new TextDecoder("utf-8").decode(bytes).replace(/\0/g, "").trim();
      } catch (_) {
        return null;
      }
    };

    // LLM 与微步/VT API 设置表单
    const llmForm = reactive({
      config_name: "DeepSeek-V3-DFIR",
      provider: "deepseek",
      base_url: "https://api.deepseek.com/v1",
      api_key: "",
      model_name: "deepseek-chat",
      temperature: 0.2,
      max_tokens: 4096,
      threatbook_api_key: "",
      vt_api_key: "",
      has_api_key: false,
      has_threatbook_key: false,
      has_vt_key: false,
    });

    // AntV G6 实例引用
    let g6Graph = null;

    // =========================================================================
    // 2. 计算属性
    // =========================================================================
    const currentCase = computed(() => {
      return cases.value.find((c) => c.id === currentCaseId.value) || null;
    });

    const isBaselineSafe = computed(() => {
      const score = patientZero.value?.risk_score || 0;
      const edgeCount = (topologyData.value?.edges || []).length;
      return hosts.value.length > 0 && score < 30 && edgeCount === 0;
    });

    const lowBaselineCount = computed(() => {
      return artifacts.value.filter((a) => !a.risk_level || a.risk_level === "low").length;
    });

    const filteredArtifacts = computed(() => {
      return artifacts.value.filter((a) => {
        if (selectedHostId.value && a.host_id !== selectedHostId.value) return false;
        if (hideLowBaseline.value && (!a.risk_level || a.risk_level === "low")) return false;
        if (filterEventId.value && String(a.event_id) !== String(filterEventId.value)) return false;
        if (filterRiskLevel.value && a.risk_level !== filterRiskLevel.value) return false;
        if (searchKeyword.value) {
          const kw = searchKeyword.value.toLowerCase();
          const text = `${a.summary || ""} ${a.decoded_payload || ""} ${JSON.stringify(a.parsed_data || {})}`.toLowerCase();
          if (!text.includes(kw)) return false;
        }
        return true;
      });
    });

    const totalTimelinePages = computed(() => {
      return Math.max(1, Math.ceil(filteredArtifacts.value.length / timelinePageSize.value));
    });

    const paginatedArtifacts = computed(() => {
      const start = (timelinePage.value - 1) * timelinePageSize.value;
      return filteredArtifacts.value.slice(start, start + timelinePageSize.value);
    });

    watch([selectedHostId, filterEventId, filterRiskLevel, hideLowBaseline, searchKeyword, currentCaseId, timelinePageSize], () => {
      timelinePage.value = 1;
    });

    const renderedAiMarkdown = computed(() => {
      const raw = aiSummaryMarkdown.value || currentCase.value?.ai_summary || "";
      if (!raw) {
        return `<div class="text-slate-400 text-xs py-6 text-center">尚未生成 AI 溯源报告，请点击顶部 <b>「⚡ 触发 AI 推理」</b> 按钮执行全案研判。</div>`;
      }
      if (window.marked && typeof window.marked.parse === "function") {
        return window.marked.parse(raw);
      }
      return `<pre class="whitespace-pre-wrap text-xs text-slate-200">${raw}</pre>`;
    });

    const stats = computed(() => {
      const critCount = artifacts.value.filter((a) => a.risk_level === "critical").length;
      const highCount = artifacts.value.filter((a) => a.risk_level === "high").length;
      const encCount = artifacts.value.filter((a) => a.decoded_payload).length;
      return {
        totalHosts: hosts.value.length,
        totalEvents: artifacts.value.length,
        criticalEvents: critCount,
        highEvents: highCount,
        decodedCount: encCount,
        iocCount: iocs.value.length,
      };
    });

    // =========================================================================
    // 3. API 交互方法
    // =========================================================================
    const apiFetch = async (url, options = {}) => {
      const res = await fetch(url, options);
      if (!res.ok) {
        let errDetail = `HTTP ${res.status}`;
        try {
          const errJson = await res.json();
          errDetail = errJson.detail || errJson.message || errDetail;
        } catch (_) {}
        throw new Error(errDetail);
      }
      return res.json();
    };

    // 加载案件列表
    const loadCases = async () => {
      loading.cases = true;
      try {
        const list = await apiFetch("/api/cases");
        cases.value = list;
        if (list.length > 0 && !currentCaseId.value) {
          await selectCase(list[0].id);
        }
      } catch (err) {
        showToast(`加载案件列表失败: ${err.message}`, "error");
      } finally {
        loading.cases = false;
      }
    };

    // 切换当前案件并加载全量关联数据
    const selectCase = async (caseId) => {
      currentCaseId.value = caseId;
      selectedHostId.value = null;
      await Promise.all([
        loadCaseHosts(caseId),
        loadCaseArtifacts(caseId),
        loadCaseIocs(caseId),
        loadCaseTopology(caseId),
        loadCaseReport(caseId),
      ]);
    };

    const loadCaseHosts = async (caseId) => {
      loading.hosts = true;
      try {
        const data = await apiFetch(`/api/cases/${caseId}/hosts`);
        const rawList = Array.isArray(data) ? data : (data.hosts || []);
        hosts.value = rawList.map((h, idx) => ({
          ...h,
          is_patient_zero: idx === 0 && (h.risk_score || 0) >= 40,
        }));
      } catch (err) {
        showToast(`加载涉案主机失败: ${err.message}`, "error");
      } finally {
        loading.hosts = false;
      }
    };

    const loadCaseArtifacts = async (caseId) => {
      loading.artifacts = true;
      try {
        const data = await apiFetch(`/api/cases/${caseId}/artifacts`);
        const rawArtifacts = data.artifacts || [];
        artifacts.value = rawArtifacts.map((art) => {
          const pdata = art.parsed_data || {};
          const rawCmd = pdata.CommandLine || pdata.ImagePath || art.summary || "";
          const decoded = art.decoded_payload || pdata.DecodedPayload || decodePsBase64(rawCmd);
          return {
            ...art,
            decoded_payload: decoded || null,
          };
        });
        // 若当前案件既有高/中危事件，又有大量 LOW 基线事件，自动开启“隐藏 LOW 级常规基线”开关避免刷屏
        const hasHighOrMed = artifacts.value.some((a) => ["critical", "high", "medium"].includes(a.risk_level));
        const hasLow = artifacts.value.some((a) => !a.risk_level || a.risk_level === "low");
        hideLowBaseline.value = hasHighOrMed && hasLow;
      } catch (err) {
        showToast(`加载攻击时间轴失败: ${err.message}`, "error");
      } finally {
        loading.artifacts = false;
      }
    };

    const loadCaseIocs = async (caseId) => {
      try {
        const data = await apiFetch(`/api/cases/${caseId}/iocs`);
        iocs.value = data.iocs || [];
      } catch (err) {
        console.error(err);
      }
    };

    const loadCaseReport = async (caseId) => {
      try {
        const data = await apiFetch(`/api/cases/${caseId}/report`);
        if (data.ai_summary_markdown && !data.ai_summary_markdown.startsWith("尚未执行")) {
          aiSummaryMarkdown.value = data.ai_summary_markdown;
        } else {
          aiSummaryMarkdown.value = "";
        }
      } catch (err) {
        console.error(err);
      }
    };

    const loadCaseTopology = async (caseId) => {
      loading.topology = true;
      try {
        const data = await apiFetch(`/api/cases/${caseId}/topology`);
        topologyData.value = data.topology || { nodes: [], edges: [] };
        patientZero.value = data.patient_zero || {};
        remediationCards.value = data.remediation_cards || [];
        cveMatches.value = data.cve_matches || [];
        ransomwareRatAlerts.value = data.ransomware_rat_alerts || [];
        persistenceChecklist.value = data.persistence_checklist || [];
        await nextTick();
        renderG6Topology();
      } catch (err) {
        showToast(`加载攻击拓扑图失败: ${err.message}`, "error");
      } finally {
        loading.topology = false;
      }
    };

    // 一键载入三大行业典型攻击仿真样本
    const loadSimulationCase = async (scenarioKey) => {
      simMenuOpen.value = false;
      loading.simulating = true;
      try {
        const res = await apiFetch(`/api/cases/simulate/${scenarioKey}`, {
          method: "POST",
        });
        showToast(res.message || `实战仿真样本 ${res.case_code} 载入成功！`, "success", 4500);
        await loadCases();
        await selectCase(res.id);
      } catch (err) {
        showToast(`载入仿真样本失败: ${err.message}`, "error");
      } finally {
        loading.simulating = false;
      }
    };

    // 切换持久化后门核查清单勾选状态
    const toggleChecklistItem = (item) => {
      item.checked = !item.checked;
    };

    // 新建应急案件
    const submitNewCase = async () => {
      if (!newCaseForm.case_name.trim()) {
        showToast("请输入应急案件名称", "error");
        return;
      }
      try {
        const res = await apiFetch("/api/cases", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(newCaseForm),
        });
        showToast(`案件 ${res.case_code} 创建成功！`, "success");
        modals.newCase = false;
        newCaseForm.case_name = "";
        newCaseForm.description = "";
        await loadCases();
        await selectCase(res.id);
      } catch (err) {
        showToast(`创建案件失败: ${err.message}`, "error");
      }
    };

    // 拖拽或选择文件上传取证包
    const handleFileChange = (e) => {
      const files = e.target.files || e.dataTransfer?.files;
      if (files && files.length > 0) {
        uploadForm.file = files[0];
      }
    };

    const handleDropFile = (e) => {
      uploadForm.isDragging = false;
      const files = e.dataTransfer?.files;
      if (files && files.length > 0) {
        uploadForm.file = files[0];
        modals.upload = true;
      }
    };

    const submitUploadEvidence = async () => {
      if (!currentCaseId.value) {
        showToast("请先选择或创建一个应急案件", "error");
        return;
      }
      if (!uploadForm.file) {
        showToast("请选择要上传的 .zip 或 .evtx 取证日志包", "error");
        return;
      }
      loading.uploading = true;
      try {
        const formData = new FormData();
        formData.append("hostname", uploadForm.hostname);
        formData.append("ip_address", uploadForm.ip_address);
        formData.append("os_version", uploadForm.os_version);
        formData.append("collector_type", uploadForm.collector_type);
        formData.append("file", uploadForm.file);

        const res = await apiFetch(`/api/cases/${currentCaseId.value}/hosts`, {
          method: "POST",
          body: formData,
        });
        showToast(
          `解析完成！提取高危事件 ${res.parse_result?.total_parsed_events || 0} 条，风险评分 ${res.parse_result?.risk_score || 0}`,
          "success"
        );
        modals.upload = false;
        uploadForm.file = null;
        await selectCase(currentCaseId.value);
      } catch (err) {
        showToast(`上传并解析取证包失败: ${err.message}`, "error");
      } finally {
        loading.uploading = false;
      }
    };

    // 删除案件
    const deleteCase = async (c) => {
      if (!c) return;
      const ok = window.confirm(
        `确定要彻底删除案件【${c.case_code} - ${c.case_name}】及其所有关联主机、日志伪影和本地取证包文件吗？\n此操作不可恢复！`
      );
      if (!ok) return;
      try {
        const res = await apiFetch(`/api/cases/${c.id}`, { method: "DELETE" });
        showToast(res.message || `案件 ${c.case_code} 已删除`, "success");
        if (currentCaseId.value === c.id) {
          currentCaseId.value = null;
          hosts.value = [];
          artifacts.value = [];
          iocs.value = [];
          patientZero.value = {};
          remediationCards.value = [];
          topologyData.value = { nodes: [], edges: [] };
          aiSummaryMarkdown.value = "";
        }
        await loadCases();
      } catch (err) {
        showToast(`删除案件失败: ${err.message}`, "error");
      }
    };

    // 删除单台涉案主机
    const deleteHost = async (h) => {
      if (!h || !currentCaseId.value) return;
      const ok = window.confirm(
        `确定要从当前案件中删除涉案主机【${h.hostname} (${h.ip_address || "无IP"})】及其解析出的所有安全日志吗？`
      );
      if (!ok) return;
      try {
        const res = await apiFetch(`/api/cases/${currentCaseId.value}/hosts/${h.id}`, {
          method: "DELETE",
        });
        showToast(res.message || `主机 ${h.hostname} 已删除`, "success");
        if (selectedHostId.value === h.id) {
          selectedHostId.value = null;
        }
        await selectCase(currentCaseId.value);
      } catch (err) {
        showToast(`删除主机失败: ${err.message}`, "error");
      }
    };

    // 触发全案 AI 溯源推理
    const triggerAiAnalysis = async () => {
      if (!currentCaseId.value) return;
      loading.analyzing = true;
      showToast("正在执行 Base64 载荷解码、IOC 威胁情报富化与 AI 攻击链推演...", "info");
      try {
        const res = await apiFetch(`/api/cases/${currentCaseId.value}/analyze`, {
          method: "POST",
        });
        aiSummaryMarkdown.value = res.ai_summary || "";
        currentPage.value = "ai_report";
        workspaceTab.value = "ai_intel";
        rightTab.value = "ai_report";
        showToast(
          `AI 研判完成！模式：${res.llm_mode === "external_llm" ? "外部大模型 (" + res.llm_model + ")" : "内置 DFIR 专家规则引擎"}`,
          "success"
        );
        await selectCase(currentCaseId.value);
      } catch (err) {
        showToast(`AI 研判失败: ${err.message}`, "error");
      } finally {
        loading.analyzing = false;
      }
    };

    // 单独触发 IOC 情报富化
    const triggerIocEnrich = async () => {
      if (!currentCaseId.value) return;
      loading.enriching = true;
      try {
        const res = await apiFetch(`/api/cases/${currentCaseId.value}/iocs/enrich`, {
          method: "POST",
        });
        showToast(res.message || "IOC 威胁情报富化完成", "success");
        await loadCaseIocs(currentCaseId.value);
      } catch (err) {
        showToast(`情报富化失败: ${err.message}`, "error");
      } finally {
        loading.enriching = false;
      }
    };

    // 导出 Word 报告
    const exportWordReport = () => {
      if (!currentCaseId.value) {
        showToast("请先选择案件", "error");
        return;
      }
      showToast("正在生成标准 Word (.doc) 应急响应报告并触发下载...", "success");
      window.open(`/api/cases/${currentCaseId.value}/export-word`, "_blank");
    };

    // 加载与保存 LLM / 微步 API 配置
    const openSettingsModal = async () => {
      modals.settings = true;
      try {
        const list = await apiFetch("/api/llm-configs");
        if (list && list.length > 0) {
          const active = list[0];
          llmForm.config_name = active.config_name;
          llmForm.provider = active.provider;
          llmForm.base_url = active.base_url;
          llmForm.model_name = active.model_name;
          llmForm.temperature = active.temperature;
          llmForm.max_tokens = active.max_tokens;
          llmForm.has_api_key = active.has_api_key;
          llmForm.has_threatbook_key = active.has_threatbook_key;
          llmForm.has_vt_key = active.has_vt_key;
        }
      } catch (err) {
        console.error(err);
      }
    };

    const onProviderChange = () => {
      if (llmForm.provider === "deepseek") {
        llmForm.base_url = "https://api.deepseek.com/v1";
        llmForm.model_name = "deepseek-chat";
        llmForm.config_name = "DeepSeek-V3-DFIR";
      } else if (llmForm.provider === "openai") {
        llmForm.base_url = "https://api.openai.com/v1";
        llmForm.model_name = "gpt-4o";
        llmForm.config_name = "OpenAI-GPT4o-DFIR";
      } else if (llmForm.provider === "qwen") {
        llmForm.base_url = "https://dashscope.aliyuncs.com/compatible-mode/v1";
        llmForm.model_name = "qwen-plus";
        llmForm.config_name = "Qwen-Plus-DFIR";
      } else if (llmForm.provider === "ollama") {
        llmForm.base_url = "http://localhost:11434/v1";
        llmForm.model_name = "qwen2.5:14b";
        llmForm.config_name = "Local-Ollama-DFIR";
      }
    };

    const saveSettings = async () => {
      loading.savingConfig = true;
      try {
        const res = await apiFetch("/api/llm-configs", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            config_name: llmForm.config_name,
            provider: llmForm.provider,
            base_url: llmForm.base_url,
            api_key: llmForm.api_key,
            model_name: llmForm.model_name,
            temperature: Number(llmForm.temperature),
            max_tokens: Number(llmForm.max_tokens),
            is_active: true,
            threatbook_api_key: llmForm.threatbook_api_key,
            vt_api_key: llmForm.vt_api_key,
          }),
        });
        showToast(res.message || "配置保存成功！", "success");
        modals.settings = false;
      } catch (err) {
        showToast(`保存配置失败: ${err.message}`, "error");
      } finally {
        loading.savingConfig = false;
      }
    };

    // 一键复制 CMD / PowerShell 修复脚本
    const copyScript = async (text, label = "命令") => {
      try {
        await navigator.clipboard.writeText(text);
        showToast(`已复制 ${label} 到剪贴板，请在目标主机管理员终端人工审核后执行`, "success");
      } catch (_) {
        const ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        showToast(`已复制 ${label} 到剪贴板`, "success");
      }
    };

    // 查看单条事件详情弹窗
    const openArtifactDetail = (art) => {
      activeArtifact.value = art;
      modals.eventDetail = true;
    };

    // =========================================================================
    // 4. AntV G6 多机横向移动与攻击链拓扑图渲染
    // =========================================================================
    const renderG6Topology = () => {
      const container = document.getElementById("g6-topology-canvas");
      if (!container || !window.G6) return;

      const width = container.clientWidth || 720;
      const height = container.clientHeight || 300;

      if (g6Graph) {
        g6Graph.destroy();
        g6Graph = null;
      }

      const colorPalette = {
        attacker: { fill: "#7f1d1d", stroke: "#ef4444", text: "#fecaca" },
        patient_zero: { fill: "#1e1b4b", stroke: "#ec4899", text: "#fbcfe8" },
        host: { fill: "#0f172a", stroke: "#38bdf8", text: "#bae6fd" },
        process: { fill: "#3b0764", stroke: "#a855f7", text: "#e9d5ff" },
        service: { fill: "#431407", stroke: "#f97316", text: "#fed7aa" },
        account: { fill: "#422006", stroke: "#eab308", text: "#fef08a" },
      };

      // 将外部攻击源 IP 节点排在最前，确保 Dagre LR 布局下位于 0 号病人主机节点左侧
      const orderPriority = { attacker: 0, patient_zero: 1, host: 2, process: 3, service: 4, account: 5 };
      const sortedRawNodes = [...(topologyData.value.nodes || [])].sort(
        (a, b) => (orderPriority[a.nodeType] ?? 9) - (orderPriority[b.nodeType] ?? 9)
      );

      // 前端兜底限流：同类型节点最多展示 8 个（含折叠汇总节点最多 9 个），防止极端情况下挤压成竖线
      const typeCounters = {};
      const allowedNodeIds = new Set();
      const filteredRawNodes = [];
      for (const n of sortedRawNodes) {
        const t = n.nodeType || "host";
        if (t === "patient_zero" || t === "host" || String(n.id).endsWith("_overflow_summary")) {
          allowedNodeIds.add(n.id);
          filteredRawNodes.push(n);
          continue;
        }
        typeCounters[t] = (typeCounters[t] || 0) + 1;
        if (typeCounters[t] <= 8) {
          allowedNodeIds.add(n.id);
          filteredRawNodes.push(n);
        }
      }

      const truncateLine = (str, maxLen = 22) => {
        if (!str) return "";
        return str.split("\n").map((line) => (line.length > maxLen ? line.slice(0, maxLen - 1) + "…" : line)).join("\n");
      };

      const nodes = filteredRawNodes.map((n) => {
        const styleCfg = colorPalette[n.nodeType] || colorPalette.host;
        return {
          id: n.id,
          label: truncateLine(n.label, 22),
          nodeType: n.nodeType,
          style: {
            fill: styleCfg.fill,
            stroke: styleCfg.stroke,
            lineWidth: n.nodeType === "patient_zero" || n.nodeType === "attacker" ? 2.5 : 1.8,
            radius: 6,
            shadowColor: styleCfg.stroke,
            shadowBlur: n.nodeType === "patient_zero" || n.nodeType === "attacker" ? 14 : 6,
          },
          labelCfg: {
            style: {
              fill: styleCfg.text,
              fontSize: 11,
              fontWeight: 600,
              fontFamily: "JetBrains Mono, Consolas, Microsoft YaHei, monospace",
            },
          },
        };
      });

      const edges = (topologyData.value.edges || [])
        .filter((e) => allowedNodeIds.has(e.source) && allowedNodeIds.has(e.target))
        .map((e, idx) => ({
          id: `edge_${idx}`,
          source: e.source,
          target: e.target,
          label: e.label,
          style: {
            stroke: e.risk === "critical" ? "#f43f5e" : "#38bdf8",
            lineWidth: e.risk === "critical" ? 2.2 : 1.6,
            lineDash: e.label.includes("爆破") && !e.label.includes("4624") ? [4, 4] : undefined,
            endArrow: {
              path: G6.Arrow.triangle(8, 10, 0),
              fill: e.risk === "critical" ? "#f43f5e" : "#38bdf8",
            },
          },
          labelCfg: {
            autoRotate: false,
            refY: -10,
            style: {
              fill: "#f8fafc",
              fontSize: 10,
              fontWeight: 600,
              background: {
                fill: "#090d16",
                stroke: e.risk === "critical" ? "#be123c" : "#475569",
                lineWidth: 1,
                padding: [2, 6, 2, 6],
                radius: 4,
              },
            },
          },
        }));

      g6Graph = new G6.Graph({
        container: "g6-topology-canvas",
        width,
        height,
        fitView: true,
        fitViewPadding: [24, 36, 24, 36],
        minZoom: 0.45,
        maxZoom: 1.15,
        modes: {
          default: ["drag-canvas", "zoom-canvas", "drag-node"],
        },
        layout: {
          type: "dagre",
          rankdir: "LR",
          nodesep: 20,
          ranksep: 85,
        },
        defaultNode: {
          type: "rect",
          size: [164, 44],
        },
        defaultEdge: {
          type: "cubic-horizontal",
        },
      });

      g6Graph.data({ nodes, edges });
      g6Graph.render();
      if (nodes.length <= 2 && g6Graph.getZoom() > 1.0) {
        g6Graph.zoomTo(1.0, { x: width / 2, y: height / 2 });
      }
    };

    const resetTopologyZoom = () => {
      if (g6Graph) {
        g6Graph.fitView([24, 36, 24, 36]);
      }
    };

    // 格式化时间
    const formatTime = (isoStr) => {
      if (!isoStr) return "N/A";
      const d = new Date(isoStr);
      if (isNaN(d.getTime())) return isoStr;
      return d.toISOString().replace("T", " ").substring(0, 19);
    };

    // 事件中文名称映射
    const eventTitleMap = {
      4624: "账户成功登录 (Logon Success)",
      4625: "账户登录失败/暴力破解 (Logon Failed)",
      4688: "新进程创建与命令行审计 (Process Creation)",
      7045: "新系统服务安装持久化 (Service Installed)",
      4720: "创建本地/域用户账户 (User Created)",
    };

    onMounted(async () => {
      await loadCases();
      window.addEventListener("resize", () => {
        const container = document.getElementById("g6-topology-canvas");
        if (g6Graph && container) {
          g6Graph.changeSize(container.clientWidth || 720, container.clientHeight || 300);
          g6Graph.fitView([24, 36, 24, 36]);
        }
      });
    });

    return {
      loading,
      toast,
      cases,
      currentCaseId,
      currentCase,
      hosts,
      selectedHostId,
      artifacts,
      filteredArtifacts,
      paginatedArtifacts,
      timelinePage,
      timelinePageSize,
      totalTimelinePages,
      iocs,
      patientZero,
      remediationCards,
      cveMatches,
      ransomwareRatAlerts,
      persistenceChecklist,
      simMenuOpen,
      topologyData,
      aiSummaryMarkdown,
      renderedAiMarkdown,
      stats,
      filterEventId,
      filterRiskLevel,
      searchKeyword,
      hideLowBaseline,
      lowBaselineCount,
      isBaselineSafe,
      currentPage,
      switchPage,
      workspaceTab,
      switchWorkspaceTab,
      rightTab,
      modals,
      activeArtifact,
      newCaseForm,
      industryMap,
      uploadForm,
      llmForm,
      eventTitleMap,
      selectCase,
      submitNewCase,
      loadSimulationCase,
      toggleChecklistItem,
      deleteCase,
      deleteHost,
      handleFileChange,
      handleDropFile,
      submitUploadEvidence,
      triggerAiAnalysis,
      triggerIocEnrich,
      exportWordReport,
      openSettingsModal,
      onProviderChange,
      saveSettings,
      copyScript,
      openArtifactDetail,
      resetTopologyZoom,
      formatTime,
    };
  },
});

app.mount("#app");
