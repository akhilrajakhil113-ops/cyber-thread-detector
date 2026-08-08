/**
 * Application Main Controller
 * Orchestrates GPU telemetry, live packet stream, UI tab switches,
 * AI Copilot interactions, attack campaign injection, and modal windows.
 */

document.addEventListener('DOMContentLoaded', () => {
    console.log("Initializing GPU-Accelerated Cyber Threat Detection & AI Security Assistant...");

    // Initialize Canvas Topology Map
    window.topologyMap = new window.TopologyMap('topologyCanvas');
    
    // Initialize PCAP Parser
    window.pcapParser = new window.PCAPParser();

    // Elements Reference
    const streamBody = document.getElementById('threatStreamBody');
    const gpuModeStatus = document.getElementById('gpu-mode-status');
    const gpuLatency = document.getElementById('gpu-latency');
    const networkThroughput = document.getElementById('network-throughput');
    const anomalyCountPill = document.getElementById('anomaly-count-pill');
    
    const gpuUtilVal = document.getElementById('gpuUtilVal');
    const gpuUtilBar = document.getElementById('gpuUtilBar');
    const vramVal = document.getElementById('vramVal');
    const vramBar = document.getElementById('vramBar');

    const modelSelect = document.getElementById('model-select');
    const scenarioSelect = document.getElementById('scenario-preset-select');
    const chatInput = document.getElementById('chatInput');
    const chatSendBtn = document.getElementById('chatSendBtn');
    const chatMessages = document.getElementById('chatMessages');

    let streamInterval = null;
    let isPaused = false;

    // 1. Subscribe to GPU Engine Updates
    window.gpuEngine.subscribe((metrics) => {
        if (gpuModeStatus) gpuModeStatus.textContent = metrics.activeModel.split(' ')[0] + " (CUDA)";
        if (gpuLatency) gpuLatency.textContent = `${metrics.latencyMicrosec} µs`;
        if (networkThroughput) networkThroughput.textContent = `${metrics.throughputGbps} Gbps`;

        if (gpuUtilVal) gpuUtilVal.textContent = `${metrics.gpuUtil}%`;
        if (gpuUtilBar) gpuUtilBar.style.width = `${metrics.gpuUtil}%`;
        
        const vramPct = Math.round((metrics.vramUsed / metrics.vramTotal) * 100);
        if (vramVal) vramVal.textContent = `${metrics.vramUsed} / ${metrics.vramTotal} MB`;
        if (vramBar) vramBar.style.width = `${vramPct}%`;
    });

    // Start GPU Telemetry loop
    window.gpuEngine.startTelemetry();

    // 2. Subscribe to Threat Detector Flow Stream
    window.threatDetector.subscribe((flow) => {
        if (anomalyCountPill) {
            anomalyCountPill.textContent = `${window.threatDetector.anomalyCount} Anomalies`;
        }

        renderFlowRow(flow);
        renderSHAPView(flow);
    });

    function renderFlowRow(flow) {
        if (!streamBody) return;

        const tr = document.createElement('tr');
        if (flow.isAnomaly) {
            tr.classList.add('anomaly-row');
        }

        let badgeClass = `badge-${flow.severity}`;

        tr.innerHTML = `
            <td>${flow.timestamp}</td>
            <td>${flow.srcIP}</td>
            <td>${flow.dstIP}:${flow.dstPort}</td>
            <td>${flow.protocol}</td>
            <td><span class="badge ${badgeClass}">${flow.threatType}</span></td>
            <td>${flow.entropy}</td>
            <td style="color: ${flow.isAnomaly ? 'var(--neon-red)' : 'var(--neon-cyan)'}">${(flow.anomalyScore * 100).toFixed(1)}%</td>
        `;

        tr.addEventListener('click', () => {
            window.aiAssistant.setSelectedFlow(flow);
            // Highlight selected row
            document.querySelectorAll('#threatStreamBody tr').forEach(r => r.style.background = '');
            tr.style.background = 'rgba(0, 240, 255, 0.15)';
            renderSHAPView(flow);
        });

        streamBody.insertBefore(tr, streamBody.firstChild);

        // Keep maximum 50 rows visible in table
        if (streamBody.children.length > 50) {
            streamBody.removeChild(streamBody.lastChild);
        }
    }

    function renderSHAPView(flow) {
        const shapContainer = document.getElementById('shapBarsContainer');
        const shapFlowId = document.getElementById('shapFlowId');
        if (!shapContainer) return;

        if (shapFlowId) shapFlowId.textContent = `Target: ${flow.id} [${flow.threatType}]`;

        shapContainer.innerHTML = '';
        flow.shap.forEach(item => {
            const barItem = document.createElement('div');
            barItem.className = 'shap-bar-item';
            barItem.innerHTML = `
                <div class="shap-label">${item.feature}</div>
                <div class="shap-track">
                    <div class="shap-fill" style="width: ${Math.abs(parseFloat(item.value)) * 100}%; background-color: ${item.color}"></div>
                </div>
                <div class="shap-val" style="color: ${item.color}">${item.value}</div>
            `;
            shapContainer.appendChild(barItem);
        });
    }

    // 3. Start Packet Generation Loop
    function startStream() {
        if (streamInterval) clearInterval(streamInterval);
        streamInterval = setInterval(() => {
            if (!isPaused) {
                window.threatDetector.generatePacketFlow();
            }
        }, 800);
    }
    startStream();

    // 4. Tab Navigation
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

            btn.classList.add('active');
            const targetTab = btn.getAttribute('data-tab');
            const tabContent = document.getElementById(`${targetTab}-tab`);
            if (tabContent) tabContent.classList.add('active');

            if (targetTab === 'topology' && window.topologyMap) {
                setTimeout(() => window.topologyMap.resize(), 100);
            }
        });
    });

    // 5. Controls: Model & Campaign Selection
    if (modelSelect) {
        modelSelect.addEventListener('change', (e) => {
            window.gpuEngine.switchModel(e.target.value);
        });
    }

    if (scenarioSelect) {
        scenarioSelect.addEventListener('change', (e) => {
            window.threatDetector.setCampaign(e.target.value);
        });
    }

    // Attack Buttons Injection
    document.querySelectorAll('.btn-attack').forEach(btn => {
        btn.addEventListener('click', () => {
            const attackType = btn.getAttribute('data-attack');
            window.threatDetector.setCampaign(attackType);
            
            // Generate immediate burst of 3 packets
            for(let i=0; i<3; i++) {
                window.threatDetector.generatePacketFlow();
            }

            // Auto-trigger AI assistant notification
            window.aiAssistant.processUserQuery(`Alert: High severity ${attackType.toUpperCase()} attack injected into GPU processing engine.`);
        });
    });

    // 6. AI Security Assistant Chat Logic
    window.aiAssistant.subscribe((messages) => {
        if (!chatMessages) return;
        chatMessages.innerHTML = '';

        messages.forEach(msg => {
            const div = document.createElement('div');
            div.className = `message-bubble msg-${msg.sender}`;
            
            let htmlContent = msg.text.replace(/\n/g, '<br>');
            // Basic markdown bold replacement
            htmlContent = htmlContent.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
            htmlContent = htmlContent.replace(/`(.*?)`/g, '<code>$1</code>');

            div.innerHTML = htmlContent;

            if (msg.code) {
                const codeDiv = document.createElement('div');
                codeDiv.className = 'msg-code';
                codeDiv.textContent = msg.code;
                div.appendChild(codeDiv);
            }

            chatMessages.appendChild(div);
        });

        chatMessages.scrollTop = chatMessages.scrollHeight;
    });

    // Send Custom User Prompt
    function handleSend() {
        const text = chatInput.value.trim();
        if (text) {
            window.aiAssistant.processUserQuery(text);
            chatInput.value = '';
        }
    }

    if (chatSendBtn) chatSendBtn.addEventListener('click', handleSend);
    if (chatInput) {
        chatInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') handleSend();
        });
    }

    // Quick Action Pills
    document.querySelectorAll('.btn-action-pill').forEach(btn => {
        btn.addEventListener('click', () => {
            const action = btn.getAttribute('data-action');
            if (action === 'triage') {
                window.aiAssistant.processUserQuery("Perform deep threat triage on selected flow.");
            } else if (action === 'rules') {
                window.aiAssistant.processUserQuery("Generate WAF and firewall mitigation rules.");
            } else if (action === 'playbook') {
                window.aiAssistant.processUserQuery("Produce NIST SP 800-61 incident response playbook.");
            } else if (action === 'payload') {
                window.aiAssistant.processUserQuery("Reverse engineer payload bytes and calculate Shannon entropy.");
            }
        });
    });

    // 7. Modals & Exporters
    const pcapBtn = document.getElementById('open-pcap-btn');
    const pcapModal = document.getElementById('pcapModal');
    const closeModal = document.getElementById('closePcapModal');

    if (pcapBtn && pcapModal) {
        pcapBtn.addEventListener('click', () => pcapModal.classList.add('active'));
    }
    if (closeModal && pcapModal) {
        closeModal.addEventListener('click', () => pcapModal.classList.remove('active'));
    }

    const exportBtn = document.getElementById('export-report-btn');
    if (exportBtn) {
        exportBtn.addEventListener('click', () => {
            window.Exporter.exportCSV();
        });
    }

    const toggleStreamBtn = document.getElementById('toggle-stream-btn');
    const streamBtnText = document.getElementById('stream-btn-text');
    if (toggleStreamBtn) {
        toggleStreamBtn.addEventListener('click', () => {
            isPaused = !isPaused;
            if (streamBtnText) streamBtnText.textContent = isPaused ? "Resume Stream" : "Pause Stream";
        });
    }

    // Welcome Message in Copilot
    window.aiAssistant.chatHistory.push({
        sender: "system",
        text: "👋 **Welcome to the GPU Cyber Threat Assistant!**\n\nI am listening to live CUDA stream telemetry. Click any packet flow row or use the quick actions below to synthesize WAF rules, generate incident playbooks, or perform deep threat triage."
    });
    window.aiAssistant.notifyListeners();
});
