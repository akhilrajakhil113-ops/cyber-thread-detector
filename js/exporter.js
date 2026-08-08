/**
 * Security Audit Log Exporter
 * Generates downloadable JSON, CSV, and formatted security compliance reports.
 */

class Exporter {
    static exportJSON() {
        const flows = window.threatDetector.flowHistory;
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(flows, null, 2));
        const downloadAnchor = document.createElement('a');
        downloadAnchor.setAttribute("href", dataStr);
        downloadAnchor.setAttribute("download", `GPU_NIDS_Threat_Report_${Date.now()}.json`);
        document.body.appendChild(downloadAnchor);
        downloadAnchor.click();
        downloadAnchor.remove();
    }

    static exportCSV() {
        const flows = window.threatDetector.flowHistory;
        if (flows.length === 0) return;

        const headers = ["ID", "Timestamp", "Source IP", "Destination IP", "Port", "Protocol", "Entropy", "Threat Type", "Severity", "Anomaly Score"];
        const rows = flows.map(f => [
            f.id,
            f.timestamp,
            f.srcIP,
            f.dstIP,
            f.dstPort,
            f.protocol,
            f.entropy,
            `"${f.threatType}"`,
            f.severity,
            f.anomalyScore
        ]);

        let csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map(r => r.join(","))].join("\n");
        const encodedUri = encodeURI(csvContent);
        const link = document.createElement("a");
        link.setAttribute("href", encodedUri);
        link.setAttribute("download", `GPU_NIDS_Audit_Log_${Date.now()}.csv`);
        document.body.appendChild(link);
        link.click();
        link.remove();
    }
}

window.Exporter = Exporter;
