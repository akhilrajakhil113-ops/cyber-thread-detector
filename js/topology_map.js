/**
 * Interactive WebGL / HTML5 2D Canvas Threat Topology Visualizer
 * Renders high-FPS network node graph, glowing particle trails,
 * active attack vectors, edge firewall, and target internal subnets.
 */

class TopologyMap {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext('2d');
        
        this.nodes = [];
        this.particles = [];
        this.animFrameId = null;
        
        this.resize();
        window.addEventListener('resize', () => this.resize());
        
        this.initNodes();
        this.startAnimation();
    }

    resize() {
        if (!this.canvas) return;
        const rect = this.canvas.parentElement.getBoundingClientRect();
        this.canvas.width = rect.width;
        this.canvas.height = rect.height;
    }

    initNodes() {
        const w = this.canvas.width || 800;
        const h = this.canvas.height || 400;

        this.nodes = [
            // External Attacker Nodes (Left Side)
            { id: "atk-1", label: "185.220.101.5 (C2)", x: w * 0.12, y: h * 0.25, type: "attacker", color: "#ff2a55", radius: 14 },
            { id: "atk-2", label: "45.142.214.8 (Botnet)", x: w * 0.12, y: h * 0.55, type: "attacker", color: "#ff9900", radius: 12 },
            { id: "atk-3", label: "89.248.165.74 (Scanner)", x: w * 0.12, y: h * 0.80, type: "attacker", color: "#ffcc00", radius: 10 },

            // Center GPU Engine Gateway
            { id: "gpu-gate", label: "NVIDIA CUDA NIDS Gateway", x: w * 0.50, y: h * 0.50, type: "gateway", color: "#00f0ff", radius: 22 },

            // Internal Secured Nodes (Right Side)
            { id: "srv-1", label: "192.168.1.105 (Web App)", x: w * 0.85, y: h * 0.25, type: "server", color: "#00ff66", radius: 14 },
            { id: "srv-2", label: "192.168.1.112 (PostgreSQL)", x: w * 0.85, y: h * 0.50, type: "server", color: "#9d00ff", radius: 14 },
            { id: "srv-3", label: "10.0.4.22 (Domain Ctrl)", x: w * 0.85, y: h * 0.75, type: "server", color: "#0088ff", radius: 14 }
        ];

        // Create connection edges
        this.edges = [
            { from: "atk-1", to: "gpu-gate", isAttack: true },
            { from: "atk-2", to: "gpu-gate", isAttack: true },
            { from: "atk-3", to: "gpu-gate", isAttack: false },
            { from: "gpu-gate", to: "srv-1", isAttack: false },
            { from: "gpu-gate", to: "srv-2", isAttack: false },
            { from: "gpu-gate", to: "srv-3", isAttack: false }
        ];
    }

    spawnParticle(isAttack) {
        if (this.nodes.length === 0) return;
        
        const srcNode = this.nodes[Math.floor(Math.random() * 3)]; // Pick attacker
        const gateNode = this.nodes[3]; // GPU Gateway
        const dstNode = this.nodes[4 + Math.floor(Math.random() * 3)]; // Pick target server

        // Phase 1: Attacker -> Gateway
        this.particles.push({
            x: srcNode.x,
            y: srcNode.y,
            targetX: gateNode.x,
            targetY: gateNode.y,
            progress: 0,
            speed: 0.015 + Math.random() * 0.01,
            color: isAttack ? "#ff2a55" : "#00f0ff",
            size: isAttack ? 4 : 2.5,
            nextDst: dstNode,
            isAttack: isAttack
        });
    }

    startAnimation() {
        let lastParticleTime = 0;

        const animate = (timestamp) => {
            if (!lastParticleTime || timestamp - lastParticleTime > 180) {
                this.spawnParticle(Math.random() < 0.4);
                lastParticleTime = timestamp;
            }

            this.draw();
            this.animFrameId = requestAnimationFrame(animate);
        };

        this.animFrameId = requestAnimationFrame(animate);
    }

    draw() {
        if (!this.ctx) return;
        const ctx = this.ctx;
        const w = this.canvas.width;
        const h = this.canvas.height;

        ctx.clearRect(0, 0, w, h);

        // Draw Connection Edges
        this.edges.forEach(edge => {
            const n1 = this.nodes.find(n => n.id === edge.from);
            const n2 = this.nodes.find(n => n.id === edge.to);
            if (!n1 || !n2) return;

            ctx.beginPath();
            ctx.moveTo(n1.x, n1.y);
            ctx.lineTo(n2.x, n2.y);
            ctx.strokeStyle = edge.isAttack ? 'rgba(255, 42, 85, 0.25)' : 'rgba(0, 240, 255, 0.15)';
            ctx.lineWidth = edge.isAttack ? 2 : 1.5;
            ctx.setLineDash(edge.isAttack ? [4, 4] : []);
            ctx.stroke();
            ctx.setLineDash([]);
        });

        // Update & Draw Flying Particles
        for (let i = this.particles.length - 1; i >= 0; i--) {
            const p = this.particles[i];
            p.progress += p.speed;

            const curX = p.x + (p.targetX - p.x) * p.progress;
            const curY = p.y + (p.targetY - p.y) * p.progress;

            ctx.beginPath();
            ctx.arc(curX, curY, p.size, 0, Math.PI * 2);
            ctx.fillStyle = p.color;
            ctx.shadowColor = p.color;
            ctx.shadowBlur = 10;
            ctx.fill();
            ctx.shadowBlur = 0;

            // When reaching gateway, transfer to target server if not blocked
            if (p.progress >= 1.0) {
                if (p.targetX === this.nodes[3].x && !p.isAttack) {
                    // Gateway to Server
                    p.x = this.nodes[3].x;
                    p.y = this.nodes[3].y;
                    p.targetX = p.nextDst.x;
                    p.targetY = p.nextDst.y;
                    p.progress = 0;
                    p.color = "#00ff66";
                } else {
                    // Remove particle (Blocked attack or reached end)
                    this.particles.splice(i, 1);
                }
            }
        }

        // Draw Nodes
        this.nodes.forEach(node => {
            // Glow aura
            ctx.beginPath();
            ctx.arc(node.x, node.y, node.radius + 6, 0, Math.PI * 2);
            ctx.fillStyle = node.color + '22';
            ctx.fill();

            // Core circle
            ctx.beginPath();
            ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
            ctx.fillStyle = '#0c1222';
            ctx.strokeStyle = node.color;
            ctx.lineWidth = 2.5;
            ctx.fill();
            ctx.stroke();

            // Node Label
            ctx.font = '11px "Fira Code", monospace';
            ctx.fillStyle = '#f0f4f8';
            ctx.textAlign = 'center';
            ctx.fillText(node.label, node.x, node.y + node.radius + 16);
        });
    }
}

window.TopologyMap = TopologyMap;
