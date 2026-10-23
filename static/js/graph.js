// Interactive Network Correlation Visualizer using HTML5 Canvas Physics
function initCorrelationGraph(graphData) {
    const canvas = document.getElementById('correlationCanvas');
    if (!canvas || !graphData || !graphData.nodes || graphData.nodes.length === 0) return;

    const ctx = canvas.getContext('2d');
    let width = canvas.clientWidth;
    let height = canvas.clientHeight;
    canvas.width = width;
    canvas.height = height;

    const nodes = graphData.nodes.map((n, i) => ({
        ...n,
        x: width / 2 + (Math.random() - 0.5) * (width * 0.5),
        y: height / 2 + (Math.random() - 0.5) * (height * 0.5),
        vx: 0,
        vy: 0,
        radius: n.size || 12,
        color: n.color || '#3b82f6'
    }));

    const nodeMap = new Map();
    nodes.forEach(n => nodeMap.set(n.id, n));

    const links = graphData.links.map(l => ({
        source: nodeMap.get(l.source),
        target: nodeMap.get(l.target),
        relation: l.relation || ''
    })).filter(l => l.source && l.target);

    let hoveredNode = null;
    let draggedNode = null;

    // Simulation Step
    function updatePhysics() {
        const repulsion = 800;
        const springLength = 110;
        const springK = 0.04;
        const damping = 0.85;

        // Repulsion between all nodes
        for (let i = 0; i < nodes.length; i++) {
            for (let j = i + 1; j < nodes.length; j++) {
                const n1 = nodes[i];
                const n2 = nodes[j];
                const dx = n2.x - n1.x;
                const dy = n2.y - n1.y;
                const dist = Math.sqrt(dx * dx + dy * dy) || 1;
                const force = repulsion / (dist * dist);
                const fx = (dx / dist) * force;
                const fy = (dy / dist) * force;

                n1.vx -= fx;
                n1.vy -= fy;
                n2.vx += fx;
                n2.vy += fy;
            }
        }

        // Spring force for links
        links.forEach(link => {
            const dx = link.target.x - link.source.x;
            const dy = link.target.y - link.source.y;
            const dist = Math.sqrt(dx * dx + dy * dy) || 1;
            const displacement = dist - springLength;
            const fx = (dx / dist) * displacement * springK;
            const fy = (dy / dist) * displacement * springK;

            link.source.vx += fx;
            link.source.vy += fy;
            link.target.vx -= fx;
            link.target.vy -= fy;
        });

        // Center gravity & update pos
        nodes.forEach(n => {
            if (n === draggedNode) return;
            n.vx += (width / 2 - n.x) * 0.002;
            n.vy += (height / 2 - n.y) * 0.002;
            n.vx *= damping;
            n.vy *= damping;
            n.x += n.vx;
            n.y += n.vy;

            // Keep within bounds
            n.x = Math.max(30, Math.min(width - 30, n.x));
            n.y = Math.max(30, Math.min(height - 30, n.y));
        });
    }

    // Render loop
    function render() {
        ctx.clearRect(0, 0, width, height);

        // Draw Links
        links.forEach(link => {
            ctx.beginPath();
            ctx.moveTo(link.source.x, link.source.y);
            ctx.lineTo(link.target.x, link.target.y);
            ctx.strokeStyle = '#1e293b';
            ctx.lineWidth = 1.5;
            ctx.stroke();

            // Link label if hovered
            if (hoveredNode && (link.source === hoveredNode || link.target === hoveredNode)) {
                ctx.strokeStyle = '#60a5fa';
                ctx.lineWidth = 2;
                ctx.stroke();

                const midX = (link.source.x + link.target.x) / 2;
                const midY = (link.source.y + link.target.y) / 2;
                ctx.fillStyle = '#94a3b8';
                ctx.font = '10px sans-serif';
                ctx.fillText(link.relation, midX + 4, midY - 4);
            }
        });

        // Draw Nodes
        nodes.forEach(n => {
            ctx.beginPath();
            ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
            ctx.fillStyle = n.color;
            ctx.fill();

            // Glow / ring on hover
            if (n === hoveredNode || n === draggedNode) {
                ctx.lineWidth = 3;
                ctx.strokeStyle = '#ffffff';
                ctx.stroke();
            } else {
                ctx.lineWidth = 1;
                ctx.strokeStyle = '#0f172a';
                ctx.stroke();
            }

            // Node Label
            ctx.fillStyle = '#f8fafc';
            ctx.font = '11px Segoe UI, sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText(n.label, n.x, n.y + n.radius + 14);
        });

        updatePhysics();
        requestAnimationFrame(render);
    }

    render();

    // Mouse Interaction
    function getNodeAt(x, y) {
        for (let i = nodes.length - 1; i >= 0; i--) {
            const n = nodes[i];
            const dx = x - n.x;
            const dy = y - n.y;
            if (Math.sqrt(dx * dx + dy * dy) <= n.radius + 4) {
                return n;
            }
        }
        return null;
    }

    canvas.addEventListener('mousemove', (e) => {
        const rect = canvas.getBoundingClientRect();
        const mouseX = e.clientX - rect.left;
        const mouseY = e.clientY - rect.top;

        if (draggedNode) {
            draggedNode.x = mouseX;
            draggedNode.y = mouseY;
            draggedNode.vx = 0;
            draggedNode.vy = 0;
            return;
        }

        hoveredNode = getNodeAt(mouseX, mouseY);
        canvas.style.cursor = hoveredNode ? 'pointer' : 'default';
    });

    canvas.addEventListener('mousedown', (e) => {
        const rect = canvas.getBoundingClientRect();
        const mouseX = e.clientX - rect.left;
        const mouseY = e.clientY - rect.top;
        draggedNode = getNodeAt(mouseX, mouseY);
    });

    window.addEventListener('mouseup', () => {
        draggedNode = null;
    });

    window.addEventListener('resize', () => {
        width = canvas.clientWidth;
        height = canvas.clientHeight;
        canvas.width = width;
        canvas.height = height;
    });
}
