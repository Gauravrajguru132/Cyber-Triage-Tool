// Dashboard Dynamic Charts and Metrics
document.addEventListener('DOMContentLoaded', () => {
    initRiskDistributionChart();
    initThreatRadarChart();
});

function initRiskDistributionChart() {
    const ctx = document.getElementById('riskChart');
    if (!ctx) return;

    const lowCount = parseInt(ctx.dataset.low || 0);
    const medCount = parseInt(ctx.dataset.medium || 0);
    const highCount = parseInt(ctx.dataset.high || 0);
    const critCount = parseInt(ctx.dataset.critical || 0);

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Low Risk', 'Medium Risk', 'High Risk', 'Critical Risk'],
            datasets: [{
                data: [lowCount, medCount, highCount, critCount],
                backgroundColor: ['#10b981', '#eab308', '#f97316', '#ef4444'],
                borderColor: '#131b2e',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#94a3b8', font: { size: 11 } }
                }
            },
            cutout: '68%'
        }
    });
}

function initThreatRadarChart() {
    const ctx = document.getElementById('threatRadarChart');
    if (!ctx) return;

    // Default or dynamically passed threat vector scores
    const labels = ['Ransomware', 'APT / C2', 'Credential Theft', 'Web Attack', 'Persistence', 'Evasion'];
    const dataValues = [
        parseInt(ctx.dataset.ransom || 20),
        parseInt(ctx.dataset.c2 || 35),
        parseInt(ctx.dataset.creds || 15),
        parseInt(ctx.dataset.web || 25),
        parseInt(ctx.dataset.persist || 30),
        parseInt(ctx.dataset.evasion || 15)
    ];

    new Chart(ctx, {
        type: 'radar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Threat Vector Activity',
                data: dataValues,
                backgroundColor: 'rgba(59, 130, 246, 0.25)',
                borderColor: '#3b82f6',
                pointBackgroundColor: '#06b6d4',
                pointBorderColor: '#fff',
                pointHoverBackgroundColor: '#fff',
                pointHoverBorderColor: '#3b82f6'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                r: {
                    angleLines: { color: '#1e293b' },
                    grid: { color: '#1e293b' },
                    pointLabels: { color: '#94a3b8', font: { size: 10.5 } },
                    ticks: { display: false, max: 100, min: 0 }
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}

// Copy to Clipboard Utility
function copyToClipboard(text, btnElement) {
    navigator.clipboard.writeText(text).then(() => {
        const originalText = btnElement.innerText;
        btnElement.innerText = 'Copied!';
        btnElement.classList.add('btn-success');
        setTimeout(() => {
            btnElement.innerText = originalText;
            btnElement.classList.remove('btn-success');
        }, 1800);
    });
}
