const scanBtn = document.getElementById('scanBtn');
const statusPill = document.getElementById('statusPill');
const statusLabel = statusPill.querySelector('.navbar__status-label');
const orb = document.getElementById('scanOrb');
const orbCaption = document.getElementById('orbCaption');
const resultsDiv = document.getElementById('results');

function setState(state, label) {
    // state: 'idle' | 'scanning' | 'done' | 'error'
    statusPill.className = 'navbar__status' + (state === 'idle' ? '' : ' is-' + state);
    statusLabel.textContent = label;

    orb.className = 'orb' + (state === 'idle' ? '' : ' is-' + state);
    orbCaption.className = 'orb-caption' + (state === 'idle' ? '' : ' is-' + state);
    orbCaption.textContent =
        state === 'scanning' ? 'sweeping target…' :
        state === 'done' ? 'scan complete' :
        state === 'error' ? 'connection failed' :
        'awaiting target';
}

// Ripple effect on the scan button click
scanBtn.addEventListener('click', (e) => {
    const ripple = scanBtn.querySelector('.btn__ripple');
    const rect = scanBtn.getBoundingClientRect();
    ripple.style.left = (e.clientX - rect.left) + 'px';
    ripple.style.top = (e.clientY - rect.top) + 'px';
    ripple.classList.remove('is-active');
    // restart animation
    void ripple.offsetWidth;
    ripple.classList.add('is-active');
});

// 3D mouse-tilt effect for any .port-card currently in the DOM
function attachTiltHandlers() {
    document.querySelectorAll('.port-card').forEach(card => {
        card.addEventListener('mousemove', (e) => {
            const rect = card.getBoundingClientRect();
            const x = (e.clientX - rect.left) / rect.width - 0.5;
            const y = (e.clientY - rect.top) / rect.height - 0.5;
            card.style.setProperty('--ry', `${x * 8}deg`);
            card.style.setProperty('--rx', `${-y * 8}deg`);
        });
        card.addEventListener('mouseleave', () => {
            card.style.setProperty('--rx', '0deg');
            card.style.setProperty('--ry', '0deg');
        });
    });
}

scanBtn.addEventListener('click', async () => {
    const target = document.getElementById('targetInput').value;

    if (!target) {
        resultsDiv.innerHTML = "<div class='msg msg--error'>Please enter a target IP or URL.</div>";
        return;
    }

    scanBtn.disabled = true;
    setState('scanning', 'Scanning');

    resultsDiv.innerHTML = `
        <div class="msg msg--info">
            Scanning ports and fuzzing directories...
            <span class="scan-loader"><span></span><span></span><span></span></span>
            <br><span style="color: var(--ink-dim); font-size: 12px;">Check your terminal for backend activity.</span>
        </div>
    `;

    try {
        const response = await fetch(`/api/scan?target=${target}`);
        const data = await response.json();

        setState('done', 'Complete');

        // Updated to look for data.recon instead of data.results
        if (!data.recon || data.recon.length === 0) {
            resultsDiv.innerHTML = `<div class="msg msg--empty">Scan complete. No open ports discovered on ${target}.</div>`;
            return;
        }

        let htmlContent = `<div class="target-banner">Scan Results for <span class="target-value">${data.target}</span></div>`;

        // 1. Render Recon & Vuln Data
        htmlContent += `<div class="section-title">Port Reconnaissance</div>`;
        data.recon.forEach(res => {
            htmlContent += `
                <div class="port-card">
                    <div class="port-card__head">
                        <span class="port-chip"><span class="port-chip__num">${res.port}</span>Port</span>
                        <span class="banner-tag">${res.service_banner}</span>
                    </div>
                    <hr class="divider">
                    <p class="vuln-label">Discovered Vulnerabilities</p>
            `;

            if (res.vulnerabilities.length === 0) {
                htmlContent += "<p class='vuln-clean'>No CVEs found, or version hidden.</p>";
            } else if (res.vulnerabilities[0].error) {
                htmlContent += `<p class='vuln-warn'>${res.vulnerabilities[0].error}</p>`;
            } else {
                res.vulnerabilities.forEach(v => {
                    htmlContent += `
                        <div class="vuln-item">
                            <span class="vuln-item__id">${v.cve_id}</span>
                            <span class="vuln-item__summary">${v.summary}</span>
                        </div>
                    `;
                });
            }
            htmlContent += `</div>`;
        });

        // 2. Render Directory Fuzzer Data
        if (data.directories && data.directories.length > 0) {
            htmlContent += `<div class="section-title">Hidden Directories Discovered</div>`;
            htmlContent += `<div class="dir-panel">`;
            data.directories.forEach(dir => {
                const badgeClass = dir.status === 200 ? "status-badge--ok" : "status-badge--warn";
                htmlContent += `
                    <div class="dir-row">
                        <a href="http://${data.target}${dir.directory}" target="_blank">${dir.directory}</a>
                        <span class="status-badge ${badgeClass}">${dir.status}</span>
                    </div>
                `;
            });
            htmlContent += `</div>`;
        } else {
            htmlContent += `<div class="msg msg--empty">No common hidden directories found.</div>`;
        }

        resultsDiv.innerHTML = htmlContent;
        attachTiltHandlers();
    } catch (error) {
        console.error("Fetch error:", error);
        setState('error', 'Error');
        resultsDiv.innerHTML = "<div class='msg msg--error'>Error connecting to backend server. Is Uvicorn running?</div>";
    } finally {
        scanBtn.disabled = false;
    }
});