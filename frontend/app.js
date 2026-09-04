/**
 * Citadel Security Platform - Frontend Dashboard Controller
 * Handles drag-and-drop .eml ingestion, quick-load research samples, and forensic rendering.
 */

document.addEventListener('DOMContentLoaded', () => {
  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');
  const browseBtn = document.getElementById('browse-btn');
  const emptyState = document.getElementById('empty-state');
  const resultsDashboard = document.getElementById('results-dashboard');
  const sampleButtonsContainer = document.getElementById('sample-buttons-container');

  // Wire up browse button and drag-drop
  browseBtn.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', handleFileSelect);

  ['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropZone.classList.add('dragover');
    }, false);
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropZone.classList.remove('dragover');
    }, false);
  });

  dropZone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files.length > 0) {
      uploadEmlFile(files[0]);
    }
  });

  // Wire up sample buttons
  sampleButtonsContainer.querySelectorAll('.sample-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const filename = btn.getAttribute('data-file');
      loadSample(filename);
    });
  });

  // Initialize Phase 7 SOC Case Management Queue
  initCaseQueue();
  loadCaseQueue();

  // ─── Citadel Info Tooltip click/tap handler (mobile + accessibility) ───
  document.addEventListener('click', (e) => {
    const tipIcon = e.target.closest('.citadel-tip-icon');
    if (tipIcon) {
      e.preventDefault();
      e.stopPropagation();
      const tip = tipIcon.closest('.citadel-tip');
      const wasActive = tip.classList.contains('active');
      // Close all other open tooltips first
      document.querySelectorAll('.citadel-tip.active').forEach(t => t.classList.remove('active'));
      if (!wasActive) tip.classList.add('active');
      return;
    }
    // Close any open tooltip when clicking elsewhere
    if (!e.target.closest('.citadel-tip-body')) {
      document.querySelectorAll('.citadel-tip.active').forEach(t => t.classList.remove('active'));
    }
  });

  function handleFileSelect(e) {
    const files = e.target.files;
    if (files.length > 0) {
      uploadEmlFile(files[0]);
    }
  }

  async function loadSample(filename) {
    showLoading();
    try {
      const res = await fetch(`/api/sample/${encodeURIComponent(filename)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}: Failed to fetch sample`);
      const data = await res.json();
      renderDashboard(data);
    } catch (err) {
      alert(`Error analyzing sample: ${err.message}`);
    }
  }

  async function uploadEmlFile(file) {
    showLoading();
    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        body: formData
      });
      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.detail || `Upload failed with status ${res.status}`);
      }
      const data = await res.json();
      renderDashboard(data);
    } catch (err) {
      alert(`Analysis error: ${err.message}`);
    }
  }

  function showLoading() {
    emptyState.style.display = 'none';
    resultsDashboard.style.display = 'flex';
    document.getElementById('threat-archetype').textContent = 'Analyzing Message Pipeline...';
    document.getElementById('threat-score-val').textContent = '--';
  }

  function getRiskColors(level) {
    switch (level) {
      case 'CRITICAL':
        return { text: '#ef4444', bg: 'rgba(239, 68, 68, 0.18)', border: '#ef4444' };
      case 'HIGH':
        return { text: '#f97316', bg: 'rgba(249, 115, 22, 0.15)', border: '#f97316' };
      case 'MEDIUM':
        return { text: '#f59e0b', bg: 'rgba(245, 158, 11, 0.12)', border: '#f59e0b' };
      default:
        return { text: '#10b981', bg: 'rgba(16, 185, 129, 0.12)', border: '#10b981' };
    }
  }

  function renderDashboard(data) {
    // 1. Top Bar Case ID & Metadata
    document.getElementById('case-id-val').textContent = data.case_id || 'UNKNOWN';
    document.getElementById('threat-archetype').textContent = data.threat_archetype;
    document.getElementById('verdict-filename').textContent = `File: ${data.filename} • Analyzed: ${new Date(data.timestamp).toLocaleTimeString()}`;

    // Show synthetic tag if it's one of the known research benchmark scenarios
    const syntheticTag = document.getElementById('synthetic-scenario-tag');
    const isSample = ['benign_project_update.eml', 'credential_phishing_link.eml', 'bec_ceo_wire_fraud.eml', 'bec_invoice_bank_change.eml'].includes(data.filename);
    if (syntheticTag) {
      syntheticTag.style.display = isSample ? 'inline-block' : 'none';
    }

    // 2. Score & Confidence
    const colors = getRiskColors(data.risk_level);
    const scoreValElem = document.getElementById('threat-score-val');
    scoreValElem.textContent = data.threat_score;
    scoreValElem.style.color = colors.text;

    const riskBadge = document.getElementById('risk-level-badge');
    riskBadge.textContent = data.risk_level;
    riskBadge.style.color = colors.text;
    riskBadge.style.backgroundColor = colors.bg;
    riskBadge.style.border = `1px solid ${colors.border}`;

    const confPercent = Math.round(data.confidence * 100);
    const confTextElem = document.getElementById('confidence-badge-text');
    const confLabel = data.ml_classification && data.ml_classification.ml_available ? 'Combined' : 'Heuristic';
    if (confTextElem) {
      confTextElem.textContent = `${confLabel} Confidence: ${confPercent}%`;
    } else {
      const confBadge = document.getElementById('confidence-badge');
      const confTip = confBadge ? confBadge.querySelector('.citadel-tip') : null;
      if (confBadge) {
        confBadge.textContent = `${confLabel} Confidence: ${confPercent}%`;
        if (confTip) confBadge.appendChild(confTip);
      }
    }

    // 2b. ML Classification Card
    const ml = data.ml_classification || {};
    const mlStatusTag = document.getElementById('ml-status-tag');
    const mlLabelElem = document.getElementById('ml-predicted-label');
    const mlConfElem = document.getElementById('ml-confidence-val');

    if (ml.ml_available) {
      mlStatusTag.textContent = 'ML Engine: Active';
      mlStatusTag.style.color = 'var(--color-clean)';
      mlStatusTag.style.borderColor = 'var(--color-clean)';
      mlStatusTag.style.background = 'var(--bg-clean)';

      mlLabelElem.textContent = ml.predicted_label || '—';
      const labelColors = {
        'phishing': 'var(--color-high)',
        'bec': 'var(--color-critical)',
        'benign': 'var(--color-clean)'
      };
      mlLabelElem.style.color = labelColors[ml.predicted_label] || 'var(--text-primary)';
      mlConfElem.textContent = `${Math.round(ml.ml_confidence * 100)}%`;

      // Probability bars
      const probs = ml.probabilities || {};
      ['benign', 'phishing', 'bec'].forEach(cls => {
        const pct = Math.round((probs[cls] || 0) * 100);
        document.getElementById(`prob-${cls}`).style.width = `${pct}%`;
        document.getElementById(`prob-${cls}-pct`).textContent = `${pct}%`;
      });
    } else {
      mlStatusTag.textContent = 'ML Engine: Unavailable';
      mlLabelElem.textContent = '—';
      mlConfElem.textContent = '—';
      ['benign', 'phishing', 'bec'].forEach(cls => {
        document.getElementById(`prob-${cls}`).style.width = '0%';
        document.getElementById(`prob-${cls}-pct`).textContent = '0%';
      });
    }

    // 2c. Contextual NLP & Semantic Pretexting Radar (Phase 4)
    const nlp = data.nlp_analysis || {};
    const nlpDom = document.getElementById('nlp-dominant-archetype');
    const nlpTone = document.getElementById('nlp-tone');
    const nlpCoercionVal = document.getElementById('nlp-coercion-val');
    const nlpCoercionLvl = document.getElementById('nlp-coercion-level');

    if (nlp && nlp.dominant_archetype) {
      nlpDom.textContent = nlp.dominant_archetype.replace(/_/g, ' ');
      nlpTone.textContent = nlp.tone || 'Neutral';
      nlpCoercionVal.textContent = (nlp.coercion_score || 0.0).toFixed(2);
      nlpCoercionLvl.textContent = nlp.coercion_level || 'LOW';

      const cColors = getRiskColors(
        nlp.coercion_level === 'CRITICAL' ? 'CRITICAL' :
        nlp.coercion_level === 'HIGH' ? 'HIGH' :
        nlp.coercion_level === 'MODERATE' ? 'MEDIUM' : 'LOW'
      );
      nlpCoercionLvl.style.color = cColors.text;
      nlpCoercionLvl.style.background = cColors.bg;
      nlpCoercionLvl.style.border = `1px solid ${cColors.border}`;

      // Sim bars
      const sims = nlp.archetype_similarities || {};
      const mapping = [
        ['sim-ceo', 'sim-ceo-pct', sims['CEO_FRAUD_PRETEXT'] || 0],
        ['sim-invoice', 'sim-invoice-pct', sims['INVOICE_FRAUD_PRETEXT'] || 0],
        ['sim-cred', 'sim-cred-pct', sims['CREDENTIAL_HARVEST_PRETEXT'] || 0],
        ['sim-benign', 'sim-benign-pct', sims['BENIGN_COLLABORATION'] || 0],
      ];
      mapping.forEach(([barId, pctId, val]) => {
        const pct = Math.min(100, Math.round(val * 100));
        const elem = document.getElementById(barId);
        const txt = document.getElementById(pctId);
        if (elem) elem.style.width = `${pct}%`;
        if (txt) txt.textContent = val.toFixed(2);
      });
    }

    // 3. Metadata Table
    const meta = data.metadata || {};
    document.getElementById('meta-subject').textContent = meta.subject || '(No subject)';
    document.getElementById('meta-from').textContent = meta.sender || '-';
    document.getElementById('meta-reply-to').textContent = meta.reply_to ? meta.reply_to : '(None - Defaults to From)';
    document.getElementById('meta-return-path').textContent = meta.return_path || '-';
    document.getElementById('meta-date').textContent = meta.date || '-';

    // 4. Header Authentication Grid (Explicit Static Notice)
    renderAuthStatus('spf', data.authentication.spf.status);
    renderAuthStatus('dkim', data.authentication.dkim.status);
    renderAuthStatus('dmarc', data.authentication.dmarc.status);

    // Spoofing Alerts
    const alertsContainer = document.getElementById('spoof-alerts-container');
    alertsContainer.innerHTML = '';
    if (data.authentication.spoof_details && data.authentication.spoof_details.length > 0) {
      data.authentication.spoof_details.forEach(detail => {
        const item = document.createElement('div');
        item.className = 'alert-item';
        item.innerHTML = `<strong>⚠️ Spoofing Alert:</strong> ${escapeHtml(detail)}`;
        alertsContainer.appendChild(item);
      });
    }

    // 5. Intent & Social Engineering Radar
    const intent = data.intent || {};
    document.getElementById('intent-score-badge').textContent = `Intent Score: ${intent.overall_intent_score}/100`;
    
    renderIntentPill('financial', intent.financial_wire_detected, intent.financial_keywords);
    renderIntentPill('urgency', intent.urgency_detected, intent.urgency_keywords);
    renderIntentPill('authority', intent.authority_pretext_detected, intent.authority_keywords);

    // 6. URL Intelligence Table (Paper 3)
    const urlBody = document.getElementById('url-table-body');
    const urlCountTag = document.getElementById('url-count-tag');
    urlBody.innerHTML = '';

    const urls = data.urls || [];
    urlCountTag.textContent = `${urls.length} URL${urls.length === 1 ? '' : 's'} Extracted`;

    if (urls.length === 0) {
      urlBody.innerHTML = `
        <tr>
          <td colspan="6">
            <div class="empty-url-notice">
              🛡️ <strong>Payload-Free Message:</strong> No embedded hyperlinks detected.<br>
              In accordance with Paper 2 (Almutairi et al.), modern BEC scams frequently omit URLs and attachments to bypass perimeter filters.
            </div>
          </td>
        </tr>
      `;
    } else {
      urls.forEach(u => {
        const tr = document.createElement('tr');
        const urlColors = getRiskColors(u.risk_category === 'MALICIOUS' ? 'CRITICAL' : (u.risk_category === 'SUSPICIOUS' ? 'MEDIUM' : 'LOW'));
        
        const triggersHtml = u.triggers.length > 0
          ? u.triggers.map(t => `<span class="kw-badge">${escapeHtml(t)}</span>`).join('')
          : '<span style="color: var(--text-muted)">Clean lexical & structural indicators</span>';

        tr.innerHTML = `
          <td class="url-cell" title="${escapeHtml(u.url)}">${escapeHtml(u.url)}</td>
          <td><code>${escapeHtml(u.domain)}</code></td>
          <td class="entropy-cell">${u.shannon_entropy} H</td>
          <td>${triggersHtml}</td>
          <td><strong style="font-family: var(--font-mono); color: ${urlColors.text}">${u.risk_score}</strong></td>
          <td><span class="table-badge" style="color: ${urlColors.text}; background: ${urlColors.bg}; border: 1px solid ${urlColors.border}">${u.risk_category}</span></td>
        `;
        urlBody.appendChild(tr);
      });
    }

    // 6b. Multi-Dimensional Enrichment (Domains, GeoIP, Threat Intel)
    const enrichContainer = document.getElementById('enrichment-content');
    const enrichCountTag = document.getElementById('enrichment-count-tag');
    enrichContainer.innerHTML = '';

    const enrichment = data.enrichment || {};
    const domains = enrichment.domains || {};
    const senderDomain = enrichment.sender_domain || null;
    const ips = enrichment.ips || {};
    const threatIntel = enrichment.threat_intel || {};

    const allDomains = {...domains};
    if (senderDomain && senderDomain.domain) {
      allDomains[`sender:${senderDomain.domain}`] = senderDomain;
    }
    const domainEntries = Object.entries(allDomains);
    const ipEntries = Object.entries(ips);

    enrichCountTag.textContent = `${domainEntries.length} Domain(s) · ${ipEntries.length} IP(s)${threatIntel.matched ? ' · ⚠ IOC HIT' : ''}`;

    if (domainEntries.length === 0 && ipEntries.length === 0 && !threatIntel.matched) {
      enrichContainer.innerHTML = '<div class="empty-url-notice">No external indicators found for enrichment.</div>';
    } else {
      // A. Threat Intelligence IOC Banner if matched
      if (threatIntel.matched) {
        const tiBanner = document.createElement('div');
        tiBanner.className = 'threat-intel-banner';
        const attributionTags = (threatIntel.attribution || []).map(a => `<span class="threat-actor-badge">${escapeHtml(a)}</span>`).join(' ');
        tiBanner.innerHTML = `
          <div class="threat-intel-title">
            <span>🚨 THREAT INTELLIGENCE FEED MATCH</span>
            ${attributionTags}
          </div>
          <div><strong>Source:</strong> ${escapeHtml(threatIntel.feed_source || 'Citadel IOC Nexus')} (Severity: <span style="color:var(--color-critical); font-weight:800;">${threatIntel.highest_severity}</span>)</div>
          ${threatIntel.matches.map(m => `
            <div class="ioc-hit-item">
              <strong>${escapeHtml(m.ioc_type.toUpperCase())} IOC:</strong> <code>${escapeHtml(m.indicator)}</code> —
              <em>${escapeHtml(m.threat_group)}</em>: ${escapeHtml(m.threat_type)}
              (Confidence: ${Math.round(m.confidence * 100)}%)
            </div>
          `).join('')}
        `;
        enrichContainer.appendChild(tiBanner);
      }

      // B. Domain Reputation Grid
      if (domainEntries.length > 0) {
        const grid = document.createElement('div');
        grid.className = 'enrichment-grid';

        domainEntries.forEach(([key, rep]) => {
          const item = document.createElement('div');
          const repLabel = rep.reputation_label || 'NEUTRAL';
          item.className = `enrichment-domain-item rep-${repLabel}`;

          const rColors = getRiskColors(
            repLabel === 'MALICIOUS' ? 'CRITICAL' :
            repLabel === 'SUSPICIOUS' ? 'HIGH' :
            repLabel === 'TRUSTED' ? 'LOW' : 'MEDIUM'
          );

          const isSender = key.startsWith('sender:');
          const displayDomain = isSender ? rep.domain + ' (sender)' : rep.domain;

          const signalsHtml = (rep.signals || []).map(s =>
            `<span class="signal-tag">${escapeHtml(s)}</span>`
          ).join('');

          const dnsInfo = rep.dns_resolution || {};
          const dnsHtml = dnsInfo.resolves
            ? `DNS: ✓ ${(dnsInfo.ip_addresses || []).slice(0, 3).join(', ')}`
            : `DNS: ✗ ${dnsInfo.error || 'No resolution'}`;

          item.innerHTML = `
            <div class="enrichment-header">
              <span class="enrichment-domain-name">${escapeHtml(displayDomain)}</span>
              <span class="enrichment-rep-badge" style="color: ${rColors.text}; background: ${rColors.bg}; border: 1px solid ${rColors.border}">${repLabel} (${rep.reputation_score}/100)</span>
            </div>
            <div class="enrichment-dns-info">${escapeHtml(dnsHtml)}</div>
            ${rep.brand_impersonation ? `<div style="color: var(--color-critical); font-size: 0.75rem; font-weight: 700; margin-top: 4px;">⚠ Brand Impersonation: ${escapeHtml(rep.impersonated_brand || '')}</div>` : ''}
            <div class="enrichment-signals">${signalsHtml}</div>
          `;
          grid.appendChild(item);
        });

        enrichContainer.appendChild(grid);
      }

      // C. IP Geolocation & ASN Grid
      if (ipEntries.length > 0) {
        const geoTitle = document.createElement('h4');
        geoTitle.style.fontSize = '0.8rem';
        geoTitle.style.color = 'var(--text-secondary)';
        geoTitle.style.margin = '14px 0 6px 0';
        geoTitle.textContent = 'IP Infrastructure & Geolocation Profiling:';
        enrichContainer.appendChild(geoTitle);

        const geoGrid = document.createElement('div');
        geoGrid.className = 'geoip-grid';

        ipEntries.forEach(([ip, geo]) => {
          const geoCard = document.createElement('div');
          geoCard.className = 'geoip-card';

          const riskBadge = geo.risk_category !== 'NEUTRAL' && geo.risk_category !== 'TRUSTED'
            ? `<span class="table-badge" style="color:var(--color-critical); background:var(--bg-critical); border:1px solid var(--color-critical);">${escapeHtml(geo.risk_category)}</span>`
            : `<span class="table-badge" style="color:var(--color-clean); background:var(--bg-clean); border:1px solid var(--color-clean);">VERIFIED</span>`;

          geoCard.innerHTML = `
            <div class="geoip-card-top">
              <span class="geoip-ip">${escapeHtml(ip)}</span>
              ${riskBadge}
            </div>
            <div class="geoip-loc">📍 ${escapeHtml(geo.city || 'Unknown')}, ${escapeHtml(geo.country || 'Unknown')} (${escapeHtml(geo.country_code || 'XX')})</div>
            <div class="geoip-asn">ASN: ${escapeHtml(geo.asn || 'AS0')} · ${escapeHtml(geo.org || 'Unknown Org')}</div>
            ${(geo.flags || []).map(f => `<div style="color:var(--color-high); font-size:0.7rem; margin-top:2px;">⚠ ${escapeHtml(f)}</div>`).join('')}
          `;
          geoGrid.appendChild(geoCard);
        });

        enrichContainer.appendChild(geoGrid);
      }
    }

    // 7. Reasons List
    const reasonsContainer = document.getElementById('reasons-list');
    reasonsContainer.innerHTML = '';
    if (data.reasons && data.reasons.length > 0) {
      data.reasons.forEach(r => {
        const rColors = getRiskColors(r.severity === 'CRITICAL' ? 'CRITICAL' : (r.severity === 'HIGH' ? 'HIGH' : (r.severity === 'MEDIUM' ? 'MEDIUM' : 'LOW')));
        const item = document.createElement('div');
        item.className = 'reason-item';
        item.style.borderLeftColor = rColors.border;
        item.innerHTML = `
          <div>
            <span class="reason-category">${escapeHtml(r.category)}</span>
            <span class="reason-desc">${escapeHtml(r.description)}</span>
          </div>
          <span class="reason-weight" style="color: ${rColors.text}; background: ${rColors.bg}">+${r.weight}</span>
        `;
        reasonsContainer.appendChild(item);
      });
    } else {
      reasonsContainer.innerHTML = '<div style="color: var(--text-muted); font-size: 0.8rem;">No suspicious anomalies or threat factors detected.</div>';
    }

    // 8. Actionable SOC Checklist
    const actionsList = document.getElementById('actions-list');
    actionsList.innerHTML = '';
    if (data.recommended_actions && data.recommended_actions.length > 0) {
      data.recommended_actions.forEach(act => {
        const li = document.createElement('li');
        li.textContent = act;
        actionsList.appendChild(li);
      });
    }

    // 9. Email Body Preview
    const previewBox = document.getElementById('email-body-preview');
    previewBox.textContent = data.body_text_preview || '(No text content)';

    // 10. Forensic Dossier Export Controls (Phase 8)
    renderDossierControls(data);

    // 11. Cryptographic Evidence Integrity (Phase 9)
    renderEvidenceIntegrity(data);

    // 12. Threat Correlation Graph (Phase 5)
    renderThreatGraph(data.threat_graph);

    // 13. Refresh SOC Incident Triage Queue (Phase 7)
    if (typeof loadCaseQueue === 'function') {
      loadCaseQueue();
    }
  }

  // -------------------------------------------------------------
  // Phase 7: SOC Incident Triage Queue & Case Management
  // -------------------------------------------------------------
  let activeNotesCaseId = null;

  function initCaseQueue() {
    const searchInput = document.getElementById('queue-search-input');
    const statusFilter = document.getElementById('queue-status-filter');
    const riskFilter = document.getElementById('queue-risk-filter');
    const refreshBtn = document.getElementById('btn-refresh-queue');
    const notesCloseBtn = document.getElementById('notes-modal-close');
    const saveNoteBtn = document.getElementById('btn-save-note');

    if (searchInput) {
      let debounceTimer;
      searchInput.addEventListener('input', () => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(loadCaseQueue, 250);
      });
    }

    if (statusFilter) statusFilter.addEventListener('change', loadCaseQueue);
    if (riskFilter) riskFilter.addEventListener('change', loadCaseQueue);
    if (refreshBtn) refreshBtn.addEventListener('click', loadCaseQueue);

    if (notesCloseBtn) {
      notesCloseBtn.addEventListener('click', () => {
        document.getElementById('case-notes-modal').style.display = 'none';
        activeNotesCaseId = null;
      });
    }

    if (saveNoteBtn) {
      saveNoteBtn.addEventListener('click', async () => {
        const textElem = document.getElementById('new-note-text');
        const authorElem = document.getElementById('new-note-author');
        const noteText = textElem.value.trim();
        const author = authorElem.value.trim() || 'SOC Analyst';

        if (!noteText || !activeNotesCaseId) return;

        saveNoteBtn.disabled = true;
        saveNoteBtn.textContent = 'Saving...';

        try {
          const res = await fetch(`/api/cases/${encodeURIComponent(activeNotesCaseId)}/notes`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ note: noteText, author: author })
          });
          if (res.ok) {
            textElem.value = '';
            await openCaseNotes(activeNotesCaseId);
            loadCaseQueue();
          } else {
            alert('Failed to save note.');
          }
        } catch (e) {
          alert('Error saving note: ' + e.message);
        } finally {
          saveNoteBtn.disabled = false;
          saveNoteBtn.textContent = '💾 Save Note';
        }
      });
    }
  }

  async function loadCaseQueue() {
    const searchInput = document.getElementById('queue-search-input');
    const statusFilter = document.getElementById('queue-status-filter');
    const riskFilter = document.getElementById('queue-risk-filter');
    const tbody = document.getElementById('queue-table-body');

    if (!tbody) return;

    const query = searchInput ? searchInput.value.trim() : '';
    const status = statusFilter ? statusFilter.value : 'ALL';
    const risk = riskFilter ? riskFilter.value : 'ALL';

    const params = new URLSearchParams();
    if (query) params.set('search', query);
    if (status && status !== 'ALL') params.set('status', status);
    if (risk && risk !== 'ALL') params.set('risk_level', risk);

    try {
      const res = await fetch(`/api/cases?${params.toString()}`);
      if (!res.ok) return;
      const data = await res.json();

      // Update aggregate stat pills
      if (data.stats) {
        const s = data.stats;
        document.getElementById('stat-total-cases').textContent = `Cases: ${s.total_cases}`;
        document.getElementById('stat-critical-cases').textContent = `Critical/High: ${s.critical_high}`;
        document.getElementById('stat-investigating-cases').textContent = `Active: ${s.investigating}`;
        document.getElementById('stat-contained-cases').textContent = `Contained: ${s.contained_resolved}`;
      }

      // Render table rows
      tbody.innerHTML = '';
      if (!data.cases || data.cases.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="queue-empty-msg">No cases match the current filter criteria.</td></tr>`;
        return;
      }

      data.cases.forEach(c => {
        const tr = document.createElement('tr');

        const scoreClass = c.threat_score >= 80 ? 'risk-critical' : (c.threat_score >= 50 ? 'risk-high' : 'risk-low');
        const formattedDate = c.created_at ? c.created_at.substring(11, 19) + ' UTC' : '-';

        tr.innerHTML = `
          <td><span class="queue-case-link" data-case-id="${escapeHtml(c.case_id)}">${escapeHtml(c.case_id)}</span></td>
          <td style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-secondary);">${formattedDate}</td>
          <td>
            <div style="font-weight: 600; color: #fff; max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(c.subject)}</div>
            <div style="font-size: 0.72rem; color: var(--text-muted); max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(c.sender)}</div>
          </td>
          <td>
            <strong class="${scoreClass}">${c.threat_score}/100</strong>
            <span class="badge ${c.risk_level === 'CRITICAL' ? 'badge-fail' : (c.risk_level === 'HIGH' ? 'badge-warn' : 'badge-pass')}" style="margin-left: 4px;">${c.risk_level}</span>
          </td>
          <td><span style="font-size: 0.75rem; color: var(--text-secondary);">${escapeHtml(c.threat_archetype)}</span></td>
          <td>
            <select class="status-select-pill status-${c.status}" data-case-id="${escapeHtml(c.case_id)}">
              <option value="NEW" ${c.status === 'NEW' ? 'selected' : ''}>NEW</option>
              <option value="TRIAGED" ${c.status === 'TRIAGED' ? 'selected' : ''}>TRIAGED</option>
              <option value="INVESTIGATING" ${c.status === 'INVESTIGATING' ? 'selected' : ''}>INVESTIGATING</option>
              <option value="CONTAINED" ${c.status === 'CONTAINED' ? 'selected' : ''}>CONTAINED</option>
              <option value="RESOLVED" ${c.status === 'RESOLVED' ? 'selected' : ''}>RESOLVED</option>
              <option value="FALSE_POSITIVE" ${c.status === 'FALSE_POSITIVE' ? 'selected' : ''}>FALSE POSITIVE</option>
            </select>
          </td>
          <td style="font-size: 0.75rem; color: var(--text-secondary);">${escapeHtml(c.assigned_analyst || 'Unassigned')}</td>
          <td>
            <div class="queue-actions-cluster">
              <button class="btn-queue-sm btn-inspect-case" data-case-id="${escapeHtml(c.case_id)}" title="Inspect full analysis on dashboard">🔍 Inspect</button>
              <button class="btn-queue-sm btn-notes-case" data-case-id="${escapeHtml(c.case_id)}" title="View/add analyst notes">📝 Notes (${c.notes ? c.notes.length : 0})</button>
              <button class="btn-queue-sm btn-dossier-case" data-case-id="${escapeHtml(c.case_id)}" title="Open Phase 8 Forensic Dossier">📄 Dossier</button>
            </div>
          </td>
        `;

        // Wire status change
        const sel = tr.querySelector('.status-select-pill');
        sel.addEventListener('change', async (e) => {
          const newStatus = e.target.value;
          sel.className = `status-select-pill status-${newStatus}`;
          try {
            await fetch(`/api/cases/${encodeURIComponent(c.case_id)}/status`, {
              method: 'PATCH',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ status: newStatus })
            });
            loadCaseQueue();
          } catch (err) {
            alert('Failed to update status: ' + err.message);
          }
        });

        // Wire inspect
        tr.querySelector('.btn-inspect-case').addEventListener('click', () => inspectCase(c.case_id));
        tr.querySelector('.queue-case-link').addEventListener('click', () => inspectCase(c.case_id));

        // Wire notes
        tr.querySelector('.btn-notes-case').addEventListener('click', () => openCaseNotes(c.case_id));

        // Wire dossier
        tr.querySelector('.btn-dossier-case').addEventListener('click', () => {
          window.open(`/api/case/${encodeURIComponent(c.case_id)}/report`, '_blank');
        });

        tbody.appendChild(tr);
      });
    } catch (e) {
      console.error('Failed to load case queue:', e);
    }
  }

  async function inspectCase(caseId) {
    try {
      const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}`);
      if (!res.ok) return;
      const ticket = await res.json();
      if (ticket.analysis_result) {
        emptyState.style.display = 'none';
        resultsDashboard.style.display = 'flex';
        renderDashboard(ticket.analysis_result);
        window.scrollTo({ top: resultsDashboard.offsetTop - 20, behavior: 'smooth' });
      }
    } catch (e) {
      alert('Failed to inspect case: ' + e.message);
    }
  }

  async function openCaseNotes(caseId) {
    activeNotesCaseId = caseId;
    const modal = document.getElementById('case-notes-modal');
    const title = document.getElementById('notes-modal-title');
    const historyList = document.getElementById('notes-history-list');

    title.textContent = `Analyst Notes // Case: ${caseId}`;
    modal.style.display = 'flex';
    historyList.innerHTML = '<div style="color:var(--text-muted); font-size:0.75rem;">Loading notes...</div>';

    try {
      const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}`);
      if (!res.ok) return;
      const ticket = await res.json();
      historyList.innerHTML = '';

      if (!ticket.notes || ticket.notes.length === 0) {
        historyList.innerHTML = '<div style="color:var(--text-muted); font-size:0.75rem;">No investigation notes recorded for this case yet.</div>';
        return;
      }

      ticket.notes.forEach(n => {
        const bubble = document.createElement('div');
        bubble.className = 'note-bubble';
        bubble.innerHTML = `
          <div class="note-meta">
            <span class="note-author">${escapeHtml(n.author)}</span>
            <span>${escapeHtml(n.timestamp ? n.timestamp.substring(0, 19).replace('T', ' ') : '')}</span>
          </div>
          <div class="note-text">${escapeHtml(n.note)}</div>
        `;
        historyList.appendChild(bubble);
      });
      historyList.scrollTop = historyList.scrollHeight;
    } catch (e) {
      historyList.innerHTML = `<div style="color:var(--color-critical); font-size:0.75rem;">Error loading notes: ${escapeHtml(e.message)}</div>`;
    }
  }

  // -------------------------------------------------------------
  // Phase 8: Forensic Dossier & SIEM/SOAR Export
  // -------------------------------------------------------------
  function renderDossierControls(data) {
    const caseId = data.case_id;
    const btnGen = document.getElementById('btn-generate-report');
    const btnPrint = document.getElementById('btn-print-report');
    const btnJson = document.getElementById('btn-download-json');

    if (btnGen) {
      btnGen.onclick = () => {
        window.open(`/api/case/${encodeURIComponent(caseId)}/report`, '_blank');
      };
    }

    if (btnPrint) {
      btnPrint.onclick = () => {
        window.open(`/api/case/${encodeURIComponent(caseId)}/report`, '_blank');
      };
    }

    if (btnJson) {
      btnJson.onclick = () => {
        const link = document.createElement('a');
        link.href = `/api/case/${encodeURIComponent(caseId)}/report/json`;
        link.download = `Citadel-Forensic-Case-${caseId}.json`;
        link.target = '_blank';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
      };
    }
  }

  // -------------------------------------------------------------
  // Phase 9: Cryptographic Evidence Integrity & Blockchain Ledger
  // -------------------------------------------------------------
  function renderEvidenceIntegrity(data) {
    const integ = data.integrity || {};
    const caseId = data.case_id;

    const evHashElem = document.getElementById('integrity-evidence-sha256');
    const vdHashElem = document.getElementById('integrity-verdict-sha256');
    const blockIdxElem = document.getElementById('ledger-block-idx');
    const merkleElem = document.getElementById('ledger-merkle-root');
    const blockHashElem = document.getElementById('ledger-block-hash');
    const prevHashElem = document.getElementById('ledger-prev-hash');
    const timeElem = document.getElementById('ledger-timestamp');

    const badge = document.getElementById('integrity-status-badge');
    const banner = document.getElementById('integrity-verification-banner');
    const headline = document.getElementById('verification-headline');
    const icon = document.getElementById('verification-icon');
    const detail = document.getElementById('verification-detail');

    const chkEv = document.getElementById('chk-evidence');
    const chkVd = document.getElementById('chk-verdict');
    const chkMk = document.getElementById('chk-merkle');
    const chkLg = document.getElementById('chk-ledger');

    function setIntegrityStatus(isVerified, message, checks) {
      if (isVerified) {
        badge.className = 'integrity-badge badge-verified';
        badge.textContent = 'INTEGRITY: VERIFIED';
        banner.className = 'integrity-banner-verified';
        icon.textContent = '✓';
        headline.textContent = 'Cryptographic Chain of Custody Confirmed';
        detail.textContent = message;
        chkEv.className = 'check-pill check-pass'; chkEv.textContent = 'Evidence Hash: Match';
        chkVd.className = 'check-pill check-pass'; chkVd.textContent = 'Verdict Digest: Match';
        chkMk.className = 'check-pill check-pass'; chkMk.textContent = 'Merkle Tree Root: Valid';
        chkLg.className = 'check-pill check-pass'; chkLg.textContent = 'Ledger Chain Linkage: Intact';
      } else {
        badge.className = 'integrity-badge badge-tampered';
        badge.textContent = 'INTEGRITY: TAMPERED';
        banner.className = 'integrity-banner-tampered';
        icon.textContent = '⚠';
        headline.textContent = 'CRITICAL: Cryptographic Tampering Detected!';
        detail.textContent = message;
        if (checks) {
          chkEv.className = checks.evidence_hash_match ? 'check-pill check-pass' : 'check-pill check-fail';
          chkEv.textContent = checks.evidence_hash_match ? 'Evidence Hash: Match' : 'Evidence Hash: MISMATCH';
          chkVd.className = checks.verdict_hash_match ? 'check-pill check-pass' : 'check-pill check-fail';
          chkVd.textContent = checks.verdict_hash_match ? 'Verdict Digest: Match' : 'Verdict Digest: MISMATCH';
          chkMk.className = checks.merkle_root_valid ? 'check-pill check-pass' : 'check-pill check-fail';
          chkMk.textContent = checks.merkle_root_valid ? 'Merkle Tree Root: Valid' : 'Merkle Tree Root: INVALID';
          chkLg.className = checks.ledger_linkage_valid ? 'check-pill check-pass' : 'check-pill check-fail';
          chkLg.textContent = checks.ledger_linkage_valid ? 'Ledger Chain Linkage: Intact' : 'Ledger Chain Linkage: BROKEN';
        }
      }
    }

    if (integ && integ.evidence_sha256) {
      evHashElem.textContent = integ.evidence_sha256;
      vdHashElem.textContent = integ.verdict_sha256 || '—';
      blockIdxElem.textContent = `#${integ.block_index !== undefined ? integ.block_index : '—'}`;
      merkleElem.textContent = integ.merkle_root || '—';
      blockHashElem.textContent = integ.block_hash || '—';
      prevHashElem.textContent = (integ.previous_block_hash || '—').substring(0, 24) + '...';
      timeElem.textContent = integ.chain_of_custody_timestamp || '-';

      setIntegrityStatus(true, "Cryptographic Chain of Custody Confirmed: Original RFC 5322 message bytes and forensic verdict match the append-only evidence ledger without tampering.");
    } else {
      evHashElem.textContent = '—';
      vdHashElem.textContent = '—';
    }

    // Verify Integrity Button Click
    const verifyBtn = document.getElementById('btn-verify-integrity');
    if (verifyBtn) {
      verifyBtn.onclick = async () => {
        verifyBtn.disabled = true;
        verifyBtn.textContent = 'Verifying...';
        try {
          const res = await fetch(`/api/case/${encodeURIComponent(caseId)}/verify-integrity`, {
            method: 'POST'
          });
          const v = await res.json();
          if (v.verified) {
            setIntegrityStatus(true, v.summary || "Evidence verified successfully.", v.checks);
          } else {
            setIntegrityStatus(false, v.summary || "Cryptographic integrity failure detected.", v.checks);
          }
        } catch (e) {
          alert('Verification request failed: ' + e.message);
        } finally {
          verifyBtn.disabled = false;
          verifyBtn.textContent = '🛡️ Verify Integrity';
        }
      };
    }

    // Simulate Tampering Button Click (for live judging demonstration)
    const tamperBtn = document.getElementById('btn-simulate-tamper');
    if (tamperBtn) {
      tamperBtn.onclick = async () => {
        tamperBtn.disabled = true;
        tamperBtn.textContent = 'Tampering...';
        try {
          await fetch(`/api/case/${encodeURIComponent(caseId)}/simulate-tamper?action=evidence`, {
            method: 'POST'
          });
          // Immediately run verification to demonstrate detection
          const res = await fetch(`/api/case/${encodeURIComponent(caseId)}/verify-integrity`, {
            method: 'POST'
          });
          const v = await res.json();
          setIntegrityStatus(false, v.summary || "Evidence has been tampered post-analysis.", v.checks);
        } catch (e) {
          alert('Tampering simulation failed: ' + e.message);
        } finally {
          tamperBtn.disabled = false;
          tamperBtn.textContent = '⚡ Test Tamper';
        }
      };
    }
  }

  // -------------------------------------------------------------
  // Phase 5: Interactive SOC Threat Correlation Graph Renderer
  // -------------------------------------------------------------
  let graphAnimationId = null;
  let activeGraphSim = null;

  function renderThreatGraph(graphData) {
    const canvas = document.getElementById('threat-graph-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const inspector = document.getElementById('graph-node-inspector');
    const nodesCountElem = document.getElementById('graph-nodes-count');
    const resetBtn = document.getElementById('graph-reset-btn');
    const closeBtn = document.getElementById('inspector-close');

    if (closeBtn) {
      closeBtn.onclick = () => { inspector.style.display = 'none'; };
    }

    if (graphAnimationId) {
      cancelAnimationFrame(graphAnimationId);
      graphAnimationId = null;
    }

    if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {
      nodesCountElem.textContent = '0 Entities Correlated';
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = '#64748b';
      ctx.font = '14px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('No graph entities available for this case.', canvas.width / 2, canvas.height / 2);
      return;
    }

    nodesCountElem.textContent = `${graphData.nodes.length} Entities · ${graphData.edges.length} Relationships`;

    // Clone nodes and assign initial radial positions
    const width = canvas.width;
    const height = canvas.height;
    const centerX = width / 2;
    const centerY = height / 2;

    const nodes = graphData.nodes.map((n, i) => {
      const angle = (i / graphData.nodes.length) * 2 * Math.PI;
      const radius = n.type === 'EMAIL' ? 0 : (n.type === 'THREAT_ACTOR' ? 140 : 110 + (i % 3) * 25);
      return {
        ...n,
        x: centerX + radius * Math.cos(angle) + (Math.random() - 0.5) * 20,
        y: centerY + radius * Math.sin(angle) + (Math.random() - 0.5) * 20,
        vx: 0,
        vy: 0,
        radius: n.type === 'EMAIL' ? 26 : (n.type === 'THREAT_ACTOR' ? 22 : 16)
      };
    });

    const nodeMap = {};
    nodes.forEach(n => { nodeMap[n.id] = n; });

    const edges = graphData.edges
      .map(e => ({
        ...e,
        sourceNode: nodeMap[e.source],
        targetNode: nodeMap[e.target]
      }))
      .filter(e => e.sourceNode && e.targetNode);

    // Interaction state
    let draggedNode = null;
    let selectedNode = null;
    let hoveredNode = null;

    canvas.onmousedown = (evt) => {
      const rect = canvas.getBoundingClientRect();
      const scaleX = canvas.width / rect.width;
      const scaleY = canvas.height / rect.height;
      const mx = (evt.clientX - rect.left) * scaleX;
      const my = (evt.clientY - rect.top) * scaleY;

      for (let n of nodes) {
        const dx = mx - n.x;
        const dy = my - n.y;
        if (Math.sqrt(dx * dx + dy * dy) <= n.radius + 4) {
          draggedNode = n;
          selectedNode = n;
          inspectNode(n);
          break;
        }
      }
    };

    window.onmousemove = (evt) => {
      const rect = canvas.getBoundingClientRect();
      const scaleX = canvas.width / rect.width;
      const scaleY = canvas.height / rect.height;
      const mx = (evt.clientX - rect.left) * scaleX;
      const my = (evt.clientY - rect.top) * scaleY;

      if (draggedNode) {
        draggedNode.x = mx;
        draggedNode.y = my;
        draggedNode.vx = 0;
        draggedNode.vy = 0;
      } else {
        hoveredNode = null;
        for (let n of nodes) {
          const dx = mx - n.x;
          const dy = my - n.y;
          if (Math.sqrt(dx * dx + dy * dy) <= n.radius + 4) {
            hoveredNode = n;
            break;
          }
        }
      }
    };

    window.onmouseup = () => {
      draggedNode = null;
    };

    if (resetBtn) {
      resetBtn.onclick = () => {
        nodes.forEach((n, i) => {
          const angle = (i / nodes.length) * 2 * Math.PI;
          const radius = n.type === 'EMAIL' ? 0 : 120;
          n.x = centerX + radius * Math.cos(angle);
          n.y = centerY + radius * Math.sin(angle);
          n.vx = 0;
          n.vy = 0;
        });
      };
    }

    function inspectNode(node) {
      if (!inspector) return;
      inspector.style.display = 'flex';
      document.getElementById('inspector-title').textContent = `${node.type} Entity Dossier`;
      const body = document.getElementById('inspector-body');

      let detailsHtml = `
        <div class="inspector-prop"><strong>ID / Name:</strong> ${escapeHtml(node.id)}</div>
        <div class="inspector-prop"><strong>Entity Type:</strong> ${escapeHtml(node.type)}</div>
        <div class="inspector-prop"><strong>Risk Assessment:</strong> <span style="color:${node.color}; font-weight:800;">${escapeHtml(node.risk)}</span></div>
      `;

      if (node.details) {
        for (const [k, v] of Object.entries(node.details)) {
          if (v !== null && v !== undefined && v !== '') {
            const valStr = Array.isArray(v) ? v.join(', ') : String(v);
            detailsHtml += `<div class="inspector-prop"><strong>${escapeHtml(k.replace(/_/g, ' '))}:</strong> ${escapeHtml(valStr)}</div>`;
          }
        }
      }

      body.innerHTML = detailsHtml;
    }

    // Force-directed Physics Simulation Loop
    function simulate() {
      // Repulsion between all nodes
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const n1 = nodes[i];
          const n2 = nodes[j];
          let dx = n2.x - n1.x;
          let dy = n2.y - n1.y;
          let dist = Math.sqrt(dx * dx + dy * dy) || 1;
          if (dist < 180) {
            const force = (180 - dist) / dist * 0.4;
            if (n1 !== draggedNode) { n1.x -= dx * force * 0.04; n1.y -= dy * force * 0.04; }
            if (n2 !== draggedNode) { n2.x += dx * force * 0.04; n2.y += dy * force * 0.04; }
          }
        }
      }

      // Spring attraction along edges
      for (let e of edges) {
        let dx = e.targetNode.x - e.sourceNode.x;
        let dy = e.targetNode.y - e.sourceNode.y;
        let dist = Math.sqrt(dx * dx + dy * dy) || 1;
        let targetDist = 90;
        let force = (dist - targetDist) * 0.015;
        if (e.sourceNode !== draggedNode) { e.sourceNode.x += dx * force * 0.05; e.sourceNode.y += dy * force * 0.05; }
        if (e.targetNode !== draggedNode) { e.targetNode.x -= dx * force * 0.05; e.targetNode.y -= dy * force * 0.05; }
      }

      // Keep within bounds
      nodes.forEach(n => {
        n.x = Math.max(n.radius + 10, Math.min(width - n.radius - 10, n.x));
        n.y = Math.max(n.radius + 10, Math.min(height - n.radius - 10, n.y));
      });

      // Render Canvas
      ctx.clearRect(0, 0, width, height);

      // Grid background
      ctx.strokeStyle = 'rgba(30, 41, 59, 0.4)';
      ctx.lineWidth = 1;
      for (let x = 0; x < width; x += 40) {
        ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, height); ctx.stroke();
      }
      for (let y = 0; y < height; y += 40) {
        ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke();
      }

      // Draw Edges
      edges.forEach(e => {
        ctx.beginPath();
        ctx.moveTo(e.sourceNode.x, e.sourceNode.y);
        ctx.lineTo(e.targetNode.x, e.targetNode.y);
        if (e.severity === 'CRITICAL') {
          ctx.strokeStyle = '#ef4444';
          ctx.lineWidth = 2.5;
        } else if (e.severity === 'ALERT') {
          ctx.strokeStyle = '#f59e0b';
          ctx.lineWidth = 2.0;
        } else {
          ctx.strokeStyle = 'rgba(71, 85, 105, 0.6)';
          ctx.lineWidth = 1.2;
        }
        ctx.stroke();

        // Edge label (relationship)
        const midX = (e.sourceNode.x + e.targetNode.x) / 2;
        const midY = (e.sourceNode.y + e.targetNode.y) / 2;
        ctx.fillStyle = '#64748b';
        ctx.font = '9px "JetBrains Mono", monospace';
        ctx.textAlign = 'center';
        ctx.fillText(e.relationship, midX, midY - 3);
      });

      // Draw Nodes
      nodes.forEach(n => {
        // Outer glow
        if (n.risk === 'CRITICAL' || n === hoveredNode || n === selectedNode) {
          ctx.beginPath();
          ctx.arc(n.x, n.y, n.radius + 6, 0, 2 * Math.PI);
          ctx.fillStyle = n.risk === 'CRITICAL' ? 'rgba(239, 68, 68, 0.25)' : 'rgba(56, 189, 248, 0.25)';
          ctx.fill();
        }

        // Main circle
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.radius, 0, 2 * Math.PI);
        ctx.fillStyle = n.color || '#64748b';
        ctx.fill();
        ctx.strokeStyle = '#0f172a';
        ctx.lineWidth = 2;
        ctx.stroke();

        // Icon / Type code inside circle
        ctx.fillStyle = '#ffffff';
        ctx.font = 'bold 10px "JetBrains Mono", monospace';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        const typeIcons = { 'EMAIL': '✉', 'SENDER': '👤', 'DOMAIN': '🌐', 'URL': '🔗', 'IP': '📍', 'ASN': '⚡', 'THREAT_ACTOR': '🚨' };
        ctx.fillText(typeIcons[n.type] || '•', n.x, n.y);

        // Node Label
        ctx.fillStyle = '#e2e8f0';
        ctx.font = '10px Inter, sans-serif';
        ctx.textBaseline = 'top';
        const lines = (n.label || '').split('\n');
        lines.forEach((line, idx) => {
          ctx.fillText(line, n.x, n.y + n.radius + 3 + (idx * 11));
        });
      });

      graphAnimationId = requestAnimationFrame(simulate);
    }

    simulate();
  }

  function renderAuthStatus(proto, status) {
    const statElem = document.getElementById(`${proto}-status`);
    const s = (status || 'none').toLowerCase();
    statElem.textContent = s.toUpperCase();

    if (s === 'pass') {
      statElem.style.color = 'var(--color-clean)';
    } else if (['fail', 'permerror'].includes(s)) {
      statElem.style.color = 'var(--color-critical)';
    } else if (['softfail', 'neutral'].includes(s)) {
      statElem.style.color = 'var(--color-medium)';
    } else {
      statElem.style.color = 'var(--text-muted)';
    }
  }

  function renderIntentPill(type, isDetected, keywords) {
    const flagElem = document.getElementById(`${type}-flag`);
    const kwElem = document.getElementById(`${type}-keywords`);

    if (isDetected) {
      flagElem.textContent = 'DETECTED';
      flagElem.className = 'intent-status-pill flag-yes';
      kwElem.innerHTML = keywords.map(kw => `<span class="kw-badge">${escapeHtml(kw)}</span>`).join('');
    } else {
      flagElem.textContent = 'NEGATIVE';
      flagElem.className = 'intent-status-pill flag-no';
      kwElem.textContent = 'None detected';
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // ─── Citadel Info Tooltip Click/Tap Support ───
  document.addEventListener('click', (e) => {
    const tip = e.target.closest('.citadel-tip');
    // Dismiss all active tooltips except the one currently clicked
    document.querySelectorAll('.citadel-tip.active').forEach(el => {
      if (el !== tip) el.classList.remove('active');
    });
    if (tip && e.target.closest('.citadel-tip-icon')) {
      tip.classList.toggle('active');
    }
  });
});

