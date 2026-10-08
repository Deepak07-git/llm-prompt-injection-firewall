(() => {
  const $ = (selector) => document.querySelector(selector);
  const welcome = $('#welcome'), messages = $('#messages'), input = $('#messageInput');
  const sendButton = $('#sendButton'), historyEl = $('#history'), modelSelect = $('#modelSelect');
  const esc = (value) => String(value).replace(/[&<>"']/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
  let conversationId = null, turns = [], busy = false, searchTerm = '', toastTimer;
  const codeBlocks = [];

  function markdown(text) {
    let source = esc(text).replace(/\r\n?/g, '\n').replace(/```([\w+-]*)\n([\s\S]*?)```/g, (_, lang, code) => {
      const index = codeBlocks.push(`<pre><code>${code.trimEnd()}</code></pre>`) - 1;
      return `\u0000${index}\u0000`;
    });
    source = source.replace(/`([^`\n]+)`/g, '<code>$1</code>');
    const inline = (line) => line.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>').replace(/\*(.+?)\*/g, '<em>$1</em>').replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
    const lines = source.split('\n'), html = []; let paragraph = [], list = '', listType = '';
    const flushParagraph = () => { if (paragraph.length) html.push(`<p>${inline(paragraph.join('<br>'))}</p>`); paragraph = []; };
    const flushList = () => { if (list) html.push(`</${listType}>`); list = ''; listType = ''; };
    for (const line of lines) {
      const fence = line.match(/^\u0000(\d+)\u0000$/);
      const heading = line.match(/^(#{1,3})\s+(.+)$/);
      const bullet = line.match(/^\s*[-*+]\s+(.+)$/);
      const ordered = line.match(/^\s*\d+[.)]\s+(.+)$/);
      if (!line.trim() || fence || heading || bullet || ordered || /^&gt;\s?/.test(line)) flushParagraph();
      if (fence) { flushList(); html.push(codeBlocks[Number(fence[1])]); }
      else if (heading) { flushList(); const level = heading[1].length; html.push(`<h${level}>${inline(heading[2])}</h${level}>`); }
      else if (bullet || ordered) { const type = bullet ? 'ul' : 'ol'; if (listType !== type) { flushList(); listType = type; html.push(`<${type}>`); list = type; } html.push(`<li>${inline((bullet || ordered)[1])}</li>`); }
      else if (/^&gt;\s?/.test(line)) { flushList(); html.push(`<blockquote>${inline(line.replace(/^&gt;\s?/, ''))}</blockquote>`); }
      else { flushList(); if (line.trim()) paragraph.push(line); }
    }
    flushParagraph(); flushList();
    return html.join('').replace(/\u0000(\d+)\u0000/g, (_, index) => codeBlocks[Number(index)]);
  }

  async function api(path, options = {}) {
    const response = await fetch(path, { credentials: 'same-origin', ...options });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'The request did not complete.');
    return data;
  }
  function toast(message) {
    const el = $('#toast'); el.textContent = message; el.classList.add('visible'); clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove('visible'), 2700);
  }
  function setConnection(online) {
    $('#headerDot').classList.toggle('online', online); $('#headerDot').classList.toggle('offline', !online);
    $('#headerDot').title = online ? 'Firewall and local model connected' : 'Firewall or local model disconnected';
  }
  function updateInput() {
    input.style.height = 'auto'; input.style.height = `${Math.min(input.scrollHeight, 180)}px`;
    sendButton.disabled = busy || !input.value.trim();
    const count = input.value.length; $('#charCount').textContent = count > 13000 ? `${count.toLocaleString()}/16,000` : '';
  }
  function scrollBottom() { $('#chatArea').scrollTo({ top: $('#chatArea').scrollHeight, behavior: 'smooth' }); }
  function messageNode(role, text, security = null, streaming = false) {
    const article = document.createElement('article'); article.className = `message ${role}`;
    const name = role === 'user' ? 'You' : 'Orbit';
    const badge = security ? `<span class="badge">⬡ FIREWALL CLEARED</span>` : '';
    article.innerHTML = `<div class="message-avatar">${role === 'user' ? 'Y' : '✳'}</div><div class="message-content"><div class="message-meta"><b>${name}</b><span>${new Intl.DateTimeFormat(undefined,{hour:'numeric',minute:'2-digit'}).format(new Date())}</span>${badge}</div><div class="message-body">${role === 'assistant' ? markdown(text) : `<p>${esc(text).replace(/\n/g,'<br>')}</p>`}</div>${security ? `<div class="security-card"><span>⬡</span><span>${esc(security.input).toUpperCase()} IN</span><span class="security-divider">·</span><span>${esc(security.output).toUpperCase()} OUT</span><span class="security-divider">·</span><span>${esc(security.model)}</span></div>` : ''}${streaming ? '<div class="typing"><span></span><span></span><span></span><span class="typing-label">Checking your message…</span></div>' : ''}${role === 'assistant' && !streaming ? '<div class="message-actions"><button class="message-action copy-reply">Copy</button></div>' : ''}</div>`;
    article.querySelector('.copy-reply')?.addEventListener('click', async (event) => {
      const button = event.currentTarget;
      try { await navigator.clipboard.writeText(text); button.textContent = 'Copied'; setTimeout(() => button.textContent = 'Copy', 1400); }
      catch { toast('Copy is not available in this browser.'); }
    });
    messages.append(article); scrollBottom(); return article;
  }
  function showChat() { welcome.classList.add('hidden'); messages.classList.remove('hidden'); }
  function showHome() { welcome.classList.remove('hidden'); messages.classList.add('hidden'); }
  function paintHistory(items) {
    historyEl.replaceChildren();
    const filtered = items.filter((item) => !searchTerm || item.title.toLowerCase().includes(searchTerm));
    if (!filtered.length) {
      const empty = document.createElement('div'); empty.className = 'history-day'; empty.textContent = searchTerm ? 'NO MATCHING CHATS' : 'YOUR RECENT CHATS WILL APPEAR HERE'; historyEl.append(empty); return;
    }
    let previousDay = '';
    for (const item of filtered) {
      const day = new Date(item.updated * 1000).toLocaleDateString(undefined, { weekday:'long', month:'short', day:'numeric' });
      if (day !== previousDay) { const title = document.createElement('div'); title.className = 'history-day'; title.textContent = day.toUpperCase(); historyEl.append(title); previousDay = day; }
      const row = document.createElement('div'); row.className = `history-item${item.id === conversationId ? ' active' : ''}`;
      row.innerHTML = `<span class="history-icon">◷</span><span title="${esc(item.title)}">${esc(item.title || 'New conversation')}</span><button class="delete-chat" aria-label="Delete conversation" title="Delete conversation">×</button>`;
      row.addEventListener('click', (event) => { if (!event.target.closest('.delete-chat')) loadConversation(item.id); });
      row.querySelector('.delete-chat').addEventListener('click', (event) => { event.stopPropagation(); deleteConversation(item.id); });
      historyEl.append(row);
    }
  }
  async function refreshHistory() {
    try { paintHistory(await api('/api/conversations')); }
    catch { toast('Conversation history could not be loaded.'); }
  }
  async function loadConversation(id) {
    if (busy) return;
    try {
      const data = await api(`/api/conversations/${encodeURIComponent(id)}`);
      conversationId = data.id; turns = data.messages || []; messages.replaceChildren(); showChat();
      for (const turn of turns) messageNode(turn.role, turn.content, turn.security || null);
      paintHistory(await api('/api/conversations')); $('#sidebar').classList.remove('open');
    } catch (error) { toast(error.message || 'Could not open conversation.'); }
  }
  async function deleteConversation(id) {
    try { await api(`/api/conversations/${encodeURIComponent(id)}`, {method:'DELETE'}); if (id === conversationId) newConversation(); await refreshHistory(); toast('Conversation deleted.'); }
    catch (error) { toast(error.message); }
  }
  function newConversation() {
    if (busy) return;
    conversationId = null; turns = []; messages.replaceChildren(); showHome(); paintHistoryFromCache(); input.focus(); $('#sidebar').classList.remove('open');
  }
  let historyCache = [];
  function paintHistoryFromCache() { paintHistory(historyCache); }
  async function getHistory() { try { historyCache = await api('/api/conversations'); paintHistoryFromCache(); } catch { /* Server may still be starting. */ } }
  async function status() {
    try {
      const data = await api('/api/status');
      modelSelect.replaceChildren();
      for (const model of data.models) { const option = new Option(model, model); option.selected = model === data.model || model.replace(/:latest$/, '') === data.model; modelSelect.add(option); }
      if (!data.models.length) { const option = new Option('No local models found', ''); modelSelect.add(option); }
      const online = data.firewall && data.ollama; setConnection(online);
      if (!data.firewall) toast('Firewall disconnected. Messages stay local until it reconnects.');
      else if (!data.ollama) toast('Start Ollama and install a local model to begin chatting.');
      return online;
    } catch { setConnection(false); return false; }
  }
  async function sendMessage(text = input.value) {
    const content = text.trim();
    if (!content || busy || content.length > 16000) return;
    busy = true; input.value = ''; input.focus(); updateInput(); showChat();
    messageNode('user', content);
    const assistant = messageNode('assistant', '', null, true);
    let phaseLabel = assistant.querySelector('.typing-label');
    turns = turns.slice(-40);
    try {
      const response = await fetch('/api/chat', {
        method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/json'},
        body:JSON.stringify({message:content, conversation_id:conversationId, model:modelSelect.value || undefined})
      });
      if (!response.ok || !response.body) { const error = await response.json().catch(() => ({})); throw new Error(error.error || 'Could not connect to the chatbot.'); }
      const reader = response.body.getReader(), decoder = new TextDecoder(); let buffer = '', finished = false;
      while (!finished) {
        const {value, done} = await reader.read(); buffer += decoder.decode(value || new Uint8Array(), {stream:!done});
        const events = buffer.split('\n\n'); buffer = events.pop() || '';
        for (const rawEvent of events) {
          const lines = rawEvent.split('\n'); const event = lines.find((line) => line.startsWith('event: '))?.slice(7);
          const rawData = lines.filter((line) => line.startsWith('data: ')).map((line) => line.slice(6)).join('\n'); if (!event || !rawData) continue;
          const data = JSON.parse(rawData);
          if (event === 'phase') { if (phaseLabel) phaseLabel.textContent = data.label; }
          if (event === 'blocked') {
            finished = true;
            assistant.querySelector('.message-content').innerHTML = `<div class="message-meta"><b>Orbit</b><span>Just now</span><span class="badge" style="color:#f19a8d;background:#2a1d1d">⬡ MESSAGE BLOCKED</span></div><div class="message-body"><p>${esc(data.message)} Your text never reached the AI.</p></div><div class="security-card" style="color:#e49182"><span>⬡</span><span>BLOCKED BY FIREWALL · ${(data.firewall?.risk || 'HIGH').toUpperCase()} RISK</span></div>`;
            setConnection(true); toast('Your firewall blocked this message.'); scrollBottom();
          }
          if (event === 'done') {
            finished = true; conversationId = data.conversation_id;
            const replacement = messageNode('assistant', data.text, data.security);
            assistant.replaceWith(replacement);
            turns.push({role:'user',content}, {role:'assistant',content:data.text,security:data.security});
            historyCache = await api('/api/conversations'); paintHistoryFromCache(); setConnection(true);
          }
          if (event === 'error') { finished = true; throw new Error(data.message || 'The reply could not be completed.'); }
        }
        if (done) finished = true;
      }
      if (!conversationId && turns.length === 0 && assistant.isConnected) assistant.remove();
      scrollBottom();
    } catch (error) {
      if (assistant.isConnected) {
        assistant.querySelector('.typing')?.remove();
        const body = assistant.querySelector('.message-body'); if (body) body.innerHTML = `<p>${esc(error.message || 'The local model is unavailable. Check your connection and try again.')}</p>`;
        if (error.message.toLowerCase().includes('firewall')) setConnection(false);
      }
      toast(error.message || 'Something went wrong. Try again.');
    } finally { busy = false; updateInput(); input.focus(); }
  }
  $('#newChat').addEventListener('click', newConversation);
  input.addEventListener('input', updateInput);
  input.addEventListener('keydown', (event) => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); sendMessage(); } });
  sendButton.addEventListener('click', () => sendMessage());
  document.querySelectorAll('.suggestion').forEach((button) => button.addEventListener('click', () => sendMessage(button.dataset.prompt)));
  modelSelect.addEventListener('change', () => toast(`Using ${modelSelect.value} on this device.`));
  $('#themeToggle').addEventListener('click', () => { document.body.classList.toggle('light'); localStorage.setItem('orbit-theme', document.body.classList.contains('light') ? 'light' : 'dark'); });
  if (localStorage.getItem('orbit-theme') === 'light') document.body.classList.add('light');
  $('#searchToggle').addEventListener('click', () => { const wrap = $('#searchWrap'); wrap.classList.toggle('hidden'); if (!wrap.classList.contains('hidden')) $('#searchInput').focus(); else { searchTerm=''; $('#searchInput').value=''; paintHistoryFromCache(); } });
  $('#searchInput').addEventListener('input', (event) => { searchTerm = event.target.value.trim().toLowerCase(); paintHistoryFromCache(); });
  $('#searchInput').addEventListener('keydown', (event) => { if (event.key === 'Escape') { event.target.value=''; searchTerm=''; $('#searchWrap').classList.add('hidden'); paintHistoryFromCache(); } });
  $('#mobileMenu').addEventListener('click', () => $('#sidebar').classList.toggle('open'));
  document.addEventListener('keydown', (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); newConversation(); }
    if (event.key === 'Escape') $('#sidebar').classList.remove('open');
  });

  async function initialize() { await status(); await getHistory(); setInterval(status, 16000); setInterval(getHistory, 20000); }
  initialize();
})();
