(() => {
  const form = document.getElementById('chat-form');
  const input = document.getElementById('chat-message');
  const messages = document.getElementById('chat-messages');
  const status = document.getElementById('chat-status');
  const send = document.getElementById('chat-send');
  const clear = document.getElementById('clear-chat');
  const csrf = form.querySelector('[name=csrfmiddlewaretoken]').value;
  let conversationId = null;
  function append(label, text) {
    const item = document.createElement('div');
    item.className = 'mb-3';
    const heading = document.createElement('strong');
    heading.textContent = label;
    const body = document.createElement('div');
    body.style.whiteSpace = 'pre-wrap';
    body.textContent = text;
    item.append(heading, body);
    messages.append(item);
    messages.scrollTop = messages.scrollHeight;
    return item;
  }
  function busy(value) { send.disabled = clear.disabled = input.disabled = value; }
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const text = input.value.trim();
    if (!text || send.disabled) return;
    append('You', text);
    input.value = '';
    busy(true);
    status.textContent = 'Validating and generating...';
    try {
      const payload = {message: text};
      if (conversationId) payload.conversation_id = conversationId;
      const result = await fetch('/api/chat/', {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrf},
        body: JSON.stringify(payload)
      });
      const data = await result.json();
      if (data.conversation_id) conversationId = data.conversation_id;
      const item = append(data.success ? 'Assistant' : data.blocked ? 'Blocked by firewall' : 'Chat error',
        data.response || data.message || data.detail || 'The request could not be processed.');
      if (data.success && data.firewall) {
        status.textContent = data.firewall.output_action === 'SANITIZE' ? 'Response sanitized by firewall.'
          : data.firewall.input_action === 'SANITIZE' ? 'Prompt sanitized by firewall.'
          : data.firewall.input_action === 'WARN' ? 'Firewall warning: suspicious prompt.' : 'Validated by firewall.';
      } else status.textContent = 'Request finished.';
      if (data.security) {
        const details = document.createElement('details');
        const summary = document.createElement('summary');
        summary.textContent = 'Security information';
        const content = document.createElement('pre');
        content.textContent = JSON.stringify({firewall: data.firewall, model: data.model, ...data.security}, null, 2);
        details.append(summary, content);
        item.append(details);
      }
    } catch (_) {
      append('Chat error', 'Unable to reach the chat service. Please try again.');
      status.textContent = 'Connection error.';
    } finally { busy(false); input.focus(); }
  });
  clear.addEventListener('click', async () => {
    busy(true);
    try {
      if (conversationId) {
        const result = await fetch(`/api/chat/conversations/${encodeURIComponent(conversationId)}/`, {
          method: 'DELETE', credentials: 'same-origin', headers: {'X-CSRFToken': csrf}
        });
        if (!result.ok) throw new Error('clear failed');
      }
      conversationId = null;
      messages.replaceChildren();
      status.textContent = 'Conversation cleared.';
    } catch (_) { status.textContent = 'Unable to clear conversation. Please try again.'; }
    finally { busy(false); }
  });
})();
