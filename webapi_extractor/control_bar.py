"""Small in-page controls used to finish or pause interactive sessions."""

CONTROL_BAR_JS = r"""
(() => {
  if (window.__web_api_extractor_bar) return;
  const root = document.createElement('div');
  const shadow = root.attachShadow({mode: 'closed'});
  root.style.cssText = 'position:fixed;right:16px;bottom:16px;z-index:2147483647;font:14px sans-serif';
  shadow.innerHTML = `<style>
    .bar{background:#16202a;color:#fff;padding:10px 12px;border-radius:8px;box-shadow:0 4px 18px #0006;display:flex;gap:8px;align-items:center}
    button{border:0;border-radius:5px;padding:6px 9px;cursor:pointer;background:#43a047;color:#fff}
    button.secondary{background:#546e7a}
  </style><div class="bar"><span id="label"></span><button id="primary"></button><button id="secondary" class="secondary"></button></div>`;
  document.documentElement.appendChild(root);
  const label = shadow.querySelector('#label');
  const primary = shadow.querySelector('#primary');
  const secondary = shadow.querySelector('#secondary');
  function send(action) { window.__mcp_control && window.__mcp_control(action); }
  window.__mcp_set_mode = mode => {
    root.dataset.mode = mode;
    if (mode === 'login') { label.textContent = '请完成登录'; primary.textContent = '登录完成'; secondary.hidden = true; primary.onclick = () => send('login_complete'); }
    else { label.textContent = '正在收集'; primary.textContent = '完成收集'; secondary.hidden = false; secondary.textContent = '暂停'; primary.onclick = () => send('stop'); secondary.onclick = () => send('pause'); }
  };
  window.__mcp_set_state = state => {
    if (root.dataset.mode !== 'login') {
      secondary.textContent = state === 'paused' ? '继续' : '暂停';
      secondary.onclick = () => send(state === 'paused' ? 'resume' : 'pause');
    }
    if (state === 'stopping') { primary.disabled = true; secondary.disabled = true; label.textContent = '正在保存'; }
  };
  window.__mcp_update_count = count => { if (root.dataset.mode !== 'login') label.textContent = `正在收集 · ${count} 个接口`; };
  window.__web_api_extractor_bar = root;
  window.__mcp_set_mode('capture');
})();
"""


LOGIN_CONTROL_BAR_JS = CONTROL_BAR_JS.replace("window.__mcp_set_mode('capture');", "window.__mcp_set_mode('login');")