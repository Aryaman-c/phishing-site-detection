// Parse query parameters passed by background worker
const params = new URLSearchParams(window.location.search);
const targetUrl = params.get('url') || 'Unknown URL';
const confidence = params.get('confidence') || '98.5';
const latency = params.get('latency') || '14.2';

document.getElementById('target-url').textContent = targetUrl;
document.getElementById('confidence-val').textContent = `${parseFloat(confidence).toFixed(1)}%`;
document.getElementById('latency-val').textContent = `${parseFloat(latency).toFixed(1)} ms`;

document.getElementById('btn-back').addEventListener('click', () => {
  if (window.history.length > 1) {
    window.history.back();
  } else {
    window.close();
  }
});

document.getElementById('btn-proceed').addEventListener('click', () => {
  if (confirm('Warning: This site is verified malicious. Are you certain you want to bypass protection?')) {
    window.location.href = targetUrl;
  }
});

