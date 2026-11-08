/**
 * Phishing Site Detection - Content Script
 * Analyzes webpage parameters, input elements, form action handlers,
 * and DOM heuristics to detect credential harvesting and phishing attempts.
 */

(function () {
  'use strict';

  // Analyze parameters once DOM is ready
  function analyzeWebpageParameters() {
    const currentUrl = window.location.href;
    if (!currentUrl || currentUrl.startsWith('chrome') || currentUrl.startsWith('about:')) {
      return;
    }

    const suspiciousFindings = [];

    // 1. Check URL Query Parameters for deceptive phishing markers
    const searchParams = new URLSearchParams(window.location.search);
    const suspiciousKeys = ['cmd', 'account', 'verify', 'update', 'login', 'redirect', 'token', 'auth'];
    searchParams.forEach((val, key) => {
      if (suspiciousKeys.includes(key.toLowerCase())) {
        suspiciousFindings.push(`Suspicious query parameter detected: ${key}=${val.substring(0, 30)}`);
      }
    });

    // 2. Check Form Action Handlers and Password Inputs
    const forms = document.querySelectorAll('form');
    forms.forEach((form, index) => {
      const action = (form.getAttribute('action') || '').trim();
      const hasPassword = form.querySelector('input[type="password"]') !== null;

      // Insecure password transmission
      if (hasPassword && window.location.protocol === 'http:') {
        suspiciousFindings.push('Insecure password form over HTTP');
      }

      // Empty or about:blank form actions
      if (action === '' || action === 'about:blank') {
        suspiciousFindings.push(`Form ${index + 1} has empty or about:blank action handler`);
      }

      // Action pointing to raw IP address
      if (/https?:\/\/(?:[0-9]{1,3}\.){3}[0-9]{1,3}/i.test(action)) {
        suspiciousFindings.push(`Form ${index + 1} submits directly to raw IP address: ${action}`);
      }
    });

    // 3. Check for hidden or zero-size iframes often used for clickjacking
    const iframes = document.querySelectorAll('iframe');
    iframes.forEach((iframe) => {
      const w = iframe.offsetWidth || iframe.width;
      const h = iframe.offsetHeight || iframe.height;
      if ((w === 0 || h === 0) && iframe.src) {
        suspiciousFindings.push('Zero-pixel iframe redirection detected');
      }
    });

    // If suspicious parameters or behaviors are detected, report to background service worker
    if (suspiciousFindings.length > 0) {
      chrome.runtime.sendMessage({
        action: 'SUSPICIOUS_PAGE_PARAMETERS',
        url: currentUrl,
        findings: suspiciousFindings,
        html: document.documentElement.outerHTML.substring(0, 10000)
      });
    }
  }

  // Run on page load
  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    analyzeWebpageParameters();
  } else {
    document.addEventListener('DOMContentLoaded', analyzeWebpageParameters);
  }
})();

