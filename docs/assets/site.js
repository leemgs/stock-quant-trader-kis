/*
 * site.js — 정적 사이트 간단 접속 코드 게이트
 *
 * ⚠️ 주의: 이것은 "초대받은 사용자용 정보 공간"을 위한 간단한 접근 제한일 뿐이며,
 * 민감정보 보호 목적이 아닙니다. 접속 코드의 SHA-256 해시가 클라이언트(브라우저)에
 * 노출되므로(config/access.json) 진짜 보안 경계로 사용하지 마세요.
 *
 * 동작:
 *   - initAuth(): 세션에 접근 허용 기록이 없으면 전체 화면 잠금 오버레이를 띄운다.
 *   - unlock():   입력한 코드를 브라우저에서 SHA-256으로 해시한 뒤 access.json의
 *                 digest 목록과 비교하여, 일치하면 sessionStorage에 허용 상태를 기록하고
 *                 오버레이를 제거한다.
 */
(function () {
  "use strict";

  var CONFIG_URL = "config/access.json";
  var SS_KEY = "site_access_granted"; // sessionStorage 키 (값 = 허용된 config version)
  var accessConfig = null;

  // ── 유틸: 입력 문자열의 SHA-256 16진 해시 ───────────────────────────────
  async function sha256Hex(text) {
    if (!(window.crypto && window.crypto.subtle)) {
      throw new Error("이 브라우저/환경에서는 SHA-256(Web Crypto)을 사용할 수 없습니다. HTTPS에서 접속하세요.");
    }
    var data = new TextEncoder().encode(text);
    var buf = await window.crypto.subtle.digest("SHA-256", data);
    var bytes = new Uint8Array(buf);
    var hex = "";
    for (var i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, "0");
    }
    return hex;
  }

  function getConfigVersion() {
    return accessConfig && accessConfig.version != null ? String(accessConfig.version) : "1";
  }

  // 현재 세션이 '유효한 버전으로' 허용된 상태인지 확인
  function isGranted() {
    try {
      return sessionStorage.getItem(SS_KEY) === getConfigVersion();
    } catch (e) {
      return false; // 프라이빗 모드 등 sessionStorage 접근 불가 시 잠금 유지
    }
  }

  function grant() {
    try {
      sessionStorage.setItem(SS_KEY, getConfigVersion());
    } catch (e) {
      /* sessionStorage 불가 시에도 이번 페이지는 오버레이 제거로 열람 허용 */
    }
  }

  // ── 잠금 오버레이 생성/표시 ─────────────────────────────────────────────
  function buildOverlay() {
    if (document.getElementById("site-auth-overlay")) return;

    var overlay = document.createElement("div");
    overlay.id = "site-auth-overlay";
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.innerHTML =
      '<div class="auth-card">' +
      '  <div class="auth-logo">🔒</div>' +
      '  <h2 class="auth-title">접속 코드 입력</h2>' +
      '  <p class="auth-desc">이 사이트는 초대받은 사용자를 위한 정보 공간입니다.<br>접속 코드를 입력해 주세요.</p>' +
      '  <input id="site-auth-input" class="auth-input" type="password" inputmode="text" autocomplete="off" placeholder="접속 코드" aria-label="접속 코드" />' +
      '  <button id="site-auth-btn" class="auth-btn" type="button">입장하기</button>' +
      '  <p id="site-auth-error" class="auth-error" role="alert"></p>' +
      '  <p class="auth-foot">⚠️ 간단한 접근 제한이며 보안 경계가 아닙니다.</p>' +
      "</div>";

    var style = document.createElement("style");
    style.id = "site-auth-style";
    style.textContent =
      "#site-auth-overlay{position:fixed;inset:0;z-index:2147483647;display:flex;align-items:center;justify-content:center;" +
      "background:linear-gradient(135deg,#0a0a0f 0%,#03256C 100%);padding:16px;" +
      "font-family:'Inter',system-ui,-apple-system,'Apple SD Gothic Neo','Malgun Gothic',sans-serif;}" +
      "#site-auth-overlay .auth-card{background:#fff;border-radius:16px;padding:32px 28px;max-width:360px;width:100%;" +
      "box-shadow:0 20px 60px rgba(0,0,0,.4);text-align:center;}" +
      "#site-auth-overlay .auth-logo{font-size:40px;margin-bottom:8px;}" +
      "#site-auth-overlay .auth-title{margin:0 0 8px;font-size:20px;font-weight:800;color:#03256C;}" +
      "#site-auth-overlay .auth-desc{margin:0 0 18px;font-size:13px;color:#666;line-height:1.6;}" +
      "#site-auth-overlay .auth-input{width:100%;box-sizing:border-box;padding:12px 14px;font-size:15px;" +
      "border:1px solid #ccc;border-radius:8px;margin-bottom:12px;outline:none;}" +
      "#site-auth-overlay .auth-input:focus{border-color:#03256C;box-shadow:0 0 0 3px rgba(3,37,108,.12);}" +
      "#site-auth-overlay .auth-btn{width:100%;padding:12px;font-size:15px;font-weight:700;color:#fff;background:#03256C;" +
      "border:none;border-radius:8px;cursor:pointer;transition:opacity .15s;}" +
      "#site-auth-overlay .auth-btn:hover{opacity:.9;}" +
      "#site-auth-overlay .auth-btn:disabled{opacity:.6;cursor:default;}" +
      "#site-auth-overlay .auth-error{min-height:18px;margin:10px 0 0;font-size:13px;color:#e53935;font-weight:600;}" +
      "#site-auth-overlay .auth-foot{margin:16px 0 0;font-size:11px;color:#aaa;}";

    document.head.appendChild(style);
    document.body.appendChild(overlay);
    try { document.body.style.overflow = "hidden"; } catch (e) {}

    var input = document.getElementById("site-auth-input");
    var btn = document.getElementById("site-auth-btn");
    btn.addEventListener("click", unlock);
    input.addEventListener("keydown", function (ev) {
      if (ev.key === "Enter") { ev.preventDefault(); unlock(); }
    });
    setTimeout(function () { try { input.focus(); } catch (e) {} }, 50);
  }

  function removeOverlay() {
    var o = document.getElementById("site-auth-overlay");
    if (o && o.parentNode) o.parentNode.removeChild(o);
    var s = document.getElementById("site-auth-style");
    if (s && s.parentNode) s.parentNode.removeChild(s);
    try { document.body.style.overflow = ""; } catch (e) {}
  }

  function showError(msg) {
    var el = document.getElementById("site-auth-error");
    if (el) el.textContent = msg || "";
  }

  // ── 입력 코드 검증 (전역 노출: unlock) ──────────────────────────────────
  async function unlock() {
    var input = document.getElementById("site-auth-input");
    var btn = document.getElementById("site-auth-btn");
    if (!input) return;
    var code = (input.value || "").trim();
    if (!code) { showError("접속 코드를 입력하세요."); return; }

    if (btn) btn.disabled = true;
    showError("");

    try {
      // 설정이 아직 로드되지 않았으면 지금 로드
      if (!accessConfig) { accessConfig = await loadConfig(); }
      var digests = (accessConfig && accessConfig.digests) || [];
      var hex = await sha256Hex(code);
      if (digests.indexOf(hex) !== -1) {
        grant();
        removeOverlay();
      } else {
        showError("접속 코드가 올바르지 않습니다.");
        input.value = "";
        input.focus();
      }
    } catch (e) {
      showError(e && e.message ? e.message : "확인 중 오류가 발생했습니다.");
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  function loadConfig() {
    return fetch(CONFIG_URL, { cache: "no-store" })
      .then(function (res) {
        if (!res.ok) throw new Error("접속 설정을 불러오지 못했습니다 (HTTP " + res.status + ").");
        return res.json();
      })
      .then(function (json) { accessConfig = json; return json; });
  }

  // ── 초기화 (전역 노출: initAuth) ────────────────────────────────────────
  function initAuth() {
    loadConfig()
      .then(function () {
        if (!isGranted()) buildOverlay();
      })
      .catch(function (e) {
        // 설정 로드 실패 시에도 잠금을 유지하여 무단 열람을 막는다.
        buildOverlay();
        showError(e && e.message ? e.message : "접속 설정을 불러오지 못했습니다.");
      });
  }

  // 전역 노출
  window.initAuth = initAuth;
  window.unlock = unlock;

  // DOM 준비 시 자동 실행
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initAuth);
  } else {
    initAuth();
  }
})();
