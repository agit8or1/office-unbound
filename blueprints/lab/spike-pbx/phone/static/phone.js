'use strict';
(function () {
  var $ = function (id) { return document.getElementById(id); };
  var ua = null, session = null, cfg = null;
  function log(m) { var l = $('log'); l.textContent += new Date().toISOString().slice(11, 19) + ' ' + m + '\n'; l.scrollTop = l.scrollHeight; }
  function setStatus(s, t) { var e = $('status'); e.dataset.state = s; e.textContent = t || s; }
  function setCall(s, peer) { var e = $('callstate'); e.dataset.state = s; e.textContent = s; $('peer').textContent = peer || ''; }
  function ui() {
    var inCall = !!session && !session.isEnded();
    $('hangup').disabled = !inCall;
    $('call').disabled = !(ua && ua.isRegistered()) || inCall;
    $('answer').hidden = !(session && session.direction === 'incoming' && !session.isEstablished() && !session.isEnded());
  }
  function attach(s) {
    session = s;
    var peer = s.remote_identity ? (s.remote_identity.display_name || '') + ' ' + s.remote_identity.uri.user : '';
    setCall(s.direction === 'incoming' ? 'ringing-in' : 'calling', peer);
    s.on('progress', function () { setCall(s.direction === 'incoming' ? 'ringing-in' : 'ringing', peer); ui(); });
    s.on('accepted', function () { setCall('connected', peer); ui(); });
    s.on('confirmed', function () { setCall('connected', peer); ui(); });
    s.on('ended', function () { setCall('ended', peer); session = null; ui(); });
    s.on('failed', function (e) { setCall('failed', (e && e.cause) || ''); log('call failed: ' + (e && e.cause)); session = null; ui(); });
    s.on('peerconnection', function (e) {
      e.peerconnection.addEventListener('track', function (ev) { $('remote').srcObject = ev.streams[0] || new MediaStream([ev.track]); });
    });
    s.connection && s.connection.addEventListener('track', function (ev) { $('remote').srcObject = ev.streams[0] || new MediaStream([ev.track]); });
    ui();
  }
  function start(c) {
    cfg = c;
    $('ext').textContent = c.extension;
    var sock = new JsSIP.WebSocketInterface(c.wss);
    ua = new JsSIP.UA({ sockets: [sock], uri: 'sip:' + c.username + '@' + c.domain, authorization_user: c.username, password: c.password,
                        display_name: c.display_name, register: true, register_expires: 600, session_timers: false });
    c.password = null; // keep the secret only inside the UA
    ua.on('connected', function () { setStatus('connected', 'connected (not yet registered)'); });
    ua.on('disconnected', function () { setStatus('offline', 'offline'); ui(); });
    ua.on('registered', function () { setStatus('registered', 'registered'); ui(); });
    ua.on('unregistered', function () { setStatus('unregistered', 'unregistered'); ui(); });
    ua.on('registrationFailed', function (e) { setStatus('reg-failed', 'registration refused (' + (e.cause || '?') + ')'); log('registrationFailed ' + (e.response ? e.response.status_code : '')); ui(); });
    ua.on('newRTCSession', function (e) { if (e.originator === 'remote') { if (session) { e.session.terminate({ status_code: 486 }); return; } } attach(e.session); });
    ua.start();
  }
  function api(path, opts) { return fetch(path, Object.assign({ credentials: 'same-origin' }, opts)).then(function (r) { if (r.status === 401) { location.href = '/login'; throw new Error('login'); } if (!r.ok) throw new Error(path + ' ' + r.status); return r.json(); }); }
  api('/api/me').then(function (me) {
    $('who').textContent = me.user;
    if (!me.extension) { setStatus('no-extension', 'your account has no extension'); return; }
    return api('/api/credential', { method: 'POST', headers: { 'X-OU-CSRF': me.csrf } }).then(start);
  }).catch(function (e) { setStatus('error', 'error: ' + e.message); });
  $('dialform').addEventListener('submit', function (ev) {
    ev.preventDefault();
    var n = $('number').value.replace(/[^0-9*#]/g, '');
    if (!n || !ua) return;
    ua.call('sip:' + n + '@' + cfg.domain, { mediaConstraints: { audio: true, video: false }, pcConfig: { iceServers: [] } });
  });
  $('answer').addEventListener('click', function () { if (session) session.answer({ mediaConstraints: { audio: true, video: false }, pcConfig: { iceServers: [] } }); });
  $('hangup').addEventListener('click', function () { if (session) session.terminate(); });
  window.addEventListener('beforeunload', function () { if (ua) ua.stop(); });
})();
