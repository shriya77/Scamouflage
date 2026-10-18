/* Optional live background: a slow constellation of "certificates" (dots) drifting behind the page.
 * When app.js reports a new catch, one dot turns red and sends out a ring.
 * Off by default; the choice is remembered. Pauses when the tab is hidden. With
 * prefers-reduced-motion it draws one still frame instead of animating.
 */
(function () {
  'use strict';
  const KEY = 'scamouflage-wallpaper';
  const canvas = document.getElementById('wallpaper');
  const toggle = document.getElementById('wallpaper-toggle');
  if (!canvas || !toggle) return;
  const ctx = canvas.getContext('2d');
  const reduce = matchMedia('(prefers-reduced-motion: reduce)');

  const LINK = 130;          // px: dots closer than this are joined by a faint line
  const FRAME_MS = 1000 / 30;
  let dots = [], rings = [], running = false, last = 0, raf = 0, w = 0, h = 0, dpr = 1;

  function resize() {
    dpr = Math.min(2, window.devicePixelRatio || 1);
    w = window.innerWidth; h = window.innerHeight;
    canvas.width = w * dpr; canvas.height = h * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const count = Math.round(Math.min(90, (w * h) / 16000));
    while (dots.length < count) dots.push(newDot());
    dots.length = count;
  }
  function newDot() {
    const speed = 0.06 + Math.random() * 0.1;          // px per frame: barely moving
    const angle = Math.random() * Math.PI * 2;
    return { x: Math.random() * w, y: Math.random() * h, vx: Math.cos(angle) * speed, vy: Math.sin(angle) * speed, hot: 0 };
  }

  function draw() {
    ctx.clearRect(0, 0, w, h);
    for (let i = 0; i < dots.length; i++) {
      const a = dots[i];
      for (let j = i + 1; j < dots.length; j++) {
        const b = dots[j];
        const dx = a.x - b.x, dy = a.y - b.y, d2 = dx * dx + dy * dy;
        if (d2 < LINK * LINK) {
          ctx.strokeStyle = `rgba(31, 74, 47, ${0.10 * (1 - Math.sqrt(d2) / LINK)})`;
          ctx.lineWidth = 1;
          ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
        }
      }
    }
    for (const d of dots) {
      ctx.fillStyle = d.hot > 0 ? `rgba(194, 65, 45, ${0.35 + 0.6 * d.hot})` : 'rgba(31, 74, 47, 0.28)';
      ctx.beginPath(); ctx.arc(d.x, d.y, d.hot > 0 ? 3 : 1.8, 0, Math.PI * 2); ctx.fill();
    }
    for (const r of rings) {
      ctx.strokeStyle = `rgba(194, 65, 45, ${0.5 * (1 - r.t)})`;
      ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.arc(r.x, r.y, 6 + r.t * 70, 0, Math.PI * 2); ctx.stroke();
    }
  }

  function step() {
    for (const d of dots) {
      d.x += d.vx; d.y += d.vy;
      if (d.x < -20) d.x = w + 20; else if (d.x > w + 20) d.x = -20;
      if (d.y < -20) d.y = h + 20; else if (d.y > h + 20) d.y = -20;
      if (d.hot > 0) d.hot = Math.max(0, d.hot - 0.006);
    }
    for (const r of rings) r.t += 0.02;
    rings = rings.filter((r) => r.t < 1);
  }

  function frame(now) {
    if (!running) return;
    raf = requestAnimationFrame(frame);
    if (now - last < FRAME_MS) return;
    last = now;
    step(); draw();
  }

  function start() {
    resize();
    if (reduce.matches) { draw(); return; }   // still picture, no motion
    if (running) return;
    running = true; last = 0; raf = requestAnimationFrame(frame);
  }
  function stop() { running = false; cancelAnimationFrame(raf); }

  function setOn(on) {
    document.body.classList.toggle('wallpaper-on', on);
    toggle.checked = on;
    try { localStorage.setItem(KEY, on ? 'on' : 'off'); } catch (_) {}
    if (on) start(); else { stop(); setTimeout(() => ctx.clearRect(0, 0, w, h), 600); }
  }

  /** Called by app.js when a new scam is caught. */
  function ping() {
    if (!document.body.classList.contains('wallpaper-on') || !dots.length) return;
    const d = dots[Math.floor(Math.random() * dots.length)];
    d.hot = 1;
    rings.push({ x: d.x, y: d.y, t: 0 });
    if (reduce.matches) draw();
  }

  toggle.addEventListener('change', () => setOn(toggle.checked));
  window.addEventListener('resize', () => { if (document.body.classList.contains('wallpaper-on')) { resize(); draw(); } });
  document.addEventListener('visibilitychange', () => {
    if (!document.body.classList.contains('wallpaper-on')) return;
    if (document.hidden) stop(); else start();
  });

  let saved = 'off';
  try { saved = localStorage.getItem(KEY) || 'off'; } catch (_) {}
  setOn(saved === 'on');

  window.ScamWallpaper = { ping };
})();
