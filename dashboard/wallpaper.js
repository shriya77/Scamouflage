/* Background picker: plain, live video wallpapers, or the offline "constellation".
 *
 * Live videos come from lorem.media (free, no key, CORS-enabled), which serves
 * Pexels/Pixabay stock clips with author credits. We list a category, keep the
 * clips that match the theme, cache that list for a day, and play a random one.
 * The author is credited bottom-left. If the API can't be reached we fall back
 * to the constellation, which needs no network.
 *
 * Videos pause when the tab is hidden. With prefers-reduced-motion we show the
 * clip's still poster image instead of playing it.
 */
(function () {
  'use strict';
  const KEY = 'scamouflage-background';
  const API = 'https://lorem.media/v2/list/video';
  const CACHE_MS = 24 * 3600 * 1000;
  const THEMES = {
    forest:   { category: 'nature',   match: /forest|woodland|trees|moss|foggy|evergreen/ },
    city:     { category: 'urban',    match: /night|light-trails|timelapse|time-lapse/ },
    abstract: { category: 'abstract', match: /abstract|light|neon|swirl|geometric/ },
  };

  const select = document.getElementById('wallpaper-select');
  const canvas = document.getElementById('wallpaper');
  const video = document.getElementById('wallpaper-video');
  const credit = document.getElementById('wallpaper-credit');
  if (!select || !canvas || !video) return;
  const reduce = matchMedia('(prefers-reduced-motion: reduce)');
  let mode = 'off';

  // ---------------- Live video ----------------
  async function clipsFor(theme) {
    const cacheKey = `${KEY}-clips-${theme}`;
    try {
      const cached = JSON.parse(localStorage.getItem(cacheKey) || 'null');
      if (cached && Date.now() - cached.at < CACHE_MS && cached.clips.length) return cached.clips;
    } catch (_) {}
    const { category, match } = THEMES[theme];
    const res = await fetch(`${API}?category=${category}&aspect=16x9&limit=50`, { cache: 'no-store' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const clips = (data.items || [])
      .filter((i) => !i.has_audio && i.duration_ms >= 8000 && match.test(String(i.attribution?.source_url || '')))
      .map((i) => ({
        id: i.id,
        poster: i.poster_url,
        author: i.attribution?.author || 'Unknown',
        source: i.attribution?.source || 'stock',
        page: i.attribution?.source_url || 'https://lorem.media/',
      }));
    if (!clips.length) throw new Error('no clips for theme');
    try { localStorage.setItem(cacheKey, JSON.stringify({ at: Date.now(), clips })); } catch (_) {}
    return clips;
  }

  async function playTheme(theme) {
    const clips = await clipsFor(theme);
    if (mode !== theme) return;                       // user changed their mind while loading
    const clip = clips[Math.floor(Math.random() * clips.length)];
    showCredit(clip);
    if (reduce.matches) {                             // still image only
      video.removeAttribute('src');
      video.poster = clip.poster;
      video.load();
      document.body.classList.add('bg-video');
      return;
    }
    video.poster = clip.poster;
    video.src = `https://lorem.media/video/id/${encodeURIComponent(clip.id)}`;
    document.body.classList.add('bg-video');
    try { await video.play(); } catch (_) {}
  }

  function showCredit(clip) {
    const site = clip.source === 'pixabay' ? 'Pixabay' : clip.source === 'pexels' ? 'Pexels' : clip.source;
    credit.textContent = `Background: ${clip.author} on ${site}`;
    credit.href = clip.page;
    credit.hidden = false;
  }

  function stopVideo() {
    video.pause();
    video.removeAttribute('src');
    video.removeAttribute('poster');
    video.load();
    credit.hidden = true;
    document.body.classList.remove('bg-video');
  }

  // ---------------- Constellation (offline) ----------------
  const ctx = canvas.getContext('2d');
  const LINK = 130, FRAME_MS = 1000 / 30;
  let dots = [], rings = [], running = false, last = 0, raf = 0, w = 0, h = 0;

  function resize() {
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    w = window.innerWidth; h = window.innerHeight;
    canvas.width = w * dpr; canvas.height = h * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const count = Math.round(Math.min(90, (w * h) / 16000));
    while (dots.length < count) dots.push(newDot());
    dots.length = count;
  }
  function newDot() {
    const speed = 0.06 + Math.random() * 0.1, angle = Math.random() * Math.PI * 2;
    return { x: Math.random() * w, y: Math.random() * h, vx: Math.cos(angle) * speed, vy: Math.sin(angle) * speed, hot: 0 };
  }
  function draw() {
    ctx.clearRect(0, 0, w, h);
    for (let i = 0; i < dots.length; i++) {
      for (let j = i + 1; j < dots.length; j++) {
        const a = dots[i], b = dots[j], dx = a.x - b.x, dy = a.y - b.y, d2 = dx * dx + dy * dy;
        if (d2 < LINK * LINK) {
          ctx.strokeStyle = `rgba(31, 74, 47, ${0.12 * (1 - Math.sqrt(d2) / LINK)})`;
          ctx.lineWidth = 1;
          ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
        }
      }
    }
    for (const d of dots) {
      ctx.fillStyle = d.hot > 0 ? `rgba(194, 65, 45, ${0.35 + 0.6 * d.hot})` : 'rgba(31, 74, 47, 0.3)';
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
    last = now; step(); draw();
  }
  function startConstellation() {
    document.body.classList.add('bg-constellation');
    resize();
    if (reduce.matches) { draw(); return; }
    if (running) return;
    running = true; last = 0; raf = requestAnimationFrame(frame);
  }
  function stopConstellation() {
    running = false; cancelAnimationFrame(raf);
    document.body.classList.remove('bg-constellation');
  }

  // ---------------- Switching ----------------
  async function setMode(next) {
    mode = next;
    select.value = next;
    try { localStorage.setItem(KEY, next); } catch (_) {}
    stopVideo();
    stopConstellation();
    if (THEMES[next]) {
      try { await playTheme(next); }
      catch (err) {
        console.warn('[background] live video unavailable, using constellation:', err.message);
        if (mode === next) startConstellation();
      }
    } else if (next === 'constellation') {
      startConstellation();
    }
  }

  /** Called by app.js when a new scam is caught (constellation only). */
  function ping() {
    if (!running && !(reduce.matches && document.body.classList.contains('bg-constellation'))) return;
    if (!dots.length) return;
    const d = dots[Math.floor(Math.random() * dots.length)];
    d.hot = 1; rings.push({ x: d.x, y: d.y, t: 0 });
    if (!running) draw();
  }

  select.addEventListener('change', () => setMode(select.value));
  window.addEventListener('resize', () => { if (document.body.classList.contains('bg-constellation')) { resize(); draw(); } });
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      video.pause();
      if (running) { running = false; cancelAnimationFrame(raf); }
    } else if (THEMES[mode] && video.src && !reduce.matches) {
      video.play().catch(() => {});
    } else if (mode === 'constellation' && !reduce.matches) {
      running = true; last = 0; raf = requestAnimationFrame(frame);
    }
  });

  let saved = 'off';
  try { saved = localStorage.getItem(KEY) || 'off'; } catch (_) {}
  setMode(Object.prototype.hasOwnProperty.call(THEMES, saved) || saved === 'constellation' ? saved : 'off');

  window.ScamWallpaper = { ping };
})();
