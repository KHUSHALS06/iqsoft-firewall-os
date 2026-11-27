(function () {
  const canvas = document.getElementById('netCanvas');
  if (!canvas) return;

  const host = canvas.parentElement;
  const ctx = canvas.getContext('2d');
  const calm = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const touch = window.matchMedia('(pointer: coarse)').matches;

  const LINK = 130;        // max distance for a connecting line
  const REPEL = 150;       // mouse influence radius
  const PUSH = 1.4;        // repel strength
  const NODE_RGB = '10, 124, 245';

  let w = 0, h = 0, dpr = 1, nodes = [], raf = 0;
  const mouse = { x: -9999, y: -9999 };

  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    w = host.clientWidth;
    h = host.clientHeight;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    const count = Math.min(90, Math.round((w * h) / 9000));
    while (nodes.length < count) {
      const a = Math.random() * Math.PI * 2;
      const s = 0.15 + Math.random() * 0.25;
      nodes.push({
        x: Math.random() * w,
        y: Math.random() * h,
        bx: Math.cos(a) * s,
        by: Math.sin(a) * s,
        vx: 0,
        vy: 0,
        r: 1.6 + Math.random() * 1.6
      });
    }
    nodes.length = count;
    nodes.forEach((n) => {
      n.x = Math.min(n.x, w);
      n.y = Math.min(n.y, h);
    });
    if (calm) draw();
  }

  function step() {
    for (const n of nodes) {
      const dx = n.x - mouse.x;
      const dy = n.y - mouse.y;
      const d = Math.sqrt(dx * dx + dy * dy);

      if (d < REPEL && d > 0.01) {
        const f = Math.pow(1 - d / REPEL, 2) * PUSH;
        n.vx += (dx / d) * f;
        n.vy += (dy / d) * f;
      }

      // ease back toward the node's own drift velocity
      n.vx = n.vx * 0.95 + n.bx * 0.05;
      n.vy = n.vy * 0.95 + n.by * 0.05;

      n.x += n.vx;
      n.y += n.vy;

      if (n.x < 0) { n.x = 0; n.vx = Math.abs(n.vx); n.bx = Math.abs(n.bx); }
      else if (n.x > w) { n.x = w; n.vx = -Math.abs(n.vx); n.bx = -Math.abs(n.bx); }
      if (n.y < 0) { n.y = 0; n.vy = Math.abs(n.vy); n.by = Math.abs(n.by); }
      else if (n.y > h) { n.y = h; n.vy = -Math.abs(n.vy); n.by = -Math.abs(n.by); }
    }
  }

  function draw() {
    ctx.clearRect(0, 0, w, h);

    ctx.lineWidth = 1;
    for (let i = 0; i < nodes.length; i++) {
      const a = nodes[i];
      for (let j = i + 1; j < nodes.length; j++) {
        const b = nodes[j];
        const dx = a.x - b.x;
        const dy = a.y - b.y;
        const d2 = dx * dx + dy * dy;
        if (d2 < LINK * LINK) {
          const alpha = (1 - Math.sqrt(d2) / LINK) * 0.35;
          ctx.strokeStyle = 'rgba(' + NODE_RGB + ',' + alpha + ')';
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }
    }

    ctx.fillStyle = 'rgba(' + NODE_RGB + ', 0.55)';
    for (const n of nodes) {
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  function loop() {
    step();
    draw();
    raf = requestAnimationFrame(loop);
  }

  function start() {
    if (!raf && !calm) raf = requestAnimationFrame(loop);
  }

  function stop() {
    cancelAnimationFrame(raf);
    raf = 0;
  }

  resize();
  draw();
  if (calm) {
    if (window.ResizeObserver) new ResizeObserver(resize).observe(host);
    return;
  }

  if (!touch) {
    host.addEventListener('mousemove', (e) => {
      const r = host.getBoundingClientRect();
      mouse.x = e.clientX - r.left;
      mouse.y = e.clientY - r.top;
    });
    host.addEventListener('mouseleave', () => {
      mouse.x = mouse.y = -9999;
    });
  }

  if (window.ResizeObserver) {
    new ResizeObserver(resize).observe(host);
  } else {
    window.addEventListener('resize', resize);
  }

  document.addEventListener('visibilitychange', () => {
    document.hidden ? stop() : start();
  });

  start();
})();
