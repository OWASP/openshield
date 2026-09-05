/**
 * Interactive 3D map of an Azure subscription: a central core connects one
 * hub per domain, each hub fans out to its rule nodes, and a scan pulse
 * sweeps the estate. Drag to rotate, click a node to focus a rule.
 */
import * as THREE from 'three';

interface OrbRule {
  id: string;
  name: string;
  severity: string;
  domain: string;
}
interface OrbData {
  /** [id, severity, name] triples, see orbRules in repoData */
  rules: [string, string, string][];
  domains: string[];
}

function domainOf(ruleId: string): string {
  const parts = ruleId.split('-');
  return (parts[1] || '').toLowerCase();
}

export function initOrb(): void {
  const canvas = document.getElementById('heroCanvas') as HTMLCanvasElement | null;
  const fallback = document.getElementById('heroFallback') as HTMLElement | null;
  const info = document.getElementById('ruleInfo');
  const legend = document.getElementById('heroLegend');
  const dataEl = document.getElementById('orb-data');
  if (!canvas || !info || !legend || !dataEl) return;

  let data: OrbData;
  try {
    data = JSON.parse(dataEl.textContent || '{}') as OrbData;
  } catch {
    return;
  }
  const RULES: OrbRule[] = (data.rules || []).map(([id, severity, name]) => ({
    id,
    severity,
    name,
    domain: domainOf(id),
  }));
  const DOMAINS = data.domains || [];
  if (!RULES.length || !DOMAINS.length) return;

  const reduce = !!window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  let renderer: THREE.WebGLRenderer;
  try {
    renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
  } catch {
    canvas.style.display = 'none';
    if (fallback) fallback.style.display = 'flex';
    return;
  }
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(42, 1, 0.1, 100);
  camera.position.set(0, 0, 4.9);
  const group = new THREE.Group();
  scene.add(group);

  const domIndex: Record<string, number> = {};
  DOMAINS.forEach((d, i) => {
    domIndex[d] = i;
  });
  const counts: Record<string, number> = {};
  RULES.forEach((r) => {
    const d = domainOf(r.id);
    counts[d] = (counts[d] || 0) + 1;
  });
  const domHue = (i: number) => (i * 137.508) % 360;
  const domColor = (i: number) => {
    const c = new THREE.Color();
    c.setHSL(domHue(i) / 360, 0.5, 0.62);
    return c;
  };

  legend.replaceChildren(
    ...DOMAINS.map((d, i) => {
      const span = document.createElement('span');
      span.className = 'lg';
      const dot = document.createElement('i');
      dot.style.background = `hsl(${Math.round(domHue(i))},50%,62%)`;
      span.appendChild(dot);
      span.appendChild(document.createTextNode(`${d.toUpperCase()} ${counts[d] || 0}`));
      return span;
    }),
  );

  const N = RULES.length;
  const D = DOMAINS.length;
  const R = 1.5;
  const golden = Math.PI * (3 - Math.sqrt(5));
  const centroids: number[][] = [];
  for (let d = 0; d < D; d++) {
    const cy = 1 - (d / (D - 1)) * 2;
    const cr = Math.sqrt(Math.max(0, 1 - cy * cy));
    centroids.push([Math.cos(golden * d) * cr, cy, Math.sin(golden * d) * cr]);
  }
  let seed = 7;
  const rnd = () => {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    return seed / 4294967296;
  };

  const positions = new Float32Array(N * 3);
  const colorsArr = new Float32Array(N * 3);
  const nodeDom = new Array<number>(N);
  RULES.forEach((r, i) => {
    const di = domIndex[domainOf(r.id)] ?? 0;
    nodeDom[i] = di;
    const c = centroids[di];
    const spread = 0.2 + (counts[DOMAINS[di]] || 1) * 0.006;
    const x = c[0] + (rnd() * 2 - 1) * spread;
    const y = c[1] + (rnd() * 2 - 1) * spread;
    const z = c[2] + (rnd() * 2 - 1) * spread;
    const len = Math.sqrt(x * x + y * y + z * z);
    positions[i * 3] = (x / len) * R;
    positions[i * 3 + 1] = (y / len) * R;
    positions[i * 3 + 2] = (z / len) * R;
    const col = domColor(di);
    colorsArr[i * 3] = col.r;
    colorsArr[i * 3 + 1] = col.g;
    colorsArr[i * 3 + 2] = col.b;
  });

  const nodeGeo = new THREE.BufferGeometry();
  nodeGeo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
  nodeGeo.setAttribute('color', new THREE.BufferAttribute(colorsArr, 3));
  const ptsMat = new THREE.PointsMaterial({
    size: 0.055,
    vertexColors: true,
    transparent: true,
    opacity: 0.95,
    sizeAttenuation: true,
  });
  const points = new THREE.Points(nodeGeo, ptsMat);
  group.add(points);

  // constellation lines within each domain cluster
  const seg: number[] = [];
  for (let a = 0; a < N; a++) {
    for (let b = a + 1; b < N; b++) {
      if (nodeDom[a] !== nodeDom[b]) continue;
      const dx = positions[a * 3] - positions[b * 3];
      const dy = positions[a * 3 + 1] - positions[b * 3 + 1];
      const dz = positions[a * 3 + 2] - positions[b * 3 + 2];
      if (Math.sqrt(dx * dx + dy * dy + dz * dz) < 0.5) {
        seg.push(
          positions[a * 3], positions[a * 3 + 1], positions[a * 3 + 2],
          positions[b * 3], positions[b * 3 + 1], positions[b * 3 + 2],
        );
      }
    }
  }
  const lineGeo = new THREE.BufferGeometry();
  lineGeo.setAttribute('position', new THREE.BufferAttribute(new Float32Array(seg), 3));
  const lineMat = new THREE.LineBasicMaterial({ color: new THREE.Color('#a7a7b0'), transparent: true, opacity: 0.10 });
  group.add(new THREE.LineSegments(lineGeo, lineMat));

  const PAPER = new THREE.Color('#f2f0ec');
  const wireMat = new THREE.MeshBasicMaterial({ color: PAPER, wireframe: true, transparent: true, opacity: 0.16 });
  const core = new THREE.Mesh(new THREE.IcosahedronGeometry(0.74, 1), wireMat);
  group.add(core);
  const ringMatA = new THREE.MeshBasicMaterial({ color: new THREE.Color('#ff5a33'), transparent: true, opacity: 0.45, side: THREE.DoubleSide });
  const ringA = new THREE.Mesh(new THREE.TorusGeometry(1.8, 0.006, 8, 140), ringMatA);
  ringA.rotation.x = Math.PI / 2.25;
  group.add(ringA);
  const ringMatB = new THREE.MeshBasicMaterial({ color: new THREE.Color('#a7a7b0'), transparent: true, opacity: 0.2, side: THREE.DoubleSide });
  const ringB = new THREE.Mesh(new THREE.TorusGeometry(1.98, 0.005, 8, 140), ringMatB);
  ringB.rotation.x = Math.PI / 1.7;
  ringB.rotation.y = 0.5;
  group.add(ringB);

  // core -> hub -> nodes wiring
  const byDom: number[][] = [];
  for (let i = 0; i < D; i++) byDom.push([]);
  for (let i = 0; i < N; i++) byDom[nodeDom[i]].push(i);
  const hubSeg: number[] = [];
  const nodeSeg: number[] = [];
  for (let h = 0; h < D; h++) {
    const hc = centroids[h];
    const hx = hc[0] * R, hy = hc[1] * R, hz = hc[2] * R;
    hubSeg.push(0, 0, 0, hx, hy, hz);
    for (const ni of byDom[h]) {
      nodeSeg.push(hx, hy, hz, positions[ni * 3], positions[ni * 3 + 1], positions[ni * 3 + 2]);
    }
    const hubMesh = new THREE.Mesh(
      new THREE.OctahedronGeometry(0.055),
      new THREE.MeshBasicMaterial({ color: domColor(h), wireframe: true, transparent: true, opacity: 0.95 }),
    );
    hubMesh.position.set(hx, hy, hz);
    group.add(hubMesh);
  }
  const hubGeo = new THREE.BufferGeometry();
  hubGeo.setAttribute('position', new THREE.BufferAttribute(new Float32Array(hubSeg), 3));
  group.add(new THREE.LineSegments(hubGeo, new THREE.LineBasicMaterial({ color: PAPER, transparent: true, opacity: 0.14 })));
  const nodeSegGeo = new THREE.BufferGeometry();
  nodeSegGeo.setAttribute('position', new THREE.BufferAttribute(new Float32Array(nodeSeg), 3));
  group.add(new THREE.LineSegments(nodeSegGeo, new THREE.LineBasicMaterial({ color: PAPER, transparent: true, opacity: 0.07 })));

  // one bridge per neighboring domain pair: a single connected map
  const bridge: number[] = [];
  for (let b = 0; b < D - 1; b++) {
    const bA = byDom[b];
    const bB = byDom[b + 1];
    let bestD = Infinity, bI = -1, bJ = -1;
    for (const ia of bA) {
      for (const jb of bB) {
        const dx = positions[ia * 3] - positions[jb * 3];
        const dy = positions[ia * 3 + 1] - positions[jb * 3 + 1];
        const dz = positions[ia * 3 + 2] - positions[jb * 3 + 2];
        const dd = dx * dx + dy * dy + dz * dz;
        if (dd < bestD) { bestD = dd; bI = ia; bJ = jb; }
      }
    }
    if (bI >= 0) {
      bridge.push(
        positions[bI * 3], positions[bI * 3 + 1], positions[bI * 3 + 2],
        positions[bJ * 3], positions[bJ * 3 + 1], positions[bJ * 3 + 2],
      );
    }
  }
  const bridgeGeo = new THREE.BufferGeometry();
  bridgeGeo.setAttribute('position', new THREE.BufferAttribute(new Float32Array(bridge), 3));
  group.add(new THREE.LineSegments(bridgeGeo, new THREE.LineBasicMaterial({ color: PAPER, transparent: true, opacity: 0.32 })));

  // scan pulse
  const pulseMat = new THREE.MeshBasicMaterial({ color: 0xff5a33, wireframe: true, transparent: true, opacity: 0 });
  const pulse = new THREE.Mesh(new THREE.SphereGeometry(1, 20, 14), pulseMat);
  group.add(pulse);

  const marker = new THREE.Mesh(
    new THREE.SphereGeometry(0.105, 16, 16),
    new THREE.MeshBasicMaterial({ color: 0xff5a33, wireframe: true, transparent: true, opacity: 0.9 }),
  );
  marker.visible = false;
  group.add(marker);

  let focus = -1;
  const sevCol: Record<string, string> = { HIGH: '#ff5a33', MEDIUM: '#e0b356', LOW: '#a7a7b0' };
  const setFocus = (i: number) => {
    focus = i;
    const r = RULES[i];
    marker.position.set(positions[i * 3], positions[i * 3 + 1], positions[i * 3 + 2]);
    (marker.material as THREE.MeshBasicMaterial).color.set(sevCol[r.severity] || '#f2f0ec');
    marker.visible = true;
    const idEl = document.createElement('b');
    idEl.textContent = r.id;
    const sevEl = document.createElement('em');
    sevEl.style.color = sevCol[r.severity] || '#a7a7b0';
    sevEl.textContent = r.severity;
    info.replaceChildren(idEl, document.createTextNode(` / ${r.name} / `), sevEl);
  };

  const ray = new THREE.Raycaster();
  ray.params.Points = { threshold: 0.14 };
  const ndc = new THREE.Vector2();
  const pick = (e: PointerEvent) => {
    const rect = canvas.getBoundingClientRect();
    ndc.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
    ndc.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
    ray.setFromCamera(ndc, camera);
    const hits = ray.intersectObject(points);
    return hits.length && hits[0].index !== undefined ? hits[0].index : -1;
  };

  let ry = 0.6, rx = 0.3, tRy = 0.6, tRx = 0.3;
  let dragging = false, lastX = 0, lastY = 0, downX = 0, downY = 0, hoverX = 0, hoverY = 0;
  const clamp1 = (v: number) => Math.max(-1, Math.min(1, v));

  canvas.addEventListener('pointerdown', (e) => {
    dragging = true;
    lastX = downX = e.clientX;
    lastY = downY = e.clientY;
    try { canvas.setPointerCapture(e.pointerId); } catch { /* ignore */ }
    e.preventDefault();
  });
  window.addEventListener('pointermove', (e) => {
    if (dragging) {
      tRy += (e.clientX - lastX) * 0.006;
      tRx = Math.max(-1.2, Math.min(1.2, tRx + (e.clientY - lastY) * 0.004));
      lastX = e.clientX;
      lastY = e.clientY;
    } else {
      const rect = canvas.getBoundingClientRect();
      if (e.clientX >= rect.left && e.clientX <= rect.right && e.clientY >= rect.top && e.clientY <= rect.bottom) {
        hoverY = clamp1((e.clientX - (rect.left + rect.width / 2)) / rect.width);
        hoverX = clamp1((e.clientY - (rect.top + rect.height / 2)) / rect.height);
        canvas.style.cursor = pick(e) >= 0 ? 'pointer' : 'grab';
      }
    }
  });
  window.addEventListener('pointerup', (e) => {
    if (!dragging) return;
    dragging = false;
    if (Math.hypot(e.clientX - downX, e.clientY - downY) < 6) {
      const i = pick(e);
      setFocus(i >= 0 ? i : (focus + 1) % N);
    }
  });

  const resize = () => {
    const w = canvas.clientWidth || canvas.parentElement?.clientWidth || 600;
    const h = canvas.clientHeight || 440;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
    const half = Math.tan((camera.fov * Math.PI) / 360);
    camera.position.z = (2.06 / half) / Math.min(1, camera.aspect) * 1.02;
  };
  window.addEventListener('resize', resize);
  resize();

  const start = performance.now();
  const frame = (now: number) => {
    requestAnimationFrame(frame);
    const t = now - start;
    if (focus >= 0 && !dragging) {
      const px = positions[focus * 3], py = positions[focus * 3 + 1], pz = positions[focus * 3 + 2];
      const ty = Math.atan2(-px, pz);
      const tx = Math.atan2(py, Math.hypot(px, pz));
      let dY = ty - tRy;
      dY = Math.atan2(Math.sin(dY), Math.cos(dY));
      tRy += dY * 0.09;
      tRx += (tx - tRx) * 0.09;
    } else if (!dragging && !reduce) {
      tRy += 0.0024;
    }
    ry += (tRy - ry) * 0.12;
    rx += (tRx - rx) * 0.12;
    group.rotation.set(rx + (reduce ? 0 : hoverX * 0.08), ry + (reduce ? 0 : hoverY * 0.1), 0);
    if (marker.visible) marker.scale.setScalar(1 + Math.sin(t * 0.005) * 0.14);
    const period = 4200;
    const pp = (t % period) / period;
    pulse.scale.setScalar(0.78 + pp * 1.4);
    pulseMat.opacity = reduce ? 0 : 0.20 * (1 - pp);
    if (!reduce) {
      ringA.rotation.z += 0.0006;
      ringB.rotation.z -= 0.0004;
      core.scale.setScalar(1 + 0.025 * Math.sin(t * 0.0024));
    }
    group.position.y = reduce ? 0 : Math.sin(t * 0.00055) * 0.07;
    renderer.render(scene, camera);
  };
  requestAnimationFrame(frame);
}
