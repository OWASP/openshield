/**
 * Immersive layer for the homepage: metric count-up, terminal type-in and
 * the hero glow parallax. Every effect is guarded for reduced motion and
 * missing elements so the script is safe to load on any page.
 */
const reduce = !!window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

function animateNum(el: HTMLElement): void {
  const target = parseInt(el.textContent ?? '', 10);
  if (Number.isNaN(target)) return;
  let node: ChildNode | null = el.firstChild;
  if (!(node && node.nodeType === Node.TEXT_NODE)) {
    node = document.createTextNode(el.textContent ?? '');
    el.insertBefore(node, el.firstChild);
  }
  const textNode = node as Text;
  let t0: number | null = null;
  const dur = 900;
  const tick = (now: number) => {
    if (t0 === null) t0 = now;
    const p = Math.min(1, (now - t0) / dur);
    const eased = 1 - Math.pow(1 - p, 3);
    textNode.nodeValue = String(Math.round(target * eased));
    if (p < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

export function initImmersive(): void {
  if (!reduce && 'IntersectionObserver' in window) {
    const io1 = new IntersectionObserver(
      (entries) => {
        entries.forEach((en) => {
          if (en.isIntersecting) {
            animateNum(en.target as HTMLElement);
            io1.unobserve(en.target);
          }
        });
      },
      { threshold: 0.4 },
    );
    document.querySelectorAll('.metric .num').forEach((el) => io1.observe(el));
  }

  /* each terminal types itself in the first time it scrolls into view */
  if (!reduce && 'IntersectionObserver' in window) {
    const io2 = new IntersectionObserver(
      (entries) => {
        entries.forEach((en) => {
          if (en.isIntersecting) {
            en.target.classList.add('anim');
            io2.unobserve(en.target);
          }
        });
      },
      { threshold: 0.35 },
    );
    document.querySelectorAll('.term').forEach((el) => {
      if (!(el as HTMLElement).hidden) io2.observe(el);
    });
  }

  const hero = document.querySelector('.hero') as HTMLElement | null;
  if (hero && !reduce) {
    hero.addEventListener('pointermove', (e) => {
      const r = hero.getBoundingClientRect();
      hero.style.setProperty('--px', ((e.clientX - r.left) / r.width - 0.5).toFixed(3));
      hero.style.setProperty('--py', ((e.clientY - r.top) / r.height - 0.5).toFixed(3));
    });
    hero.addEventListener('pointerleave', () => {
      hero.style.setProperty('--px', '0');
      hero.style.setProperty('--py', '0');
    });
  }
}
