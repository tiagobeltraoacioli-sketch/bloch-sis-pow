(() => {
  const header = document.querySelector('[data-header]');
  const progress = document.querySelector('.scroll-progress span');
  const toggle = document.querySelector('.menu-toggle');
  const menu = document.querySelector('#mobile-nav');

  const updateScroll = () => {
    const y = window.scrollY;
    header?.classList.toggle('is-scrolled', y > 18);
    const available = document.documentElement.scrollHeight - window.innerHeight;
    if (progress) progress.style.width = `${available > 0 ? Math.min(100, y / available * 100) : 0}%`;
  };

  toggle?.addEventListener('click', () => {
    const open = toggle.getAttribute('aria-expanded') === 'true';
    toggle.setAttribute('aria-expanded', String(!open));
    menu.hidden = open;
  });

  menu?.querySelectorAll('a').forEach((link) => link.addEventListener('click', () => {
    toggle?.setAttribute('aria-expanded', 'false');
    menu.hidden = true;
  }));

  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.classList.add('is-visible');
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.12, rootMargin: '0px 0px -40px' });

  document.querySelectorAll('.reveal').forEach((element, index) => {
    element.style.transitionDelay = `${Math.min(index % 4, 3) * 70}ms`;
    observer.observe(element);
  });

  window.addEventListener('scroll', updateScroll, { passive: true });
  updateScroll();
})();
