/* Navigation enhances native links and disclosure elements; all content works without JavaScript. */
const menu = document.querySelector('.mobile-menu');
if (menu) {
  menu.querySelectorAll('a').forEach((link) => {
    link.addEventListener('click', () => { menu.open = false; });
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && menu.open) {
      menu.open = false;
      menu.querySelector('summary')?.focus();
    }
  });
  document.addEventListener('click', (event) => {
    if (menu.open && event.target instanceof Node && !menu.contains(event.target)) menu.open = false;
  });
  const desktop = window.matchMedia('(min-width: 901px)');
  desktop.addEventListener('change', () => { if (desktop.matches) menu.open = false; });
}
