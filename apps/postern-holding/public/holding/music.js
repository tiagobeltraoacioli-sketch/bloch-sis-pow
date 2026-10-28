// Floating play/pause control for the site soundtrack. Nothing plays until the visitor asks.
(() => {
  const audio = document.querySelector('audio[data-site-music]');
  if (!audio) return;

  const player = document.createElement('div');
  player.className = 'site-music';
  player.setAttribute('role', 'region');
  player.setAttribute('aria-label', 'Site music');
  player.innerHTML = '<button class="site-music-toggle" type="button" aria-pressed="false"></button>'
    + '<span class="site-music-meta"><strong></strong><small></small><span class="site-music-bar"><span></span></span></span>'
    + '<span class="site-music-eq" aria-hidden="true"><i></i><i></i><i></i></span>';
  const toggle = player.querySelector('button');
  const progress = player.querySelector('.site-music-bar span');
  player.querySelector('strong').textContent = audio.dataset.title || 'Soundtrack';
  player.querySelector('small').textContent = audio.dataset.artist || '';

  const sync = () => {
    const playing = !audio.paused;
    player.classList.toggle('is-playing', playing);
    toggle.setAttribute('aria-pressed', String(playing));
    toggle.setAttribute('aria-label', `${playing ? 'Pause' : 'Play'} ${audio.dataset.title || 'music'}`);
  };

  toggle.addEventListener('click', () => {
    if (audio.paused) audio.play().catch(sync);
    else audio.pause();
  });
  audio.addEventListener('play', sync);
  audio.addEventListener('pause', sync);
  audio.addEventListener('timeupdate', () => {
    if (audio.duration) progress.style.width = `${audio.currentTime / audio.duration * 100}%`;
  });

  sync();
  document.body.append(player);
})();
