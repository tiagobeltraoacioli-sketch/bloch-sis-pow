// Click-to-load YouTube player for the site soundtrack (Sovereign of Our Lives only).
// Follows the YouTube embed rules: the official player stays visible at >= 200x200 with nothing
// over it, it loads only after the visitor asks, and closing it removes the player entirely.
(() => {
  const source = document.querySelector('[data-site-music]');
  if (!source) return;
  const id = source.dataset.youtubeId;
  if (!/^[A-Za-z0-9_-]{11}$/.test(id)) return;
  const title = source.dataset.title || 'Soundtrack';
  const artist = source.dataset.artist || '';

  const player = document.createElement('div');
  player.className = 'site-music';
  player.setAttribute('role', 'region');
  player.setAttribute('aria-label', 'Site music');
  player.innerHTML = '<div class="site-music-bar">'
    + '<button class="site-music-toggle" type="button" aria-expanded="false"></button>'
    + '<span class="site-music-meta"><strong></strong><small></small></span>'
    + '<button class="site-music-close" type="button" aria-label="Close player" hidden>×</button></div>'
    + '<div class="site-music-frame" hidden></div>'
    + '<a class="site-music-link" target="_blank" rel="noopener noreferrer" hidden>Open in YouTube Music ↗</a>';
  const toggle = player.querySelector('.site-music-toggle');
  const close = player.querySelector('.site-music-close');
  const frame = player.querySelector('.site-music-frame');
  const link = player.querySelector('.site-music-link');
  player.querySelector('strong').textContent = title;
  player.querySelector('small').textContent = artist ? `${artist} · YouTube` : 'YouTube';
  toggle.setAttribute('aria-label', `Play ${title} on YouTube`);
  link.href = `https://music.youtube.com/watch?v=${id}`;

  const open = () => {
    if (frame.firstChild) return;
    const iframe = document.createElement('iframe');
    // loop needs playlist set to the same video, so only this track repeats.
    iframe.src = `https://www.youtube-nocookie.com/embed/${id}?autoplay=1&loop=1&playlist=${id}&rel=0&playsinline=1`;
    iframe.title = `${title} — ${artist} (YouTube video player)`;
    iframe.allow = 'autoplay; encrypted-media; picture-in-picture; fullscreen';
    iframe.referrerPolicy = 'strict-origin-when-cross-origin';
    iframe.allowFullscreen = true;
    frame.append(iframe);
    frame.hidden = close.hidden = link.hidden = false;
    toggle.hidden = true;
    player.classList.add('is-open');
    close.focus();
  };
  const shut = () => {
    frame.replaceChildren();
    frame.hidden = close.hidden = link.hidden = true;
    toggle.hidden = false;
    player.classList.remove('is-open');
    toggle.focus();
  };

  toggle.addEventListener('click', open);
  close.addEventListener('click', shut);
  document.body.append(player);
})();
