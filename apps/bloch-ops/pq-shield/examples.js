document.querySelectorAll('button[data-copy]').forEach((button) => {
  button.addEventListener('click', async () => {
    const target = document.getElementById(button.dataset.copy);
    if (!target || !navigator.clipboard?.writeText) return;
    try {
      await navigator.clipboard.writeText(target.textContent);
      button.textContent = 'COPIED';
      window.setTimeout(() => { button.textContent = 'COPY'; }, 2000);
    } catch {
      button.textContent = 'SELECT TEXT';
      window.setTimeout(() => { button.textContent = 'COPY'; }, 2500);
    }
  });
});
