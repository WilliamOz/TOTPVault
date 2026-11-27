<?php $pageTitle = 'Entrar — TOTPVault'; require __DIR__ . '/layout.php'; ?>
<main style="min-height:100vh;display:grid;place-items:center;padding:1rem">
  <section class="card" style="width:min(100%,400px);padding:2rem">
    <div class="nav-brand"><img src="/favicon.png" width="32" height="32" alt=""> TOTPVault</div>
    <h1 style="margin:1.25rem 0 .375rem;font-size:1.65rem">Acesso corporativo</h1>
    <p class="text-ink3" style="margin-bottom:1.25rem">Use seu usuário de rede do Active Directory.</p>
    <?php if (isset($error)): ?>
      <p role="alert" style="color:var(--red);margin-bottom:1rem"><?= h($error) ?></p>
    <?php endif; ?>
    <form action="/auth/ad" method="post" style="display:grid;gap:.85rem">
      <input type="hidden" name="_csrf" value="<?= h(csrf_token()) ?>">
      <label>Usuário<input class="input" name="username" autocomplete="username" maxlength="80" required autofocus></label>
      <label>Senha<input class="input" type="password" name="password" autocomplete="current-password" required></label>
      <button class="btn btn-primary w-full" type="submit">Entrar</button>
    </form>
  </section>
</main>
</body>
</html>
