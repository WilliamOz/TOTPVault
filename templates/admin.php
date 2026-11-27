<?php $pageTitle = 'Administração de usuários — TOTPVault'; require __DIR__ . '/layout.php'; ?>
<style>
.users-page{max-width:960px;margin:0 auto;padding:clamp(1rem,4vw,2.5rem)}
.users-table{width:100%;border-collapse:collapse;white-space:nowrap}
.users-table th,.users-table td{text-align:left;padding:.9rem 1rem;border-bottom:1px solid var(--line)}
.users-table th{color:var(--ink3);font-size:.8125rem;background:var(--bg2)}
.users-table tr:last-child td{border-bottom:0}
.users-table td:first-child{white-space:normal;min-width:10rem}
</style>
<nav class="nav">
  <a class="nav-brand" href="/dashboard"><img src="/favicon.png" width="30" height="30" alt=""> TOTPVault</a>
  <div class="nav-spacer"></div>
  <a href="/dashboard" class="btn btn-secondary">Meus tokens</a>
</nav>
<main class="users-page">
  <h1 style="font-size:1.65rem">Usuários do cofre</h1>
  <p class="text-ink3" style="margin:.45rem 0 1.25rem">Contas do AD que já acessaram o TOTPVault. Desabilitar uma conta encerra o acesso ao cofre e preserva seus tokens.</p>
  <div class="card" style="overflow:auto">
    <table class="users-table">
      <thead><tr><th scope="col">Nome</th><th scope="col">Usuário do AD</th><th scope="col">Acesso</th><th scope="col">Ação</th></tr></thead>
      <tbody>
        <?php foreach ($users as $account): ?>
          <?php $disabled = $account['disabled_at'] !== null; ?>
          <tr>
            <td><?= h($account['name'] ?: $account['ad_username']) ?></td>
            <td><?= h($account['ad_username']) ?></td>
            <td style="color:<?= $disabled ? 'var(--red)' : 'var(--green)' ?>"><?= $disabled ? 'Desabilitado' : 'Habilitado' ?></td>
            <td>
              <?php if ($account['id'] === $user['id']): ?>
                <span class="text-ink3">Sua conta</span>
              <?php else: ?>
                <form action="/admin/users/access" method="post">
                  <input type="hidden" name="_csrf" value="<?= h(csrf_token()) ?>">
                  <input type="hidden" name="target" value="<?= (int)$account['id'] ?>">
                  <button class="btn btn-secondary btn-sm" type="submit" name="action" value="<?= $disabled ? 'enable' : 'disable' ?>">
                    <?= $disabled ? 'Reabilitar' : 'Desabilitar' ?>
                  </button>
                </form>
              <?php endif; ?>
            </td>
          </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div>
</main>
</body>
</html>
