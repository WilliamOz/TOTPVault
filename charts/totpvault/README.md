# Implantação do TOTPVault com Helm

Disponibilize uma imagem deste fork no seu registry e defina `image.repository` e `image.tag`. Use uma versão imutável em produção.

Configure `ad.host`, `ad.baseDn`, `ad.bindDn` e `ad.adminGroupDn`. O grupo opcional `ad.accessGroupDn` limita quem pode entrar. Os grupos exigem associação direta. Para uma CA interna, crie um Secret com a chave `ad-ca.pem` e informe seu nome em `ad.caSecret`. Sirva o aplicativo por um Ingress com TLS que sobrescreva `X-Forwarded-Proto` e restrinja o acesso direto ao Service. Os probes consultam `/healthz`.

Crie um Secret no namespace com `DB_PASSWORD`, `AD_BIND_PASSWORD`, `ENCRYPTION_KEY` (32 bytes aleatórios codificados em Base64) e `DB_ROOT_PASSWORD` se usar o MariaDB do chart. Informe seu nome em `secrets.existingSecret`. Para migrar uma instalação antiga, inclua `LEGACY_ENCRYPTION_KEY` com a chave antiga. O valor de `ENCRYPTION_KEY` e o banco precisam de backup separado.

O MariaDB interno inicializa o esquema somente em volume vazio. Para banco externo, use `mariadb.enabled=false`, configure `externalDatabase` e aplique `schema.sql`. Antes de atualizar um banco existente, siga a migração no [README do projeto](../../README.md).

As sessões PHP usam arquivos. Para múltiplas réplicas, use volume de sessões compartilhado com suporte a escrita concorrente. Em uma réplica, a configuração padrão mantém os arquivos na PVC.
