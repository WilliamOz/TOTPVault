# TOTPVault com Active Directory

O [autenticador para Windows](desktop/README.md) usa o mesmo cofre e permite consultar códigos sem abrir o navegador.

Cofre TOTP para a rede interna. O funcionário entra com o usuário do AD e consulta seus códigos pelo navegador. Cada conta possui um cofre próprio, vinculado ao `objectGUID` do AD. Alterar o login da conta mantém os tokens. O aplicativo cria o cadastro local no primeiro login.

O painel **Administrar usuários** lista as contas que já entraram no cofre. Membros diretos do grupo de administradores podem desabilitar ou reabilitar esses cadastros. O bloqueio vale na próxima requisição, preserva os tokens e invalida as sessões anteriores, inclusive depois da reabilitação. O painel controla somente o acesso ao TOTPVault e registra quem alterou cada conta na tabela `user_access_audit`. Administradores também só podem acessar seus próprios tokens.

## Implantação com Docker Compose

1. Configure o LDAPS no controlador de domínio. Obtenha o nome DNS completo que aparece no certificado e a cadeia da CA em PEM. O servidor do cofre deve resolver o nome e alcançar o controlador na porta TCP 636. Consulte a [documentação do certificado LDAPS](https://learn.microsoft.com/pt-br/windows-server/identity/ad-ds/configure-ldap-signing-certificates).
2. Separe uma conta de serviço somente leitura que possa pesquisar a base e ler os atributos necessários, incluindo `objectGUID`, `sAMAccountName`, `displayName`, `userAccountControl`, `accountExpires` e `memberOf`. Defina um grupo de administradores e, de preferência, outro grupo para autorizar os usuários do cofre. Use membros diretos nos dois grupos.
3. Copie `.env.example` para `.env`. Defina senhas únicas para o MariaDB, gere `ENCRYPTION_KEY` com `openssl rand -base64 32` e preencha as variáveis `AD_*`. Coloque a cadeia de confiança em `local-config/ad-ca.pem`. Guarde o `.env` com acesso restrito.
4. Execute `docker compose up -d --build`. A porta HTTP fica vinculada somente a `127.0.0.1:8080`. Configure um proxy HTTPS local que sobrescreva `X-Forwarded-Proto` e impeça acesso direto ao backend. Para servir HTTPS diretamente no Apache, use `TRUST_TLS_PROXY=false`.
5. Abra a URL HTTPS pelo navegador. Use o nome curto do AD (`sAMAccountName`). Teste com dois funcionários e um administrador antes de importar segredos reais.

O cofre limita tentativas por conta e por endereço remoto. Atrás de proxy, configure `mod_remoteip` com a lista explícita de proxies confiáveis se precisar preservar o IP de origem. A aplicação usa `REMOTE_ADDR`. Sem essa configuração, o limite por IP é compartilhado pelos clientes do proxy.

As sessões têm duração máxima de 8 horas. O estado da conta no AD é revalidado em até 60 segundos na próxima requisição e a associação ao grupo administrador é conferida a cada acesso ao painel. Falhas de LDAPS interrompem a autenticação. Para desenvolvimento controlado, `ALLOW_HTTP_DEV=true` permite HTTP local. Use HTTPS com contas reais.

## Migração de uma implantação anterior

Em uma instalação nova, o Compose aplica `schema.sql` na criação do banco. Para atualizar uma instalação existente:

1. Pare o aplicativo antigo. Faça backup do banco e guarde o valor anterior da chave de criptografia. Registre o ID local de cada usuário e confira, com o responsável pelo AD, o `ObjectGUID` da conta que deve receber o cofre.
2. Aplique `migrations/002_ad_only.sql` uma vez e, em seguida, `schema.sql`. A migração remove os métodos de login legados e as permissões de compartilhamento. Os IDs e segredos dos tokens são preservados.
3. Vincule manualmente cada ID local autorizado ao GUID do AD **antes do primeiro login** dessa conta. Se o GUID vier do PowerShell, converta os 16 bytes na ordem usada pelo LDAP, por exemplo `[Convert]::ToHexString($conta.ObjectGUID.ToByteArray()).ToLowerInvariant()` no PowerShell 7. O SQL é `UPDATE users SET ad_guid = '<32 caracteres hexadecimais>', ad_username = '<usuário AD>' WHERE id = <id local conferido> AND ad_guid IS NULL;`. O aplicativo nunca vincula uma conta antiga automaticamente pelo nome.
4. Defina `LEGACY_ENCRYPTION_KEY` com o valor efetivo da configuração antiga e use uma chave aleatória de 32 bytes em `ENCRYPTION_KEY`. Confira a abertura de tokens antigos pelo dono correto após a migração. Mantenha backup seguro das chaves enquanto existirem tokens que dependam delas.

O armazenamento usa AES-256-GCM. Proteja o servidor e mantenha a chave de criptografia separada do backup do banco. Os códigos são gerados no servidor e exigem conectividade com a rede que hospeda o cofre. Para sistemas que aceitam a mesma senha do AD, lembre que o login por senha neste cofre não oferece um segundo fator independente.

A versão usa JavaScript e fontes servidos localmente. O importador de QR permite trazer tokens do Google Authenticator sem usar o serviço do Google para login.

[Implantação em Kubernetes](charts/totpvault/README.md) · [Projeto original](https://github.com/token2/TOTPVault)
