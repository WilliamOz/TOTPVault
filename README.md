# TOTPVault nativo para Windows

Servidor em C# executado como serviço do Windows e autenticador WinForms. Usa o .NET Framework 4.8 ou posterior, HTTPS pelo HTTP.sys, Active Directory via LDAPS e um cofre local protegido pelo DPAPI do Windows. A edição `windows-native` é independente da versão PHP que permanece na branch `main`.

## Instalar

1. Após a revisão e a assinatura pela TI, extraia o pacote de instalação na máquina Windows que possui o IPv4 para o qual foi compilado. Abra o Windows PowerShell como administrador local, entre na pasta e execute `.\Instalar.ps1` conforme a política de execução da empresa. A porta TCP 443 precisa estar livre nesse endereço. A regra de firewall fica limitada às sub-redes locais e aos perfis Domínio e Privado.
2. Tenha o UPN ou DN e a senha de uma conta de serviço **somente leitura** do AD e o DN completo do grupo de administradores do cofre. Um grupo opcional pode restringir quais funcionários entram. Os grupos devem ter membros diretos. Deixe a Base DN em branco para ler o contexto padrão do AD.
3. O controlador precisa aceitar LDAPS na porta 636 e apresentar um certificado que corresponda ao seu nome DNS. O Windows que recebe o serviço precisa confiar na CA do controlador no repositório de certificado da **Máquina Local**. O assistente valida a conta de serviço, a base e os grupos antes de registrar o serviço.
4. Para HTTPS do cofre, use de preferência um certificado corporativo instalado em `LocalMachine\My`, com chave privada e o IPv4 de destino no SAN. Se o assistente gerar um certificado, ele exportará a parte pública `TOTPVault-HTTPS.cer` para a pasta do aplicativo. A TI deve distribuir esse certificado pelo mecanismo de confiança dos PCs, após validar a impressão digital que o instalador exibe. O autenticador mantém a validação de certificados do Windows.
5. Distribua o `TOTPVault.exe` instalado em `C:\Program Files\TOTPVaultNative`. A tela solicita usuário curto do AD e senha. O endereço é fixado na compilação. Administradores veem o botão **Usuários** e podem desabilitar ou reabilitar contas do cofre. Os funcionários precisam de acesso de rede ao cofre.

O painel controla as contas que já entraram no aplicativo. Desabilitar invalida as sessões e preserva tokens. Reabilitar exige novo login. A conta do domínio permanece sob gestão do AD. Alterações do grupo administrador são verificadas em cada ação no painel.

Os dados ficam em `%ProgramData%\TOTPVaultNative`. Faça backup como administrador, preservando a instalação e as chaves de máquina do Windows. Copiar apenas `cofre.dat` para outra máquina não transfere o cofre. A edição nativa cria um cofre novo. Seus segredos estão protegidos contra leitura do arquivo por usuários sem acesso à pasta. Uma conta administrativa ou o serviço com controle sobre o servidor pode acessar o cofre.

A autenticação do aplicativo é feita pela senha do AD. Se o sistema que consome o código também aceita essa mesma senha, abrir o cofre com ela não oferece um segundo fator independente.

## Compilar

No Windows com .NET Framework 4.8 ou posterior:

```powershell
.\Build.ps1 -ServerIp '192.0.2.10' -AdHost 'dc01.example.com'
```

A saída contém `TOTPVault-Windows-Instalacao.zip` e `TOTPVault-Windows-Nativo.exe`. O ZIP tem o script PowerShell, os executáveis do servidor e do cliente, os padrões locais e a lista de hashes SHA-256. O build não assina os arquivos. A TI pode revisar as fontes e assinar os executáveis e o script com seu processo corporativo. Os endereços são informados na compilação. O repositório não inclui credenciais ou certificados reais.

Uma detecção de ameaça deve ser analisada pela equipe de segurança e pelo fabricante do antivírus antes da implantação. Preserve as proteções e o registro do nome da detecção e do arquivo afetado.

[Configuração de LDAPS no Windows](https://learn.microsoft.com/pt-br/troubleshoot/windows-server/identity/enable-ldap-over-ssl-3rd-certification-authority) · [Vínculo HTTPS do HTTP.sys](https://learn.microsoft.com/pt-br/windows-server/administration/windows-commands/netsh-http)
