# TOTPVault portátil para Windows

O cofre e o cliente são programas nativos do Windows e usam o .NET Framework 4.8 ou posterior. A edição portátil é executada diretamente da pasta. O servidor usa HTTPS pelo HTTP.sys, Active Directory via LDAPS e o DPAPI do Windows para proteger a configuração e o cofre local.

## Preparar e iniciar

1. Extraia a pasta `TOTPVault` para `C:\TOTPVault` no servidor que tem o IP para o qual o pacote foi compilado. A porta TCP 443 precisa estar livre nesse IP. A pasta fica no disco NTFS do Windows para que as permissões do Agendador sejam previsíveis.
2. Em **Windows PowerShell como administrador**, entre nessa pasta e execute os comandos abaixo, conforme a política de execução da empresa.

```powershell
Set-Location C:\TOTPVault
.\Configurar-Pasta.ps1
.\Inicio-Automatico.ps1
```

O primeiro comando de configuração lê o domínio, testa LDAPS e o grupo administrador, prepara o HTTPS e cria uma regra de firewall limitada à sub-rede local e aos perfis Domínio e Privado. A conta de serviço do AD precisa de acesso somente de leitura. Use o DN completo de um grupo do AD para administrar o cofre. O campo da Base DN pode ficar em branco para detecção automática.

A CA do certificado LDAPS precisa ser confiável no repositório de **Máquina Local** do servidor. O instalador antigo fica em quarentena conforme o processo da TI. Este ZIP usa arquivos separados e o build não é assinado. Se o produto de segurança alertar sobre algum arquivo, preserve o alerta e encaminhe o nome e o hash para análise pela TI. Os hashes do pacote estão em `SHA256SUMS.txt`.

Para o HTTPS do cofre, informe o thumbprint de um certificado corporativo existente, em `LocalMachine\My`, com chave privada e com o IPv4 do cofre no SAN. Se escolher o certificado gerado pelo Windows, a TI precisa distribuir a parte pública `TOTPVault-HTTPS.cer` para os PCs pelo mecanismo de confiança da empresa, após conferir o SHA-256 exibido.

O último comando cria a tarefa **TOTPVault-Portatil** visível no Agendador, inicia agora e inicia novamente ao ligar o Windows, mesmo sem login no computador. A tarefa usa a conta Windows Serviço Local. Preserve o caminho da pasta. [Agendador de Tarefas](https://learn.microsoft.com/pt-br/powershell/module/scheduledtasks/new-scheduledtasktrigger)

## Operação

- Para iniciar manualmente, em vez da tarefa, abra o Windows PowerShell como administrador na pasta e execute `.\TOTPVault-Servidor.exe --portable C:\TOTPVault\dados`. O servidor fica no console. Use Ctrl+C para fechar. Mantenha apenas uma instância.
- Para iniciar uma tarefa já registrada, use `Start-ScheduledTask -TaskName 'TOTPVault-Portatil'`. Para parar e desativar o início automático, use `Disable-ScheduledTask -TaskName 'TOTPVault-Portatil'` e `Stop-ScheduledTask -TaskName 'TOTPVault-Portatil'`.
- Distribua somente `TOTPVault.exe` aos funcionários. A tela pede o usuário curto do AD e a senha. O endereço HTTPS é fixado na compilação. Administradores do cofre veem o botão **Usuários**.
- O cofre e os logs ficam em `C:\TOTPVault\dados`. Estão protegidos pelas permissões do Windows. O banco é protegido contra leitura do arquivo sem acesso à máquina. Faça backup como administrador e preserve as chaves DPAPI da instalação do Windows. Copiar apenas os arquivos para outra máquina não transfere o cofre. A primeira execução desta pasta cria um cofre novo.

O bloqueio pelo painel preserva os tokens e invalida as sessões. A conta do domínio continua sob gestão do AD. Usar a mesma senha de AD para abrir o cofre e para entrar no sistema protegido não fornece um segundo fator independente.

## Compilar

Em um Windows com .NET Framework 4.8 ou posterior, a partir da pasta de fontes:

```powershell
.\Build.ps1 -ServerIp '192.0.2.10' -AdHost 'dc01.example.com'
```

O build gera `TOTPVault-Portatil.zip` com a pasta `TOTPVault`, os dois executáveis, scripts, código-fonte, licença e hashes. Os endereços da empresa entram na compilação. O repositório não inclui credenciais nem certificados da empresa.
