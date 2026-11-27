# TOTPVault para Windows

Execute `TOTPVault.exe` em um PC com .NET Framework 4.8 ou posterior. Informe a URL HTTPS do cofre e seu usuário e senha do AD. O endereço é o do portal TOTPVault. O cliente utiliza a validação de certificados do Windows e descarta suas credenciais e sessão ao sair. Ele consulta códigos no servidor e precisa de acesso à rede interna ou à VPN.

O aplicativo permite cadastrar, editar e excluir tokens por chave Base32, consultar e copiar o código atual. A importação de QR e a administração de usuários também estão disponíveis no portal web.

Para compilar no Windows:

```powershell
.\desktop\build.ps1
```

Use `-ServerUrl 'https://cofre.example.com'` se quiser preencher a URL na tela inicial. O campo permanece editável.
