using System;
using System.Drawing;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using System.Windows.Forms;

[assembly: TargetFramework(".NETFramework,Version=v4.8")]

namespace TotpVault {
    internal static class Program {
        [STAThread]
        private static void Main() {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new VaultWindow());
        }
    }

    internal sealed class VaultWindow : Form {
        private readonly TextBox username = new TextBox { MaxLength = 80 };
        private readonly TextBox password = new TextBox { MaxLength = 1024, UseSystemPasswordChar = true };
        private readonly Button login = new Button();
        private readonly Label loginStatus = new Label();
        private readonly Label vaultStatus = new Label();
        private readonly Label account = new Label();
        private readonly Label otp = new Label();
        private readonly Label remaining = new Label();
        private readonly ListBox tokens = new ListBox { DisplayMember = "Title", IntegralHeight = false };
        private readonly Button copy = new Button();
        private readonly Button reveal = new Button();
        private readonly Button edit = new Button();
        private readonly Button delete = new Button();
        private readonly Button admin = new Button { Visible = false };
        private readonly Timer timer = new Timer { Interval = 1000 };
        private readonly TableLayoutPanel loginPanel;
        private readonly TableLayoutPanel vaultPanel;
        private VaultApi api;
        private bool working;
        private bool polling;
        private DateTime revealUntil;
        private DateTime nextSessionCheck;
        private string currentCode;
        private DateTime codeExpiry;
        private TokenInfo Selected { get { return tokens.SelectedItem as TokenInfo; } }

        internal VaultWindow() {
            Text = "TOTPVault";
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(640, 465);
            MinimumSize = new Size(555, 442);
            AutoScaleMode = AutoScaleMode.Dpi;
            Font = new Font("Segoe UI", 10);
            BackColor = Color.FromArgb(245, 247, 252);
            ForeColor = Color.FromArgb(25, 33, 51);

            loginPanel = Column(465);
            loginPanel.Controls.Add(Label("TOTPVault", 24, true));
            loginPanel.Controls.Add(Label("Entre com sua conta do Active Directory", 10, false));
            AddField(loginPanel, "Usuário do AD", username);
            AddField(loginPanel, "Senha", password);
            SetupButton(login, "Entrar", true);
            loginPanel.Controls.Add(login);
            ConfigureStatus(loginStatus);
            loginPanel.Controls.Add(loginStatus);

            vaultPanel = Column(1180);
            vaultPanel.AutoSize = false;
            vaultPanel.Dock = DockStyle.Fill;
            vaultPanel.Padding = new Padding(25, 18, 25, 16);
            vaultPanel.RowCount = 8;
            for (int i = 0; i < vaultPanel.RowCount; i++) {
                vaultPanel.RowStyles.Add(i == 2 ? new RowStyle(SizeType.Percent, 100) : new RowStyle(SizeType.AutoSize));
            }
            vaultPanel.Controls.Add(Label("Meus tokens", 21, true));
            account.AutoSize = true;
            vaultPanel.Controls.Add(account);
            tokens.Dock = DockStyle.Fill;
            tokens.MinimumSize = new Size(270, 75);
            tokens.AccessibleName = "Tokens do usuário";
            vaultPanel.Controls.Add(tokens);
            otp.AutoSize = true;
            otp.Text = "—";
            otp.Font = new Font("Consolas", 29, FontStyle.Bold);
            otp.Margin = new Padding(0, 8, 0, 0);
            vaultPanel.Controls.Add(otp);
            remaining.AutoSize = true;
            vaultPanel.Controls.Add(remaining);
            var codeActions = Arow();
            SetupButton(copy, "Copiar código", true);
            SetupButton(reveal, "Mostrar código", false);
            codeActions.Controls.AddRange(new Control[] { copy, reveal });
            vaultPanel.Controls.Add(codeActions);
            var actions = Arow();
            var add = new Button();
            var signOut = new Button();
            SetupButton(add, "Adicionar", false);
            SetupButton(edit, "Editar", false);
            SetupButton(delete, "Excluir", false);
            SetupButton(signOut, "Sair", false);
            SetupButton(admin, "Usuários", false);
            actions.Controls.AddRange(new Control[] { add, edit, delete, admin, signOut });
            vaultPanel.Controls.Add(actions);
            ConfigureStatus(vaultStatus);
            vaultPanel.Controls.Add(vaultStatus);

            var center = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 3 };
            center.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            center.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 455));
            center.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            center.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
            center.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            center.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
            loginPanel.Dock = DockStyle.Fill;
            center.Controls.Add(loginPanel, 1, 1);
            Controls.Add(vaultPanel);
            Controls.Add(center);
            vaultPanel.Hide();
            AcceptButton = login;
            Shown += (s, e) => username.Focus();

            login.Click += async (s, e) => await SignIn();
            signOut.Click += async (s, e) => await SignOut();
            timer.Tick += async (s, e) => await RefreshCode();
            tokens.SelectedIndexChanged += async (s, e) => {
                revealUntil = DateTime.MinValue;
                ClearCode();
                await RefreshCode();
            };
            reveal.Click += async (s, e) => {
                revealUntil = DateTime.UtcNow.AddSeconds(10);
                await RefreshCode();
            };
            copy.Click += (s, e) => {
                if (currentCode == null || codeExpiry <= DateTime.UtcNow) return;
                try { Clipboard.SetText(currentCode); vaultStatus.Text = "Código copiado."; }
                catch (System.Runtime.InteropServices.ExternalException) { vaultStatus.Text = "Área de transferência indisponível."; }
            };
            add.Click += async (s, e) => await ChangeToken(null);
            edit.Click += async (s, e) => { if (Selected != null) await ChangeToken(Selected); };
            delete.Click += async (s, e) => await DeleteToken();
            admin.Click += (s, e) => {
                if (api == null) return;
                var connection = api;
                using (var window = new AdminWindow(connection, ex => {
                    if (api == connection) HandleVaultError(ex);
                })) window.ShowDialog(this);
            };
            FormClosed += (s, e) => { timer.Stop(); timer.Dispose(); if (api != null) api.Dispose(); };
        }

        private async Task SignIn() {
            if (working) return;
            working = true;
            login.Enabled = false;
            loginStatus.Text = "Entrando…";
            VaultApi candidate = null;
            try {
                var server = VaultApi.ParseServer(BuildSettings.ServerUrl);
                if (username.TextLength == 0 || password.TextLength == 0) {
                    loginStatus.Text = "Informe seu usuário e sua senha do AD.";
                    return;
                }
                candidate = new VaultApi(server, BuildSettings.ServerCertificateSha256);
                var signIn = candidate.Login(username.Text.Trim(), password.Text);
                password.Clear();
                string signedAs = await signIn;
                if (string.IsNullOrEmpty(signedAs)) throw new InvalidOperationException("Sessão inválida.");
                var profiles = await candidate.ListTokens();
                api = candidate;
                candidate = null;
                admin.Visible = api.CanAdmin;
                account.Text = signedAs;
                loginPanel.Parent.Hide();
                vaultPanel.Show();
                AcceptButton = null;
                LoadTokens(profiles, null);
                vaultStatus.Text = profiles.Length == 0 ? "Adicione seu primeiro token TOTP." : "";
                timer.Start();
            } catch (Exception ex) {
                loginStatus.Text = ErrorMessage(ex, true);
            } finally {
                if (candidate != null) candidate.Dispose();
                working = false;
                login.Enabled = true;
            }
            await RefreshCode();
        }

        private async Task SignOut() {
            var previous = api;
            if (previous == null) return;
            CloseVault("");
            try { await previous.Logout(); } catch (Exception) { }
            finally { previous.Dispose(); }
        }

        private void CloseVault(string message) {
            api = null;
            timer.Stop();
            ClearCode();
            revealUntil = DateTime.MinValue;
            tokens.DataSource = null;
            account.Text = "";
            vaultPanel.Hide();
            loginPanel.Parent.Show();
            AcceptButton = login;
            loginStatus.Text = message;
            password.Focus();
        }

        private void ClearCode() {
            currentCode = null;
            otp.Text = "—";
            remaining.Text = " ";
            copy.Enabled = false;
            reveal.Enabled = Selected != null && Selected.hide_code != 0;
            edit.Enabled = delete.Enabled = Selected != null;
        }

        private async Task RefreshCode() {
            var connection = api;
            if (connection == null || working || polling) return;
            DateTime now = DateTime.UtcNow;
            var token = Selected;
            bool show = token != null && (token.hide_code == 0 || revealUntil > now);
            if (!show) ClearCode();
            if (!show && nextSessionCheck > now) return;
            polling = true;
            try {
                if (!show) {
                    var session = await connection.GetSession();
                    if (session.username == null) throw new VaultException(401);
                    nextSessionCheck = now.AddSeconds(5);
                    return;
                }
                var value = await connection.GetCode(token.id);
                if (api != connection || Selected != token) return;
                if (token.hide_code != 0 && revealUntil <= DateTime.UtcNow) {
                    ClearCode();
                    return;
                }
                currentCode = value.code;
                codeExpiry = now.AddSeconds(Math.Max(0, value.remaining));
                otp.Text = value.code;
                remaining.Text = value.remaining + " s para renovar";
                copy.Enabled = currentCode != null;
                reveal.Enabled = false;
            } catch (Exception ex) {
                if (api == connection) {
                    ClearCode();
                    HandleVaultError(ex);
                }
            } finally { polling = false; }
        }

        private void LoadTokens(TokenInfo[] entries, int? selectedId) {
            tokens.DataSource = entries;
            if (selectedId.HasValue) {
                for (int i = 0; i < entries.Length; i++) {
                    if (entries[i].id == selectedId.Value) { tokens.SelectedIndex = i; break; }
                }
            }
            nextSessionCheck = DateTime.MinValue;
            ClearCode();
        }

        private async Task ChangeToken(TokenInfo old) {
            if (working || api == null) return;
            using (var dialog = new TokenWindow(old)) {
                if (dialog.ShowDialog(this) != DialogResult.OK || api == null) return;
                await Mutate(async connection => {
                    await connection.SaveToken(dialog.Value, dialog.Secret);
                }, old == null ? (int?)null : old.id);
            }
        }

        private async Task DeleteToken() {
            var token = Selected;
            if (working || token == null || api == null) return;
            if (MessageBox.Show(this, "Excluir o token " + token.name + "?", Text,
                MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            await Mutate(async connection => { await connection.DeleteToken(token.id); }, null);
        }

        private async Task Mutate(Func<VaultApi, Task> operation, int? selectedId) {
            var connection = api;
            if (connection == null) return;
            working = true;
            try {
                await operation(connection);
                var entries = await connection.ListTokens();
                if (api == connection) {
                    LoadTokens(entries, selectedId);
                    vaultStatus.Text = "Meus tokens atualizados.";
                }
            } catch (Exception ex) {
                if (api == connection) HandleVaultError(ex);
            } finally { working = false; }
            await RefreshCode();
        }

        private void HandleVaultError(Exception ex) {
            var response = ex as VaultException;
            if (response != null && response.Status == 401) {
                var previous = api;
                CloseVault("Sessão encerrada. Entre novamente.");
                previous.Dispose();
            } else {
                vaultStatus.Text = ErrorMessage(ex, false);
            }
        }

        private static string ErrorMessage(Exception exception, bool atLogin) {
            for (var error = exception; error != null; error = error.InnerException) {
                var network = error as System.Net.WebException;
                if (error is System.Security.Authentication.AuthenticationException ||
                    (network != null && network.Status == System.Net.WebExceptionStatus.TrustFailure)) {
                    return "Certificado HTTPS do cofre não reconhecido.";
                }
            }
            var response = exception as VaultException;
            if (response != null) {
                switch (response.Status) {
                    case 400: return "Revise os dados informados.";
                    case 401: return atLogin ? "Usuário, senha ou acesso ao cofre inválido." : "Sessão encerrada.";
                    case 403: return "Seu acesso a esta operação foi recusado.";
                    case 404: return "Recurso indisponível. Confira a instalação do servidor.";
                    case 429: return "Muitas tentativas. Aguarde alguns minutos.";
                    case 503: return "O cofre ou o Active Directory está indisponível.";
                }
            }
            if (exception is ArgumentException || exception is InvalidOperationException) {
                return exception.Message;
            }
            return "Falha na comunicação. Confira a rede e o certificado HTTPS do cofre.";
        }

        internal static TableLayoutPanel Column(int width) {
            var panel = new TableLayoutPanel { Width = width, AutoSize = true, ColumnCount = 1, Padding = new Padding(15) };
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            return panel;
        }

        internal static Label Label(string text, float size, bool bold) {
            return new Label { Text = text, AutoSize = true, Margin = new Padding(0, 2, 0, 5),
                Font = new Font("Segoe UI", size, bold ? FontStyle.Bold : FontStyle.Regular) };
        }

        internal static void AddField(TableLayoutPanel panel, string title, Control input) {
            var label = Label(title, 10, false);
            label.Margin = new Padding(0, 6, 0, 0);
            panel.Controls.Add(label);
            input.AccessibleName = title;
            input.Dock = DockStyle.Top;
            input.Margin = new Padding(0, 3, 0, 3);
            panel.Controls.Add(input);
        }

        internal static void SetupButton(Button button, string name, bool primary) {
            button.Text = name;
            button.AutoSize = true;
            button.MinimumSize = new Size(75, 31);
            button.Margin = new Padding(0, 5, 8, 3);
            button.Padding = new Padding(6, 0, 6, 0);
            if (!primary) return;
            button.FlatStyle = FlatStyle.Flat;
            button.FlatAppearance.BorderSize = 0;
            button.BackColor = Color.FromArgb(34, 71, 168);
            button.ForeColor = Color.White;
        }

        private static void ConfigureStatus(Label status) {
            status.Height = 31;
            status.Dock = DockStyle.Top;
            status.ForeColor = Color.FromArgb(115, 44, 45);
            status.AutoEllipsis = true;
        }

        private static FlowLayoutPanel Arow() {
            return new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = Padding.Empty };
        }
    }
}
