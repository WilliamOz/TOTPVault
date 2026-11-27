using System;
using System.Drawing;
using System.IO;
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

    internal sealed partial class VaultWindow : Form {
        private readonly TextBox username = new TextBox { MaxLength = 80 };
        private readonly TextBox password = new TextBox { MaxLength = 1024, UseSystemPasswordChar = true };
        private readonly Button login = new RoundedButton();
        private readonly Button retrySession = new RoundedButton { Visible = false };
        private readonly Label loginStatus = new Label();
        private readonly Label vaultStatus = new Label();
        private readonly Label account = new Label();
        private readonly Label otp = new Label();
        private readonly Label remaining = new Label();
        private readonly ListBox tokens = new VaultTokenList();
        private readonly Button copy = new RoundedButton();
        private readonly Button reveal = new RoundedButton();
        private readonly Button edit = new RoundedButton();
        private readonly Button delete = new RoundedButton();
        private readonly Button admin = new RoundedButton { Visible = false };
        private readonly Timer timer = new Timer { Interval = 1000 };
        private readonly Uri endpoint = VaultApi.ParseServer(BuildSettings.ServerUrl);
        private readonly SessionCache cache;
        private StoredSession activeSession;
        private VaultApi api;
        private bool working;
        private bool polling;
        private DateTime revealUntil;
        private DateTime nextSessionCheck;
        private string currentCode;
        private DateTime codeExpiry;
        private TokenInfo Selected { get { return tokens.SelectedItem as TokenInfo; } }

        internal VaultWindow() : this(null) {}

        internal VaultWindow(SessionCache customCache) {
            cache = customCache ?? new SessionCache(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TOTPVault"),
                endpoint.AbsoluteUri, BuildSettings.ServerCertificateSha256);
            BuildInterface();
            Shown += async (s, e) => await RestoreSession();

            login.Click += async (s, e) => await SignIn();
            retrySession.Click += async (s, e) => await RestoreSession();
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
            retrySession.Enabled = false;
            loginStatus.Text = "Entrando…";
            VaultApi candidate = null;
            try {
                if (username.TextLength == 0 || password.TextLength == 0) {
                    loginStatus.Text = "Informe seu usuário e sua senha do AD.";
                    return;
                }
                candidate = new VaultApi(endpoint, BuildSettings.ServerCertificateSha256);
                var signIn = candidate.Login(username.Text.Trim(), password.Text);
                password.Clear();
                string signedAs = await signIn;
                if (string.IsNullOrEmpty(signedAs)) throw new InvalidOperationException("Sessão inválida.");
                var record = new StoredSession(candidate.SessionToken, DateTime.UtcNow.AddHours(8));
                var previousRecord = cache.Load();
                bool remembered = cache.Save(record);
                if (!remembered && previousRecord != null) cache.Clear(previousRecord.Token);
                var profiles = await candidate.ListTokens();
                if (IsDisposed) return;
                OpenVault(candidate, signedAs, record, profiles);
                candidate = null;
                if (!remembered) vaultStatus.Text = "A sessão está ativa. O Windows não conseguiu salvá-la para reabrir.";
            } catch (Exception ex) {
                if (!IsDisposed) {
                    loginStatus.Text = ErrorMessage(ex, true);
                    retrySession.Visible = cache.Load() != null;
                }
            } finally {
                if (candidate != null) candidate.Dispose();
                working = false;
                if (!IsDisposed) login.Enabled = retrySession.Enabled = true;
            }
            await RefreshCode();
        }

        private async Task RestoreSession() {
            if (working || api != null) return;
            var record = cache.Load();
            if (record == null) {
                retrySession.Visible = false;
                username.Focus();
                return;
            }
            working = true;
            login.Enabled = retrySession.Enabled = false;
            loginStatus.Text = "Restaurando sessão…";
            VaultApi candidate = new VaultApi(endpoint, BuildSettings.ServerCertificateSha256);
            try {
                var signedAs = await candidate.Restore(record.Token);
                if (string.IsNullOrEmpty(signedAs)) throw new VaultException(401);
                var profiles = await candidate.ListTokens();
                if (IsDisposed) return;
                OpenVault(candidate, signedAs, record, profiles);
                candidate = null;
            } catch (VaultException ex) {
                if (ex.Status == 401) {
                    cache.Clear(record.Token);
                    if (!IsDisposed) {
                        retrySession.Visible = false;
                        loginStatus.Text = "Sessão encerrada. Entre novamente.";
                    }
                } else if (!IsDisposed) {
                    retrySession.Visible = true;
                    loginStatus.Text = ErrorMessage(ex, true);
                }
            } catch (Exception ex) {
                if (!IsDisposed) {
                    retrySession.Visible = true;
                    loginStatus.Text = ErrorMessage(ex, true);
                }
            } finally {
                if (candidate != null) candidate.Dispose();
                working = false;
                if (!IsDisposed) login.Enabled = retrySession.Enabled = true;
            }
            if (!IsDisposed && api == null) username.Focus();
            await RefreshCode();
        }

        private void OpenVault(VaultApi connection, string signedAs, StoredSession record, TokenInfo[] profiles) {
            api = connection;
            activeSession = record;
            admin.Visible = connection.CanAdmin;
            account.Text = signedAs;
            sessionTime.Text = "Sessão até " + record.ExpiresUtc.ToLocalTime().ToString("HH:mm");
            username.Text = signedAs;
            retrySession.Visible = false;
            loginView.Hide();
            vaultPanel.Show();
            AcceptButton = null;
            LoadTokens(profiles, null);
            vaultStatus.Text = "";
            timer.Start();
        }

        private async Task SignOut() {
            var previous = api;
            if (previous == null) return;
            bool cleared = activeSession == null || cache.Clear(activeSession.Token);
            CloseVault("");
            try { await previous.Logout(); }
            catch (Exception) {
                if (!cleared && !IsDisposed) loginStatus.Text = "Não foi possível confirmar a saída. Verifique a conexão.";
            }
            finally { previous.Dispose(); }
        }

        private void CloseVault(string message) {
            api = null;
            activeSession = null;
            timer.Stop();
            ClearCode();
            revealUntil = DateTime.MinValue;
            tokens.DataSource = null;
            account.Text = "";
            vaultPanel.Hide();
            loginView.Show();
            AcceptButton = login;
            loginStatus.Text = message;
            password.Focus();
        }

        private void ClearCode() {
            currentCode = null;
            otp.Text = "—";
            tokenHeading.Text = Selected == null ? "Selecione um token" : Selected.name;
            remaining.Text = Selected == null ? "Seu código aparecerá aqui." :
                Selected.hide_code != 0 ? "O código está oculto." : "Aguardando código…";
            codeProgress.Fraction = 0;
            copy.Enabled = false;
            reveal.Visible = reveal.Enabled = Selected != null && Selected.hide_code != 0;
            edit.Enabled = delete.Enabled = Selected != null;
        }

        private async Task RefreshCode() {
            var connection = api;
            if (connection == null || working || polling) return;
            DateTime now = DateTime.UtcNow;
            if (activeSession != null && activeSession.ExpiresUtc <= now) {
                HandleVaultError(new VaultException(401));
                return;
            }
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
                otp.Text = FormatCode(value.code);
                remaining.Text = "Renova em " + value.remaining + " s";
                codeProgress.Fraction = value.remaining / (float)Math.Max(1, token.period);
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
            emptyTokens.Visible = entries.Length == 0;
            tokens.Visible = entries.Length != 0;
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
                if (activeSession != null) cache.Clear(activeSession.Token);
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
            return VaultTheme.Label(text, size, bold, VaultTheme.Ink);
        }

        internal static void AddField(TableLayoutPanel panel, string title, Control input) {
            var label = Label(title, 9, true);
            label.Margin = new Padding(0, 5, 0, 2);
            panel.Controls.Add(label);
            input.AccessibleName = title;
            input.Dock = DockStyle.Top;
            input.Margin = new Padding(0, 0, 0, 3);
            var text = input as TextBox;
            if (text != null && !SystemInformation.HighContrast) {
                var field = new RoundedSurface {
                    Radius = 9, Height = 37, Dock = DockStyle.Top, Padding = new Padding(10, 8, 10, 4),
                    Margin = new Padding(0, 0, 0, 4), BackColor = VaultTheme.Surface,
                    FillColor = Color.FromArgb(248, 251, 254)
                };
                text.BackColor = field.FillColor;
                text.ForeColor = VaultTheme.Ink;
                text.BorderStyle = BorderStyle.None;
                text.Enter += (s, e) => { field.LineColor = VaultTheme.Brand; field.Invalidate(); };
                text.Leave += (s, e) => { field.LineColor = VaultTheme.Border; field.Invalidate(); };
                field.Controls.Add(text);
                panel.Controls.Add(field);
            } else {
                panel.Controls.Add(input);
            }
        }

        internal static void SetupButton(Button button, string name, bool primary, bool onDark = false) {
            button.Text = name;
            button.AutoSize = true;
            button.MinimumSize = new Size(75, 36);
            button.Margin = new Padding(0, 3, 8, 3);
            button.Padding = new Padding(10, 0, 10, 0);
            button.BackColor = onDark ? VaultTheme.Navy : VaultTheme.Surface;
            button.ForeColor = onDark ? Color.White : VaultTheme.Ink;
            var rounded = button as RoundedButton;
            if (rounded != null) {
                rounded.Primary = primary;
                rounded.OnDark = onDark;
            }
        }

        private static void ConfigureStatus(Label status) {
            status.Height = 42;
            status.Dock = DockStyle.Top;
            status.Margin = new Padding(0, 2, 0, 0);
            status.TextAlign = ContentAlignment.MiddleLeft;
            status.ForeColor = VaultTheme.Muted;
            status.AutoEllipsis = true;
        }

        private static FlowLayoutPanel ButtonRow() {
            return new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = Padding.Empty, BackColor = Color.Transparent };
        }
    }
}
