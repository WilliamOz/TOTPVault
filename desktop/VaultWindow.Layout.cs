using System;
using System.Drawing;
using System.Windows.Forms;

namespace TotpVault {
    internal sealed partial class VaultWindow {
        private Control loginView;
        private TableLayoutPanel vaultPanel;
        private readonly Label sessionTime = VaultTheme.Label("", 9, false, VaultTheme.Muted);
        private readonly Label tokenHeading = VaultTheme.Label("", 11, false, VaultTheme.Pale);
        private readonly Label emptyTokens = VaultTheme.Label("Você ainda não tem tokens.\nUse Adicionar para cadastrar o primeiro.", 10, false, VaultTheme.Muted);
        private readonly CodeProgress codeProgress = new CodeProgress();

        private void BuildInterface() {
            Text = "TOTPVault";
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(880, 574);
            MinimumSize = new Size(772, 515);
            DoubleBuffered = true;
            VaultTheme.Decorate(this);

            var add = new RoundedButton();
            var signOut = new RoundedButton();
            vaultPanel = BuildDashboard(add, signOut);
            loginView = BuildLogin();
            Controls.Add(vaultPanel);
            Controls.Add(loginView);
            vaultPanel.Hide();
            AcceptButton = login;

            add.Click += async (s, e) => await ChangeToken(null);
            signOut.Click += async (s, e) => await SignOut();
        }

        private Control BuildLogin() {
            var center = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 3, BackColor = VaultTheme.Canvas };
            center.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50f));
            center.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 450f));
            center.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50f));
            center.RowStyles.Add(new RowStyle(SizeType.Percent, 50f));
            center.RowStyles.Add(new RowStyle(SizeType.Absolute, 440));
            center.RowStyles.Add(new RowStyle(SizeType.Percent, 50f));

            var card = new RoundedSurface { Dock = DockStyle.Fill, Padding = new Padding(29, 24, 29, 18), Radius = 22 };
            var form = new TableLayoutPanel { AutoSize = true, Dock = DockStyle.Top, ColumnCount = 1, BackColor = Color.Transparent, Margin = Padding.Empty };
            form.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            form.Controls.Add(Mark(59));
            var name = VaultTheme.Label("TOTPVault", 25, true, VaultTheme.Ink);
            name.Margin = new Padding(0, 7, 0, 1);
            form.Controls.Add(name);
            var description = VaultTheme.Label("Entre com sua conta do Active Directory.", 10, false, VaultTheme.Muted);
            description.Margin = new Padding(0, 0, 0, 18);
            form.Controls.Add(description);
            AddField(form, "Usuário do AD", username);
            AddField(form, "Senha", password);
            var actions = ButtonRow();
            actions.Margin = new Padding(0, 10, 0, 0);
            SetupButton(login, "Entrar", true);
            login.MinimumSize = new Size(108, 40);
            SetupButton(retrySession, "Restaurar sessão", false);
            actions.Controls.AddRange(new Control[] { login, retrySession });
            form.Controls.Add(actions);
            ConfigureStatus(loginStatus);
            loginStatus.ForeColor = VaultTheme.Error;
            form.Controls.Add(loginStatus);
            card.Controls.Add(form);
            center.Controls.Add(card, 1, 1);
            return center;
        }

        private TableLayoutPanel BuildDashboard(Button add, Button signOut) {
            var layout = new TableLayoutPanel {
                ColumnCount = 1, RowCount = 3, Dock = DockStyle.Fill, BackColor = VaultTheme.Canvas,
                Padding = new Padding(26, 17, 26, 12)
            };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 80));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));

            var header = new TableLayoutPanel { ColumnCount = 3, RowCount = 1, Dock = DockStyle.Fill, Margin = Padding.Empty };
            header.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 58));
            header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            var symbol = Mark(48);
            symbol.Anchor = AnchorStyles.Left;
            header.Controls.Add(symbol, 0, 0);
            var profile = new FlowLayoutPanel {
                Dock = DockStyle.Fill, Padding = new Padding(4, 5, 0, 0), Margin = Padding.Empty,
                FlowDirection = FlowDirection.TopDown, WrapContents = false
            };
            profile.Controls.Add(VaultTheme.Label("TOTPVault", 17, true, VaultTheme.Ink));
            account.Font = new Font("Segoe UI", 9f, FontStyle.Bold);
            account.AutoSize = true;
            account.ForeColor = VaultTheme.Ink;
            account.Margin = new Padding(0,0,10,0);
            var accountLine = ButtonRow();
            accountLine.Controls.AddRange(new Control[] { account, sessionTime });
            profile.Controls.Add(accountLine);
            header.Controls.Add(profile, 1, 0);
            var sessionActions = ButtonRow();
            sessionActions.Anchor = AnchorStyles.Right;
            SetupButton(admin, "Usuários", false);
            SetupButton(signOut, "Sair", false);
            admin.BackColor = signOut.BackColor = VaultTheme.Canvas;
            sessionActions.Controls.AddRange(new Control[] { admin, signOut });
            header.Controls.Add(sessionActions, 2, 0);
            layout.Controls.Add(header, 0, 0);

            var workspace = new TableLayoutPanel { ColumnCount = 2, RowCount = 1, Dock = DockStyle.Fill, Margin = Padding.Empty };
            workspace.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 48));
            workspace.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 52));
            workspace.Controls.Add(BuildTokens(add), 0, 0);
            workspace.Controls.Add(BuildCode(), 1, 0);
            layout.Controls.Add(workspace, 0, 1);
            ConfigureStatus(vaultStatus);
            vaultStatus.ForeColor = VaultTheme.Muted;
            layout.Controls.Add(vaultStatus, 0, 2);
            return layout;
        }

        private Control BuildTokens(Button add) {
            var panel = new RoundedSurface { Dock = DockStyle.Fill, Padding = new Padding(19, 15, 17, 15), Margin = new Padding(0, 0, 10, 0) };
            var grid = new TableLayoutPanel {
                ColumnCount = 1, RowCount = 3, Dock = DockStyle.Fill, BackColor = Color.Transparent, Margin = Padding.Empty
            };
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            grid.RowStyles.Add(new RowStyle(SizeType.Absolute, 49));
            grid.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            grid.RowStyles.Add(new RowStyle(SizeType.Absolute, 49));
            var head = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Color.Transparent, Margin = Padding.Empty };
            head.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            head.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            var title = VaultTheme.Label("Meus tokens", 17, true, VaultTheme.Ink);
            title.Anchor = AnchorStyles.Left;
            head.Controls.Add(title, 0, 0);
            SetupButton(add, "Adicionar", false);
            add.Anchor = AnchorStyles.Right;
            add.Margin = Padding.Empty;
            head.Controls.Add(add, 1, 0);
            grid.Controls.Add(head, 0, 0);

            var listPanel = new Panel { Dock = DockStyle.Fill, BackColor = VaultTheme.Surface, Margin = new Padding(0, 5, 0, 9) };
            tokens.Dock = DockStyle.Fill;
            tokens.AccessibleName = "Tokens do usuário";
            emptyTokens.AutoSize = false;
            emptyTokens.Dock = DockStyle.Fill;
            emptyTokens.TextAlign = ContentAlignment.MiddleCenter;
            listPanel.Controls.Add(tokens);
            listPanel.Controls.Add(emptyTokens);
            grid.Controls.Add(listPanel, 0, 1);

            SetupButton(edit, "Editar", false);
            SetupButton(delete, "Excluir", false);
            var buttons = ButtonRow();
            buttons.Anchor = AnchorStyles.Left;
            buttons.Controls.AddRange(new Control[] { edit, delete });
            grid.Controls.Add(buttons, 0, 2);
            panel.Controls.Add(grid);
            return panel;
        }

        private Control BuildCode() {
            var panel = new RoundedSurface {
                Dock = DockStyle.Fill, Padding = new Padding(25, 23, 25, 18), Margin = new Padding(10, 0, 0, 0),
                FillColor = VaultTheme.Navy, LineColor = VaultTheme.Navy
            };
            var grid = new TableLayoutPanel {
                ColumnCount = 1, RowCount = 8, Dock = DockStyle.Fill, BackColor = VaultTheme.Navy, Margin = Padding.Empty
            };
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            grid.RowStyles.Add(new RowStyle(SizeType.Absolute, 41));
            grid.RowStyles.Add(new RowStyle(SizeType.Absolute, 37));
            grid.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
            grid.RowStyles.Add(new RowStyle(SizeType.Absolute, 71));
            grid.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            grid.RowStyles.Add(new RowStyle(SizeType.Absolute, 13));
            grid.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
            grid.RowStyles.Add(new RowStyle(SizeType.Absolute, 54));
            grid.Controls.Add(VaultTheme.Label("Código atual", 19, true, VaultTheme.OnNavy), 0, 0);
            tokenHeading.AutoSize = false;
            tokenHeading.Dock = DockStyle.Fill;
            tokenHeading.AutoEllipsis = true;
            tokenHeading.Text = "Selecione um token";
            grid.Controls.Add(tokenHeading, 0, 1);
            otp.BackColor = VaultTheme.Navy;
            otp.Text = "—";
            otp.ForeColor = VaultTheme.OnNavy;
            otp.Font = new Font("Consolas", 34, FontStyle.Bold);
            otp.Dock = DockStyle.Fill;
            otp.Margin = Padding.Empty;
            grid.Controls.Add(otp, 0, 3);
            remaining.Dock = DockStyle.Fill;
            remaining.BackColor = VaultTheme.Navy;
            remaining.Font = new Font("Segoe UI", 9f);
            remaining.ForeColor = VaultTheme.Pale;
            remaining.Text = "Seu código aparecerá aqui.";
            remaining.Margin = new Padding(0, 5, 0, 0);
            grid.Controls.Add(remaining, 0, 4);
            codeProgress.Dock = DockStyle.Top;
            codeProgress.BackColor = VaultTheme.Navy;
            codeProgress.Margin = new Padding(0, 2, 0, 0);
            grid.Controls.Add(codeProgress, 0, 5);
            SetupButton(copy, "Copiar código", true, true);
            SetupButton(reveal, "Mostrar código", false, true);
            copy.Enabled = reveal.Enabled = false;
            reveal.Visible = false;
            var buttons = ButtonRow();
            buttons.Anchor = AnchorStyles.Left | AnchorStyles.Bottom;
            buttons.Controls.AddRange(new Control[] { copy, reveal });
            grid.Controls.Add(buttons, 0, 7);
            panel.Controls.Add(grid);
            return panel;
        }

        private static PictureBox Mark(int size) {
            return new PictureBox { Image = VaultTheme.Mark, Size = new Size(size, size),
                SizeMode = PictureBoxSizeMode.Zoom, Margin = Padding.Empty, BackColor = Color.Transparent, TabStop = false };
        }

        private static string FormatCode(string value) {
            if (string.IsNullOrEmpty(value)) return "—";
            return value.Length == 6 || value.Length == 8 || value.Length == 10
                ? value.Insert(value.Length / 2, " ") : value;
        }
    }
}
