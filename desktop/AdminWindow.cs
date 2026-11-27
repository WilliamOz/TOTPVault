using System;
using System.Drawing;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace TotpVault {
    internal sealed class AdminWindow : Form {
        private readonly VaultApi api;
        private readonly Action<Exception> onError;
        private readonly ListView users = new ListView {
            View = View.Details, FullRowSelect = true, MultiSelect = false, Dock = DockStyle.Fill
        };
        private readonly Label status = new Label { AutoSize = true };
        private readonly Button change = new RoundedButton { Enabled = false };
        private bool busy;

        internal AdminWindow(VaultApi api, Action<Exception> onError) {
            this.api = api;
            this.onError = onError;
            Text = "Administrar usuários do TOTPVault";
            ClientSize = new Size(665, 410);
            MinimumSize = new Size(540, 285);
            StartPosition = FormStartPosition.CenterParent;
            VaultTheme.Decorate(this);
            var panel = new TableLayoutPanel { ColumnCount = 1, RowCount = 4, Dock = DockStyle.Fill, Padding = new Padding(18) };
            panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            panel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            panel.Controls.Add(VaultWindow.Label("Usuários do cofre", 18, true));
            users.BackColor = VaultTheme.Surface;
            users.ForeColor = VaultTheme.Ink;
            users.BorderStyle = BorderStyle.None;
            users.HideSelection = false;
            users.Columns.Add("Nome", 245);
            users.Columns.Add("Usuário do AD", 175);
            users.Columns.Add("Acesso", 175);
            panel.Controls.Add(users);
            var row = new FlowLayoutPanel { AutoSize = true, WrapContents = false };
            var reload = new RoundedButton();
            VaultWindow.SetupButton(change, "Desabilitar", true);
            VaultWindow.SetupButton(reload, "Atualizar lista", false);
            change.BackColor = reload.BackColor = VaultTheme.Canvas;
            row.Controls.AddRange(new Control[] { change, reload });
            panel.Controls.Add(row);
            panel.Controls.Add(status);
            Controls.Add(panel);

            users.SelectedIndexChanged += (s, e) => SetAction();
            Shown += async (s, e) => await RefreshList(null);
            reload.Click += async (s, e) => await RefreshList(null);
            change.Click += async (s, e) => {
                var account = Selected();
                if (account == null || account.self || busy) return;
                string verb = account.disabled ? "Reabilitar" : "Desabilitar";
                if (MessageBox.Show(this, verb + " o acesso de " + account.username + " ao cofre?", Text,
                    MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
                busy = true;
                SetAction();
                try {
                    await api.SetDisabled(account.id, !account.disabled);
                    if (IsDisposed) return;
                    status.Text = "Acesso atualizado.";
                } catch (Exception error) {
                    Report(error);
                } finally { busy = false; }
                if (!IsDisposed) await RefreshList(account.id);
            };
        }

        private AccountInfo Selected() {
            return users.SelectedItems.Count == 1 ? (AccountInfo)users.SelectedItems[0].Tag : null;
        }

        private void SetAction() {
            if (IsDisposed) return;
            var account = Selected();
            change.Enabled = !busy && account != null && !account.self;
            change.Text = account != null && account.disabled ? "Reabilitar" : "Desabilitar";
        }

        private async Task RefreshList(int? selection) {
            if (busy || IsDisposed) return;
            busy = true;
            SetAction();
            try {
                var accounts = await api.ListAccounts();
                if (IsDisposed) return;
                users.BeginUpdate();
                try {
                    users.Items.Clear();
                    foreach (var account in accounts) {
                        var item = new ListViewItem(new[] { account.name, account.username,
                            account.self ? "Sua conta" : account.disabled ? "Desabilitado" : "Habilitado" });
                        item.Tag = account;
                        users.Items.Add(item);
                        if (selection == account.id) item.Selected = true;
                    }
                } finally { users.EndUpdate(); }
            } catch (Exception error) {
                Report(error);
            } finally {
                busy = false;
                SetAction();
            }
        }

        private void Report(Exception error) {
            if (IsDisposed) return;
            var state = error as VaultException;
            if (state != null && (state.Status == 401 || state.Status == 403)) {
                onError(error);
                Close();
            } else {
                status.Text = "Não foi possível atualizar o acesso agora.";
            }
        }
    }
}
