using System;
using System.Drawing;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace TotpVault {
    internal sealed class TokenWindow : Form {
        private readonly TextBox name = new TextBox { MaxLength = 255 };
        private readonly TextBox issuer = new TextBox { MaxLength = 255 };
        private readonly TextBox secret = new TextBox { UseSystemPasswordChar = true, MaxLength = 680 };
        private readonly ComboBox algo = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList };
        private readonly ComboBox digits = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList };
        private readonly NumericUpDown period = new NumericUpDown { Minimum = 15, Maximum = 300 };
        private readonly CheckBox hide = new CheckBox { Text = "Ocultar até eu pedir para mostrar", AutoSize = true };
        internal TokenInfo Value { get; private set; }
        internal string Secret { get { return secret.Text.Trim(); } }

        internal TokenWindow(TokenInfo old) {
            Text = old == null ? "Adicionar token" : "Editar token";
            ClientSize = new Size(474, 511);
            VaultTheme.Decorate(this);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterParent;
            MaximizeBox = MinimizeBox = false;
            var stack = VaultWindow.Column(474);
            stack.Dock = DockStyle.Fill;
            stack.Padding = new Padding(24,18,24,18);
            stack.BackColor = VaultTheme.Surface;
            stack.Controls.Add(VaultWindow.Label(Text, 17, true));
            Controls.Add(stack);
            VaultWindow.AddField(stack, "Nome", name);
            VaultWindow.AddField(stack, "Serviço (opcional)", issuer);
            VaultWindow.AddField(stack, old == null ? "Chave Base32" : "Nova chave Base32 (opcional)", secret);
            VaultWindow.AddField(stack, "Algoritmo", algo);
            VaultWindow.AddField(stack, "Dígitos", digits);
            VaultWindow.AddField(stack, "Período (segundos)", period);
            stack.Controls.Add(hide);
            var save = new RoundedButton();
            var cancel = new RoundedButton { DialogResult = DialogResult.Cancel };
            VaultWindow.SetupButton(save, "Salvar", true);
            VaultWindow.SetupButton(cancel, "Cancelar", false);
            var actions = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0,6,0,0) };
            actions.Controls.AddRange(new Control[] { save, cancel });
            stack.Controls.Add(actions);
            AcceptButton = save;
            CancelButton = cancel;
            algo.Items.AddRange(new object[] { "SHA1", "SHA256", "SHA512" });
            digits.Items.AddRange(new object[] { 6, 8, 10 });
            name.Text = old == null ? "" : old.name;
            issuer.Text = old == null ? "" : old.issuer;
            algo.SelectedItem = old == null ? "SHA1" : old.algorithm;
            if (algo.SelectedIndex < 0) algo.SelectedIndex = 0;
            digits.SelectedItem = old == null ? 6 : old.digits;
            if (digits.SelectedIndex < 0) digits.SelectedIndex = 0;
            period.Value = old == null ? 30 : Math.Max(15, Math.Min(300, old.period));
            hide.Checked = old != null && old.hide_code != 0;

            save.Click += (s, e) => {
                string normalized = Regex.Replace(Secret, @"\s+", "").ToUpperInvariant();
                if (string.IsNullOrWhiteSpace(name.Text)
                    || ((old == null || normalized.Length != 0) && !Regex.IsMatch(normalized, @"\A[A-Z2-7]{2,512}={0,6}\z"))) {
                    MessageBox.Show(this, "Informe um nome e uma chave Base32 válida.", Text);
                    return;
                }
                Value = new TokenInfo { id = old == null ? 0 : old.id, name = name.Text.Trim(), issuer = issuer.Text.Trim(),
                    algorithm = (string)algo.SelectedItem, digits = (int)digits.SelectedItem,
                    period = (int)period.Value, hide_code = hide.Checked ? 1 : 0 };
                DialogResult = DialogResult.OK;
            };
        }
    }
}
