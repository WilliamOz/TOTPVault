using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Windows.Forms;

namespace TotpVault {
    internal static class VaultTheme {
        internal static readonly Color Canvas = SystemInformation.HighContrast ? SystemColors.Window : Color.FromArgb(240, 245, 250);
        internal static readonly Color Surface = SystemInformation.HighContrast ? SystemColors.Window : Color.White;
        internal static readonly Color Ink = SystemInformation.HighContrast ? SystemColors.WindowText : Color.FromArgb(16, 33, 57);
        internal static readonly Color Muted = SystemInformation.HighContrast ? SystemColors.WindowText : Color.FromArgb(72, 91, 117);
        internal static readonly Color Border = Color.FromArgb(203, 216, 232);
        internal static readonly Color Brand = Color.FromArgb(60, 54, 172);
        internal static readonly Color BrandHover = Color.FromArgb(49, 43, 150);
        internal static readonly Color Selected = Color.FromArgb(230, 239, 255);
        internal static readonly Color Navy = SystemInformation.HighContrast ? SystemColors.Window : Color.FromArgb(12, 28, 52);
        internal static readonly Color OnNavy = SystemInformation.HighContrast ? SystemColors.WindowText : Color.White;
        internal static readonly Color Pale = SystemInformation.HighContrast ? SystemColors.WindowText : Color.FromArgb(184, 204, 231);
        internal static readonly Color Cyan = Color.FromArgb(64, 225, 246);
        internal static readonly Color Error = SystemInformation.HighContrast ? SystemColors.WindowText : Color.FromArgb(142, 44, 58);
        internal static readonly Font TextFont = new Font("Segoe UI", 10f);
        internal static readonly Image Mark = LoadMark();
        internal static readonly Icon AppIcon = Icon.ExtractAssociatedIcon(typeof(VaultTheme).Assembly.Location);

        private static Image LoadMark() {
            using (Stream source = typeof(VaultTheme).Assembly.GetManifestResourceStream("TotpVault.Brand.png")) {
                if (source == null) return null;
                using (var image = Image.FromStream(source)) return new Bitmap(image);
            }
        }

        internal static void Decorate(Form form) {
            form.AutoScaleDimensions = new SizeF(96, 96);
            form.AutoScaleMode = AutoScaleMode.Dpi;
            form.BackColor = Canvas;
            form.ForeColor = Ink;
            form.Font = TextFont;
            if (AppIcon != null) form.Icon = AppIcon;
        }

        internal static Label Label(string text, float size, bool bold, Color color) {
            return new Label {
                Text = text, AutoSize = true, BackColor = Color.Transparent, ForeColor = color,
                Font = new Font("Segoe UI", size, bold ? FontStyle.Bold : FontStyle.Regular),
                Margin = new Padding(0, 0, 0, 5)
            };
        }

        internal static GraphicsPath Rounded(RectangleF bounds, float radius) {
            var path = new GraphicsPath();
            float diameter = Math.Min(radius * 2, Math.Min(bounds.Width, bounds.Height));
            if (diameter <= 0) return path;
            path.AddArc(bounds.X, bounds.Y, diameter, diameter, 180, 90);
            path.AddArc(bounds.Right - diameter, bounds.Y, diameter, diameter, 270, 90);
            path.AddArc(bounds.Right - diameter, bounds.Bottom - diameter, diameter, diameter, 0, 90);
            path.AddArc(bounds.X, bounds.Bottom - diameter, diameter, diameter, 90, 90);
            path.CloseFigure();
            return path;
        }
    }

    internal sealed class RoundedSurface : Panel {
        internal Color FillColor = VaultTheme.Surface;
        internal Color LineColor = VaultTheme.Border;
        internal int Radius = 18;

        internal RoundedSurface() {
            DoubleBuffered = true;
            BackColor = VaultTheme.Canvas;
        }

        protected override void OnPaint(PaintEventArgs e) {
            base.OnPaint(e);
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            using (var shape = VaultTheme.Rounded(new RectangleF(.5f, .5f, Width - 1f, Height - 1f), Radius * DeviceDpi / 96f))
            using (var brush = new SolidBrush(SystemInformation.HighContrast ? SystemColors.Window : FillColor))
            using (var pen = new Pen(SystemInformation.HighContrast ? SystemColors.WindowText : LineColor)) {
                e.Graphics.FillPath(brush, shape);
                e.Graphics.DrawPath(pen, shape);
            }
        }
    }

    internal sealed class RoundedButton : Button {
        internal bool Primary;
        internal bool OnDark;
        private bool hover, pressed;

        internal RoundedButton() {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer, true);
            FlatStyle = FlatStyle.Flat;
            FlatAppearance.BorderSize = 0;
            UseVisualStyleBackColor = false;
            Cursor = Cursors.Hand;
        }

        protected override void OnMouseEnter(EventArgs e) { base.OnMouseEnter(e); hover = true; Invalidate(); }
        protected override void OnMouseLeave(EventArgs e) { base.OnMouseLeave(e); hover = pressed = false; Invalidate(); }
        protected override void OnMouseDown(MouseEventArgs e) { base.OnMouseDown(e); if (e.Button == MouseButtons.Left) pressed = true; Invalidate(); }
        protected override void OnMouseUp(MouseEventArgs e) { base.OnMouseUp(e); pressed = false; Invalidate(); }
        protected override void OnGotFocus(EventArgs e) { base.OnGotFocus(e); Invalidate(); }
        protected override void OnLostFocus(EventArgs e) { base.OnLostFocus(e); Invalidate(); }
        protected override void OnEnabledChanged(EventArgs e) { base.OnEnabledChanged(e); Invalidate(); }

        protected override void OnPaint(PaintEventArgs e) {
            if (SystemInformation.HighContrast) {
                TextRenderer.DrawText(e.Graphics, Text, Font, ClientRectangle,
                    Enabled ? SystemColors.ControlText : SystemColors.GrayText,
                    SystemColors.Control, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix);
                ControlPaint.DrawBorder(e.Graphics, ClientRectangle, SystemColors.ControlText, ButtonBorderStyle.Solid);
                if (Focused) ControlPaint.DrawFocusRectangle(e.Graphics, Rectangle.Inflate(ClientRectangle, -3, -3));
                return;
            }
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            bool active = pressed || hover;
            Color fill = Primary
                ? (OnDark ? (active ? Color.FromArgb(134, 240, 251) : VaultTheme.Cyan) : (active ? VaultTheme.BrandHover : VaultTheme.Brand))
                : (OnDark ? (active ? Color.FromArgb(38, 68, 105) : Color.FromArgb(25, 50, 84)) : (active ? VaultTheme.Selected : VaultTheme.Surface));
            Color ink = Primary && !OnDark ? Color.White : OnDark && !Primary ? Color.White : VaultTheme.Ink;
            Color line = Primary ? fill : OnDark ? Color.FromArgb(77, 110, 148) : VaultTheme.Border;
            if (!Enabled) {
                fill = OnDark ? Color.FromArgb(36, 59, 88) : Color.FromArgb(232, 238, 246);
                ink = OnDark ? VaultTheme.Pale : VaultTheme.Muted;
                line = fill;
            }
            using (var path = VaultTheme.Rounded(new RectangleF(.5f,.5f,Width-1,Height-1), 10 * DeviceDpi / 96f))
            using (var background = new SolidBrush(fill))
            using (var stroke = new Pen(line)) {
                e.Graphics.FillPath(background, path);
                e.Graphics.DrawPath(stroke, path);
            }
            TextRenderer.DrawText(e.Graphics, Text, Font, ClientRectangle, ink,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
            if (Focused && Enabled) {
                using (var path = VaultTheme.Rounded(new RectangleF(3,3,Width-6,Height-6), 7 * DeviceDpi / 96f))
                using (var stroke = new Pen(OnDark && !Primary || Primary && !OnDark ? VaultTheme.Cyan : VaultTheme.Brand, 1.4f)) {
                    stroke.DashStyle = DashStyle.Dot;
                    e.Graphics.DrawPath(stroke, path);
                }
            }
        }
    }

    internal sealed class VaultTokenList : ListBox {
        private readonly Font titleFont = new Font("Segoe UI", 10f, FontStyle.Bold);
        private readonly Font detailFont = new Font("Segoe UI", 9f);
        internal VaultTokenList() {
            DisplayMember = "Title";
            IntegralHeight = false;
            DrawMode = DrawMode.OwnerDrawFixed;
            ItemHeight = 58;
            BorderStyle = BorderStyle.None;
            BackColor = VaultTheme.Surface;
            ForeColor = VaultTheme.Ink;
        }

        protected override void OnDrawItem(DrawItemEventArgs e) {
            if (e.Index < 0 || e.Index >= Items.Count) return;
            var token = Items[e.Index] as TokenInfo;
            if (token == null) return;
            bool selected = (e.State & DrawItemState.Selected) != 0;
            Color fill = selected ? VaultTheme.Selected : VaultTheme.Surface;
            if (SystemInformation.HighContrast) fill = selected ? SystemColors.Highlight : SystemColors.Window;
            Color ink = SystemInformation.HighContrast ? (selected ? SystemColors.HighlightText : SystemColors.WindowText) : VaultTheme.Ink;
            Color muted = SystemInformation.HighContrast ? ink : VaultTheme.Muted;
            float scale = DeviceDpi / 96f;
            int margin = (int)(12 * scale);
            using (var paper = new SolidBrush(SystemInformation.HighContrast ? SystemColors.Window : VaultTheme.Surface))
                e.Graphics.FillRectangle(paper, e.Bounds);
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            var item = Rectangle.Inflate(e.Bounds, -2, -2);
            using (var round = VaultTheme.Rounded(item, 9 * scale))
            using (var background = new SolidBrush(fill)) {
                e.Graphics.FillPath(background, round);
            }
            var text = Rectangle.Inflate(e.Bounds, -margin, 0);
            var flags = TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine | TextFormatFlags.VerticalCenter;
            if (string.IsNullOrEmpty(token.issuer)) {
                TextRenderer.DrawText(e.Graphics, token.name ?? "", titleFont, text, ink, flags);
            } else {
                text.Y += (int)(6 * scale);
                text.Height = e.Bounds.Height / 2;
                TextRenderer.DrawText(e.Graphics, token.name ?? "", titleFont, text, ink, flags);
                text.Y = e.Bounds.Top + e.Bounds.Height / 2 - 1;
                TextRenderer.DrawText(e.Graphics, token.issuer, detailFont, text, muted, flags);
            }
            if (Focused && selected) ControlPaint.DrawFocusRectangle(e.Graphics, Rectangle.Inflate(item,-2,-2), ink, fill);
        }

        protected override void Dispose(bool disposing) {
            if (disposing) {
                titleFont.Dispose();
                detailFont.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    internal sealed class CodeProgress : Control {
        private float fraction;
        internal CodeProgress() { DoubleBuffered = true; Height = 6; TabStop = false; }
        internal float Fraction {
            set {
                var bounded = Math.Max(0f, Math.Min(1f, value));
                if (bounded == fraction) return;
                fraction = bounded;
                Invalidate();
            }
        }
        protected override void OnPaint(PaintEventArgs e) {
            if (Width <= 0 || Height <= 0) return;
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            using (var path = VaultTheme.Rounded(new RectangleF(0,0,Width,Height), Height / 2f))
            using (var track = new SolidBrush(SystemInformation.HighContrast ? SystemColors.GrayText : Color.FromArgb(49, 70, 101)))
            using (var current = new SolidBrush(SystemInformation.HighContrast ? SystemColors.Highlight : VaultTheme.Cyan)) {
                e.Graphics.FillPath(track,path);
                if (fraction > 0) {
                    var state = e.Graphics.Save();
                    e.Graphics.SetClip(path);
                    e.Graphics.FillRectangle(current, new RectangleF(0,0,Width * fraction,Height));
                    e.Graphics.Restore(state);
                }
            }
        }
    }
}
