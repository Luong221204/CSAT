namespace CSAT;
using System.IO;
using System.Drawing;
using System.Linq.Expressions;
using System.Windows.Forms;
using Encryption;
public partial class Form1 : Form
{
    private Panel headerPanel;
    private Label lblTitle;
    private TextBox txtPath;
    private Button btnSelect;
    private Button btnAction;
    private Label lblStatus;

    public Form1()
    {
        // Cấu hình Form chính
        this.Text = "Két Sắt Dữ Liệu v1.0";
        this.Size = new Size(500, 350);
        this.BackColor = Color.FromArgb(30, 30, 30); // Màu nền tối
        this.FormBorderStyle = FormBorderStyle.FixedDialog;
        this.StartPosition = FormStartPosition.CenterScreen;

        InitCustomUI();
    }

    private void InitCustomUI()
    {
        // 1. Header Panel với Gradient
        headerPanel = new Panel();
        headerPanel.Dock = DockStyle.Top;
        headerPanel.Height = 80;
        headerPanel.BackColor = Color.FromArgb(45, 45, 48);

        lblTitle = new Label();
        lblTitle.Text = "SECURITY FILE VAULT";
        lblTitle.ForeColor = Color.White;
        lblTitle.Font = new Font("Segoe UI", 16, FontStyle.Bold);
        lblTitle.Location = new Point(20, 25);
        lblTitle.AutoSize = true;
        headerPanel.Controls.Add(lblTitle);

        // 2. Ô nhập đường dẫn (Custom looking)
        txtPath = new TextBox();
        txtPath.Location = new Point(30, 120);
        txtPath.Size = new Size(340, 35);
        txtPath.BackColor = Color.FromArgb(60, 60, 60);
        txtPath.ForeColor = Color.White;
        txtPath.BorderStyle = BorderStyle.FixedSingle;
        txtPath.Font = new Font("Segoe UI", 11);
        txtPath.PlaceholderText = " Chọn file cần bảo mật...";

        // 3. Nút Chọn File (Style hiện đại)
        btnSelect = new Button();
        btnSelect.Text = "Duyệt";
        btnSelect.Location = new Point(380, 118);
        btnSelect.Size = new Size(80, 32);
        btnSelect.FlatStyle = FlatStyle.Flat;
        btnSelect.FlatAppearance.BorderSize = 0;
        btnSelect.BackColor = Color.FromArgb(0, 122, 204);
        btnSelect.ForeColor = Color.White;
        btnSelect.Cursor = Cursors.Hand;
        btnSelect.Click += (s, e) => SelectFile();

        // 4. Nút Hành động chính (Mã hóa)
        btnAction = new Button();
        btnAction.Text = "BẮT ĐẦU MÃ HÓA";
        btnAction.Location = new Point(30, 180);
        btnAction.Size = new Size(430, 50);
        btnAction.FlatStyle = FlatStyle.Flat;
        btnAction.Font = new Font("Segoe UI", 12, FontStyle.Bold);
        btnAction.BackColor = Color.FromArgb(37, 160, 67); // Màu xanh lá hiện đại
        btnAction.ForeColor = Color.White;
        btnAction.FlatAppearance.BorderSize = 0;
        btnAction.Cursor = Cursors.Hand;

        // 5. Label trạng thái
        lblStatus = new Label();
        lblStatus.Text = "Trạng thái: Sẵn sàng";
        lblStatus.ForeColor = Color.Gray;
        lblStatus.Location = new Point(30, 250);
        lblStatus.AutoSize = true;

        // Thêm vào Form
        this.Controls.Add(headerPanel);
        this.Controls.Add(txtPath);
        this.Controls.Add(btnSelect);
        this.Controls.Add(btnAction);
        this.Controls.Add(lblStatus);
        InitEvents();
    }

    private void SelectFile()
    {
        using (OpenFileDialog ofd = new OpenFileDialog())
        {
            if (ofd.ShowDialog() == DialogResult.OK)
            {
                txtPath.Text = ofd.FileName;
                lblStatus.Text = "Trạng thái: Đã chọn file";
                lblStatus.ForeColor = Color.LightGreen;
            }
        }
    }

    private void InitEvents()
    {
        btnAction.Click += (s, e) =>
        {
            string input = txtPath.Text; // Lấy đường dẫn file từ TextBox

            if (string.IsNullOrEmpty(input) || !File.Exists(input))
            {
                MessageBox.Show("Vui lòng chọn một file hợp lệ!", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            // Tạo đường dẫn file đầu ra (ví dụ: thêm đuôi .enc)
            string output = input + ".enc";

            // Tạo Key (Trong thực tế, bạn nên lấy từ một ô nhập Password rồi Hash nó)
            // Ở đây dùng tạm 16 byte mẫu cho AES-128
            byte[] key = System.Text.Encoding.UTF8.GetBytes("1234567890123456");

            try
            {
                lblStatus.Text = "Trạng thái: Đang mã hóa...";
                lblStatus.ForeColor = Color.Yellow;
                btnAction.Enabled = false; // Khóa nút để tránh nhấn nhiều lần

                // GỌI HÀM LOGIC CỦA BẠN
                AESFileManual.EncryptFileManual(input, output, key);

                lblStatus.Text = "Trạng thái: Mã hóa thành công!";
                lblStatus.ForeColor = Color.LightGreen;
                MessageBox.Show($"File đã được bảo mật tại:\n{output}", "Thành công");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Lỗi: {ex.Message}", "Thất bại");
                lblStatus.Text = "Trạng thái: Có lỗi xảy ra";
                lblStatus.ForeColor = Color.Red;
            }
            finally
            {
                btnAction.Enabled = true;
            }
        };
    }
}
