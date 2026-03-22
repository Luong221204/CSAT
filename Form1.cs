namespace CSAT;

using System.IO;
using System.Drawing;
using System.Linq.Expressions;
using System.Windows.Forms;
using Encryption;
using Decryption;
using CSAT.Network.Sender;
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

        //InitCustomUI();
        SetupTabs();
    }
    private void SetupTabs()
{
    TabControl tabControl = new TabControl { Dock = DockStyle.Fill };
    
    // --- TAB GỬI FILE ---
    TabPage tabSend = new TabPage("Gửi File (Client)");
    Label lblIP = new Label { Text = "IP Máy Nhận:", Top = 20, Left = 20 };
    TextBox txtIP = new TextBox { Name = "txtIP", Text = "127.0.0.1", Top = 20, Left = 120, Width = 150 };
    
    Button btnBrowse = new Button { Text = "Chọn File", Top = 60, Left = 20 };
    TextBox txtPath = new TextBox { Name = "txtPath", Top = 60, Left = 120, Width = 250, ReadOnly = true };
    
    Button btnSend = new Button { Name = "btnSend", Text = "MÃ HÓA & GỬI", Top = 120, Left = 120, Width = 150, Height = 40, BackColor = Color.LightBlue };
    
    tabSend.Controls.AddRange(new Control[] { lblIP, txtIP, btnBrowse, txtPath, btnSend });

    // --- TAB NHẬN FILE ---
    TabPage tabReceive = new TabPage("Nhận File (Server)");
    Label lblPort = new Label { Text = "Cổng (Port):", Top = 20, Left = 20 };
    TextBox txtPort = new TextBox { Name = "txtPort", Text = "5000", Top = 20, Left = 120, Width = 80 };
    
    Button btnStartServer = new Button { Name = "btnStartServer", Text = "BẬT SERVER", Top = 60, Left = 20, Width = 100 };
    ListBox lstLog = new ListBox { Name = "lstLog", Top = 100, Left = 20, Width = 350, Height = 150 };
    
    tabReceive.Controls.AddRange(new Control[] { lblPort, txtPort, btnStartServer, lstLog });

    // Thêm các tab vào Control chính
    tabControl.TabPages.Add(tabSend);
    tabControl.TabPages.Add(tabReceive);
    this.Controls.Add(tabControl);
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

    private async void InitEvents()
    {
        btnAction.Click += async (s, e) =>
        {
            string ip = "127.0.0.1"; // Ví dụ: 127.0.0.1
            int port = 5000;
            //string input = txtPath.Text; // Lấy đường dẫn file từ TextBox
            string input = "D:\\Documents\\banro_ma.txt";
            Console.WriteLine("--- Bat dau qua trinh ma hoa ---");
            Console.WriteLine("Duong dan file: ");
            if (string.IsNullOrEmpty(input) || !File.Exists(input))
            {
                MessageBox.Show("Vui lòng chọn một file hợp lệ!", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            string directory = Path.GetDirectoryName(input);
            string fileName = Path.GetFileNameWithoutExtension(input);
            string extension = Path.GetExtension(input);

            string output = Path.Combine(directory, fileName + "_ma" + extension);
            // Tạo Key (Trong thực tế, bạn nên lấy từ một ô nhập Password rồi Hash nó)
            // Ở đây dùng tạm 16 byte mẫu cho AES-128
            byte[] key = System.Text.Encoding.UTF8.GetBytes("1234567890123456");

            try
            {
                lblStatus.Text = "Trạng thái: Đang mã hóa...";
                lblStatus.ForeColor = Color.Yellow;
                btnAction.Enabled = false; // Khóa nút để tránh nhấn nhiều lần

                // GỌI HÀM LOGIC CỦA BẠN
                byte[] encryptedData = AESFileManual.EncryptFileManual(input, output, key);

                lblStatus.Text = "Trạng thái: Mã hóa thành công!";
                lblStatus.ForeColor = Color.LightGreen;
                FileSender senderService = new FileSender();
                await senderService.SendFileAsync(ip, port, input, encryptedData);

                MessageBox.Show("Gửi file thành công rực rỡ!");
                // MessageBox.Show($"File đã được bảo mật tại:\n{output}", "Thành công");
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
