namespace CSAT;

using System.IO;
using System.Drawing;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.Text;
using System.Net.Sockets;
using System.Net;
using Encryption;
using Decryption;
public partial class Form1 : Form
{
    private TabControl tabControl;
    private TabPage tabClient, tabServer;

    // Controls cho Tab Client
    private TextBox txtFilePath, txtKey, txtClientLog, txtKeyServer;
    private Button btnBrowse, btnEncryptAndSend;
    private Label lblClientStatus;

    // Controls cho Tab Server
    private TextBox txtEncryptedReceived, txtDecryptedResult;
    private Label lblServerStatus;
    private Button btnStartServer, btnStopServer;

    private TcpListener serverListener;
    private bool isServerRunning = false;
    private CancellationTokenSource cancellationTokenSource;

    private RadioButton rdoECB_Client, rdoCBC_Client;
    private RadioButton rdoECB_Server, rdoCBC_Server;
    public Form1()
    {
        this.Text = "AES File Transfer - Client/Server";
        this.Size = new Size(700, 650);
        this.BackColor = Color.White;
        this.FormBorderStyle = FormBorderStyle.FixedSingle;
        this.StartPosition = FormStartPosition.CenterScreen;
        this.MaximizeBox = false;

        SetupUI();
    }

    private void SetupUI()
    {
        // ==========================================
        // THIẾT KẾ TAB CLIENT
        // ==========================================
        tabControl = new TabControl { Dock = DockStyle.Fill, Font = new Font("Segoe UI", 10) };
        tabClient = new TabPage("📤 Client - Gửi File");
        tabServer = new TabPage("📥 Server - Nhận File");

        // --- TAB CLIENT ---
        Label lblFile = new Label { Text = "Chọn file:", Top = 20, Left = 20, Font = new Font("Segoe UI", 10, FontStyle.Bold) };
        txtFilePath = new TextBox { Top = 20, Left = 120, Width = 420, ReadOnly = true, BackColor = Color.WhiteSmoke };
        btnBrowse = new Button { Text = "Duyệt...", Top = 18, Left = 550, Width = 100, Height = 40 };
        btnBrowse.Click += (s, e) => SelectFile();

        Label lblKey = new Label { Text = "Key :", Top = 60, Left = 20, Font = new Font("Segoe UI", 10, FontStyle.Bold) };
        txtKey = new TextBox
        {
            Top = 60,
            Left = 120,
            Width = 420,
            Text = "1234567890123456",
            BackColor = Color.WhiteSmoke
        };
        Label lblModeClient = new Label
        {
            Text = "Mode:",
            Top = 170,
            Left = 20,
            Font = new Font("Segoe UI", 10, FontStyle.Bold)
        };

        rdoECB_Client = new RadioButton
        {
            Text = "ECB",
            Top = 170,
            Left = 120
        };

        rdoCBC_Client = new RadioButton
        {
            Text = "CBC",
            Top = 170,
            Left = 300,
            Checked = true // mặc định CBC
        };
        Label lblServerIP = new Label { Text = "Server IP:", Top = 100, Left = 20, Font = new Font("Segoe UI", 10, FontStyle.Bold) };
        TextBox txtServerIP = new TextBox
        {
            Top = 100,
            Left = 120,
            Width = 420,
            Text = "192.168.1.122",
            BackColor = Color.WhiteSmoke
        };

        Label lblServerPort = new Label { Text = "Server Port:", Top = 140, Left = 20, Font = new Font("Segoe UI", 10, FontStyle.Bold) };
        TextBox txtServerPort = new TextBox
        {
            Top = 140,
            Left = 120,
            Width = 420,
            Text = "5000",
            BackColor = Color.WhiteSmoke
        };

        btnEncryptAndSend = new Button
        {
            Text = "🔒 MÃ HÓA & GỬI FILE",
            Top = 210,
            Left = 120,
            Width = 420,
            Height = 50,
            BackColor = Color.FromArgb(50, 150, 250),
            ForeColor = Color.White,
            Font = new Font("Segoe UI", 11, FontStyle.Bold),
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand
        };
        btnEncryptAndSend.Click += async (s, e) => await EncryptAndSendFile(txtServerIP.Text, txtServerPort.Text, txtKey.Text);

        lblClientStatus = new Label { Text = "Trạng thái: Sẵn sàng", Top = 270, Left = 20, Width = 500, ForeColor = Color.Green, Font = new Font("Segoe UI", 9) };

        Label lblLog = new Label { Text = "📋 Log:", Top = 300, Left = 20, Font = new Font("Segoe UI", 10, FontStyle.Bold) };
        txtClientLog = new TextBox
        {
            Top = 320,
            Left = 20,
            Width = 630,
            Height = 230,
            Multiline = true,
            ScrollBars = ScrollBars.Vertical,
            ReadOnly = true,
            BackColor = Color.Black,
            ForeColor = Color.Lime,
            Font = new Font("Courier New", 9)
        };

        tabClient.Controls.AddRange(new Control[] {
            lblFile, txtFilePath, btnBrowse,
            lblKey, txtKey,
            lblServerIP, txtServerIP,
            lblServerPort, txtServerPort,
            btnEncryptAndSend,
            lblClientStatus,
            lblModeClient, rdoECB_Client, rdoCBC_Client,

            lblLog, txtClientLog
        });

        // --- TAB SERVER ---
        lblServerStatus = new Label
        {
            Text = "🔴 Server: Dừng",
            Top = 20,
            Left = 20,
            Width = 300,
            ForeColor = Color.Red,
            Font = new Font("Segoe UI", 11, FontStyle.Bold)
        };
        Label lblKeyServer = new Label { Text = "Key:", Top = 60, Left = 20, Font = new Font("Segoe UI", 10, FontStyle.Bold) };
        txtKeyServer = new TextBox
        {
            Top = 60,
            Left = 120,
            Width = 420,
            Text = "1234567890123456",
            BackColor = Color.WhiteSmoke
        };
        Label lblPort = new Label { Text = "Port:", Top = 20, Left = 450, Font = new Font("Segoe UI", 10, FontStyle.Bold) };
        TextBox txtPort = new TextBox
        {
            Top = 20,
            Left = 560,
            Width = 80,
            Text = "5000",
            BackColor = Color.WhiteSmoke
        };
        Label lblModeServer = new Label
        {
            Text = "Mode:",
            Top = 100,
            Left = 20,
            Font = new Font("Segoe UI", 10, FontStyle.Bold)
        };

        rdoECB_Server = new RadioButton
        {
            Text = "ECB",
            Top = 100,
            Left = 120
        };

        rdoCBC_Server = new RadioButton
        {
            Text = "CBC",
            Top = 100,
            Left = 300,
            Checked = true
        };
        btnStartServer = new Button
        {
            Text = "▶ BẬT SERVER",
            Top = 140,
            Left = 20,
            Width = 150,
            Height = 40,
            BackColor = Color.FromArgb(50, 200, 50),
            ForeColor = Color.White,
            Font = new Font("Segoe UI", 10, FontStyle.Bold),
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand
        };
        btnStartServer.Click += (s, e) => StartServer(txtPort.Text);

        btnStopServer = new Button
        {
            Text = "⏹ DỪNG SERVER",
            Top = 140,
            Left = 180,
            Width = 150,
            Height = 40,
            BackColor = Color.FromArgb(200, 50, 50),
            ForeColor = Color.White,
            Font = new Font("Segoe UI", 10, FontStyle.Bold),
            FlatStyle = FlatStyle.Flat,
            Cursor = Cursors.Hand,
            Enabled = false
        };
        btnStopServer.Click += (s, e) => StopServer();

        Label lblEnc = new Label { Text = "🔐 Dữ liệu mã hóa nhận được (Hex):", Top = 180, Left = 20, Font = new Font("Segoe UI", 10, FontStyle.Bold) };
        txtEncryptedReceived = new TextBox
        {
            Top = 215,
            Left = 20,
            Width = 630,
            Height = 150,
            Multiline = true,
            ScrollBars = ScrollBars.Vertical,
            ReadOnly = true,
            BackColor = Color.Black,
            ForeColor = Color.Lime,
            Font = new Font("Courier New", 9)
        };

        Label lblDec = new Label { Text = "✅ Nội dung sau khi giải mã:", Top = 375, Left = 20, Font = new Font("Segoe UI", 10, FontStyle.Bold) };
        txtDecryptedResult = new TextBox
        {
            Top = 400,
            Left = 20,
            Width = 630,
            Height = 180,
            Multiline = true,
            ScrollBars = ScrollBars.Vertical,
            ReadOnly = true,
            BackColor = Color.WhiteSmoke,
            Font = new Font("Segoe UI", 9)
        };

        tabServer.Controls.AddRange(new Control[] {
            lblServerStatus,
            lblPort, txtPort,
            lblKeyServer, txtKeyServer,
            btnStartServer, btnStopServer,
            lblEnc, txtEncryptedReceived,
            lblDec, txtDecryptedResult,
                lblModeServer, rdoECB_Server, rdoCBC_Server

        });

        // Thêm tab vào control chính
        tabControl.TabPages.Add(tabClient);
        tabControl.TabPages.Add(tabServer);
        this.Controls.Add(tabControl);
    }

    private void SelectFile()
    {
        try
        {
            using (OpenFileDialog ofd = new OpenFileDialog())
            {
                ofd.Title = "Chọn file cần mã hóa";
                ofd.Filter = "Tất cả file|*.*|File text|*.txt|File image|*.jpg;*.png;*.bmp";
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    txtFilePath.Text = ofd.FileName;
                    Log($"✓ Đã chọn file: {Path.GetFileName(ofd.FileName)}");
                }
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Lỗi khi chọn file: {ex.Message}", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
            Log($"❌ Lỗi chọn file: {ex.Message}");
        }
    }

    private async Task EncryptAndSendFile(string serverIP, string portStr, string key)
    {
        try
        {
            if (string.IsNullOrEmpty(txtFilePath.Text))
            {
                MessageBox.Show("Vui lòng chọn file!", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            /*if (key.Length != 16)
            {
                MessageBox.Show("Key phải là 16 ký tự cho AES-128!", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }*/

            if (!int.TryParse(portStr, out int port))
            {
                MessageBox.Show("Port phải là số!", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            btnEncryptAndSend.Enabled = false;
            lblClientStatus.Text = "Trạng thái: Đang xử lý...";
            lblClientStatus.ForeColor = Color.Orange;
            Log("⏳ Bắt đầu mã hóa file...");

            string filePath = txtFilePath.Text;
            byte[] fileData = File.ReadAllBytes(filePath);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            string directory = Path.GetDirectoryName(filePath);
            string fileName = Path.GetFileNameWithoutExtension(filePath);
            string extension = Path.GetExtension(filePath);

            string output = Path.Combine(directory, fileName + "_ma" + extension);

            // Mã hóa file

            string mode = rdoECB_Client.Checked ? "ECB" : "CBC";
            if (mode == "ECB")
            {
                byte[] encryptedData = AESFileManual.EncryptFileManual(filePath, output, keyBytes);
                Log($"✓ Mã hóa thành công ({encryptedData.Length} bytes)");
                Log($"📤 Gửi đến {serverIP}:{port}...");

                // Gửi đến server
                await SendToServer(serverIP, port, Path.GetFileName(filePath), encryptedData);
            }
            else
            {
                byte[] encryptedData = AESFileManual.EncryptFileCBC(filePath, output, keyBytes);
                Log($"✓ Mã hóa thành công ({encryptedData.Length} bytes)");
                Log($"📤 Gửi đến {serverIP}:{port}...");

                // Gửi đến server
                await SendToServer(serverIP, port, Path.GetFileName(filePath), encryptedData);
            }


            lblClientStatus.Text = "Trạng thái: Gửi thành công!";
            lblClientStatus.ForeColor = Color.Green;
            Log("✓ Gửi file thành công!");
            MessageBox.Show("Gửi file thành công!", "Thành công", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            lblClientStatus.Text = $"Trạng thái: Lỗi - {ex.Message}";
            lblClientStatus.ForeColor = Color.Red;
            Log($"❌ Lỗi: {ex.Message}");
            MessageBox.Show($"Lỗi: {ex.Message}", "Thất bại", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            btnEncryptAndSend.Enabled = true;
        }
    }

    private async Task SendToServer(string ip, int port, string fileName, byte[] data)
    {
        using (TcpClient client = new TcpClient())
        {
            Log("Da ket noi den Server!");
            await client.ConnectAsync(ip, port);
            using (NetworkStream stream = client.GetStream())
            {
                // Gửi tên file (length + data)
                byte[] fileNameBytes = Encoding.UTF8.GetBytes(fileName);
                stream.Write(BitConverter.GetBytes(fileNameBytes.Length), 0, 4);
                stream.Write(fileNameBytes, 0, fileNameBytes.Length);

                // Gửi dữ liệu mã hóa
                stream.Write(BitConverter.GetBytes(data.Length), 0, 4);
                stream.Write(data, 0, data.Length);
                stream.Flush();
            }
        }
    }

    private void StartServer(string portStr)
    {
        try
        {
            if (!int.TryParse(portStr, out int port))
            {
                MessageBox.Show("Port phải là số!", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (txtKeyServer.Text.Length == 0 || txtKeyServer.Text.Length > 32)
            {
                MessageBox.Show("Key phải là chuỗi đúng định dạng", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            btnStartServer.Enabled = false;
            btnStopServer.Enabled = true;
            isServerRunning = true;
            cancellationTokenSource = new CancellationTokenSource();

            serverListener = new TcpListener(IPAddress.Any, port);
            serverListener.Start();
            lblServerStatus.Text = $"🟢 Server: Chạy (Port {port})";
            lblServerStatus.ForeColor = Color.Green;
            Log($"✓ Server khởi động trên port {port}");

            // Lắng nghe client trong background
            _ = ListenForClientsAsync(cancellationTokenSource.Token);
        }
        catch (Exception ex)
        {
            lblServerStatus.Text = "🔴 Server: Lỗi";
            lblServerStatus.ForeColor = Color.Red;
            Log($"❌ Lỗi khởi động server: {ex.Message}");
            btnStartServer.Enabled = true;
            btnStopServer.Enabled = false;
        }
    }

    private void StopServer()
    {
        try
        {
            isServerRunning = false;
            cancellationTokenSource?.Cancel();
            serverListener?.Stop();

            lblServerStatus.Text = "🔴 Server: Dừng";
            lblServerStatus.ForeColor = Color.Red;
            Log("✓ Server đã dừng");

            btnStartServer.Enabled = true;
            btnStopServer.Enabled = false;
        }
        catch (Exception ex)
        {
            Log($"❌ Lỗi dừng server: {ex.Message}");
        }
    }

    private async Task ListenForClientsAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                if (serverListener.Pending())
                {
                    TcpClient client = await serverListener.AcceptTcpClientAsync(cancellationToken);
                    _ = HandleClientAsync2(client, cancellationToken);
                }
                else
                {
                    await Task.Delay(100, cancellationToken);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Bình thường khi server dừng
        }
        catch (Exception ex)
        {
            if (isServerRunning)
                Log($"❌ Lỗi nghe client: {ex.Message}");
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken cancellationToken)
    {
        try
        {
            using (client)
            using (NetworkStream stream = client.GetStream())
            {
                byte[] lengthBuffer = new byte[4];

                // Nhận tên file
                await stream.ReadExactlyAsync(lengthBuffer, 0, 4, cancellationToken);
                int fileNameLength = BitConverter.ToInt32(lengthBuffer, 0);
                byte[] fileNameBytes = new byte[fileNameLength];
                await stream.ReadExactlyAsync(fileNameBytes, 0, fileNameLength, cancellationToken);
                string fileName = Encoding.UTF8.GetString(fileNameBytes);

                // Nhận dữ liệu mã hóa
                await stream.ReadExactlyAsync(lengthBuffer, 0, 4, cancellationToken);
                int dataLength = BitConverter.ToInt32(lengthBuffer, 0);
                byte[] encryptedData = new byte[dataLength];
                await stream.ReadExactlyAsync(encryptedData, 0, dataLength, cancellationToken);

                // Hiển thị dữ liệu mã hóa (Hex)
                string hexData = BitConverter.ToString(encryptedData).Replace("-", "");
                Invoke((Action)(() =>
                {
                    txtEncryptedReceived.Text = $"File: {fileName}\r\nKích thước: {dataLength} bytes\r\n\r{hexData.Substring(0, Math.Min(200, hexData.Length))}...";
                    Log($"📥 Nhận file: {fileName} ({dataLength} bytes)");
                }));

                // Giải mã
                byte[] key = Encoding.UTF8.GetBytes("1234567890123456");
                byte[] decryptedData = AESEncryption.DecryptAES(encryptedData, key);
                string decryptedText = Encoding.UTF8.GetString(decryptedData);

                Invoke((Action)(() =>
                {
                    txtDecryptedResult.Text = decryptedText;
                    Log("✓ Giải mã thành công!");
                }));
            }
        }
        catch (Exception ex)
        {
            Log($"❌ Lỗi xử lý client: {ex.Message}");
        }
    }

    private async Task HandleClientAsync2(TcpClient client, CancellationToken cancellationToken)
    {
        try
        {
            using (client)
            using (NetworkStream stream = client.GetStream())
            {
                byte[] lengthBuffer = new byte[4];

                // --- BƯỚC 1: NHẬN TÊN FILE ---
                // Đọc 4 byte đầu tiên để biết độ dài tên file
                await stream.ReadExactlyAsync(lengthBuffer, 0, 4, cancellationToken);
                int fileNameLength = BitConverter.ToInt32(lengthBuffer, 0);

                byte[] fileNameBytes = new byte[fileNameLength];
                await stream.ReadExactlyAsync(fileNameBytes, 0, fileNameLength, cancellationToken);
                string fileName = Encoding.UTF8.GetString(fileNameBytes);

                // --- BƯỚC 2: NHẬN DỮ LIỆU MÃ HÓA (LUỒNG DATA) ---
                // Đọc 4 byte tiếp theo để biết độ dài mảng encryptedData
                await stream.ReadExactlyAsync(lengthBuffer, 0, 4, cancellationToken);
                int dataLength = BitConverter.ToInt32(lengthBuffer, 0);

                byte[] encryptedData = new byte[dataLength];
                await stream.ReadExactlyAsync(encryptedData, 0, dataLength, cancellationToken);

                // Hiển thị thông tin nhận được lên UI
                Invoke((Action)(() =>
                {
                    Log($"📥 Nhận gói tin: {fileName} ({dataLength} bytes)");
                    txtEncryptedReceived.Text = BitConverter.ToString(encryptedData).Replace("-", " ");
                }));

                // --- BƯỚC 3: GIẢI MÃ BẰNG HÀM MANUAL ---
                byte[] key = Encoding.UTF8.GetBytes(txtKeyServer.Text); // Key phải đủ 16 byte

                try
                {

                    string mode = rdoECB_Server.Checked ? "ECB" : "CBC";
                    if(mode == "ECB")
                    {
                        // Gọi hàm DecryptDataManual bạn vừa sửa
                        byte[] decryptedData = AESFileDecryptor.DecryptDataManual(encryptedData, key);

                        // Chuyển mảng byte "sạch" sang String
                        string decryptedText = Encoding.UTF8.GetString(decryptedData);

                        // Hiển thị kết quả cuối cùng
                        Invoke((Action)(() =>
                        {
                            txtDecryptedResult.Text = decryptedText;
                            Log("✓ Giải mã và xử lý luồng data thành công!");
                        }));
                    }else{
                          // Gọi hàm DecryptDataManual bạn vừa sửa
                        byte[] decryptedData = AESFileDecryptor.DecryptDataCBC(encryptedData, key);

                        // Chuyển mảng byte "sạch" sang String
                        string decryptedText = Encoding.UTF8.GetString(decryptedData);

                        // Hiển thị kết quả cuối cùng
                        Invoke((Action)(() =>
                        {
                            txtDecryptedResult.Text = decryptedText;
                            Log("✓ Giải mã và xử lý luồng data thành công!");
                        }));
                    }
                }
                catch (Exception decryptEx)
                {
                    Invoke((Action)(() => Log($"❌ Lỗi giải mã: {decryptEx.Message}")));
                }
            }
        }
        catch (Exception ex)
        {
            Invoke((Action)(() => Log($"❌ Lỗi kết nối: {ex.Message}")));
        }
    }

    private void Log(string message)
    {
        Invoke((Action)(() =>
        {
            txtClientLog.Text += DateTime.Now.ToString("[HH:mm:ss] ") + message + Environment.NewLine;
            txtClientLog.SelectionStart = txtClientLog.Text.Length;
            txtClientLog.ScrollToCaret();
        }));
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        StopServer();
        base.OnFormClosing(e);
    }
}
