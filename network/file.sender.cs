using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace CSAT.Network.Sender
{
    public class FileSender
    {
        public async Task SendFileAsync(string ip, int port, string filePath, byte[] encryptedData)
        {
            try
            {
                using (TcpClient client = new TcpClient())
                {
                    Console.WriteLine($"[CONNECTING] Đang kết nối tới {ip}:{port}...");
                    await client.ConnectAsync(ip, port);
                    
                    using (NetworkStream ns = client.GetStream())
                    {
                        // 1. Lấy thông tin tên file
                        string fileName = Path.GetFileName(filePath);
                        byte[] fileNameBytes = Encoding.UTF8.GetBytes(fileName);
                        
                        // 2. Gửi độ dài tên file (4 byte)
                        byte[] fileNameLen = BitConverter.GetBytes(fileNameBytes.Length);
                        await ns.WriteAsync(fileNameLen, 0, 4);
                        
                        // 3. Gửi tên file thật
                        await ns.WriteAsync(fileNameBytes, 0, fileNameBytes.Length);
                        
                        // 4. Gửi độ dài dữ liệu mã hóa (8 byte - long)
                        byte[] dataLen = BitConverter.GetBytes((long)encryptedData.Length);
                        await ns.WriteAsync(dataLen, 0, 8);
                        
                        // 5. Gửi mảng byte dữ liệu đã mã hóa
                        // Chia nhỏ ra để gửi (Buffer) giúp tránh treo mạng với file lớn
                        int bufferSize = 4096; // 4KB
                        int sent = 0;
                        while (sent < encryptedData.Length)
                        {
                            int toSend = Math.Min(bufferSize, encryptedData.Length - sent);
                            await ns.WriteAsync(encryptedData, sent, toSend);
                            sent += toSend;
                            
                            // In tiến độ ra Console đen của bạn
                            double progress = (double)sent / encryptedData.Length * 100;
                            if (sent % (bufferSize * 10) == 0 || sent == encryptedData.Length)
                                Console.WriteLine($"[SENDING] Đã gửi: {progress:F1}%");
                        }

                        await ns.FlushAsync();
                        Console.WriteLine("[SUCCESS] Đã gửi file thành công!");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[ERROR] Lỗi khi gửi file: " + ex.Message);
                throw;
            }
        }
    }
}