using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets; // Đảm bảo có cả dòng này cho TcpListener
namespace CSAT.Network.Receiver
{
    public class FileReceiver
    {
        public async Task StartListening(int port)
        {
            TcpListener listener = new TcpListener(IPAddress.Any, port);
            listener.Start();
            Console.WriteLine($"[SERVER] Đang đợi file tại cổng {port}...");

            while (true)
            {
                using (TcpClient client = await listener.AcceptTcpClientAsync())
                using (NetworkStream ns = client.GetStream())
                {
                    Console.WriteLine("[SERVER] Có kết nối mới!");

                    // 1. Đọc độ dài tên file (4 byte)
                    byte[] nameLenBytes = new byte[4];
                    await ns.ReadExactlyAsync(nameLenBytes, 0, 4);
                    int nameLen = BitConverter.ToInt32(nameLenBytes, 0);

                    // 2. Đọc tên file
                    byte[] nameBytes = new byte[nameLen];
                    await ns.ReadExactlyAsync(nameBytes, 0, nameLen);
                    string fileName = Encoding.UTF8.GetString(nameBytes);

                    // 3. Đọc độ dài dữ liệu (8 byte)
                    byte[] dataLenBytes = new byte[8];
                    await ns.ReadExactlyAsync(dataLenBytes, 0, 8);
                    long dataLen = BitConverter.ToInt64(dataLenBytes, 0);

                    // 4. Đọc dữ liệu mã hóa
                    byte[] encryptedData = new byte[dataLen];
                    int totalRead = 0;
                    while (totalRead < dataLen)
                    {
                        int read = await ns.ReadAsync(encryptedData, totalRead, (int)dataLen - totalRead);
                        totalRead += read;
                    }

                    Console.WriteLine($"[SERVER] Đã nhận xong file mã hóa: {fileName}");
                    // Sau bước này, bạn đem encryptedData đi giải mã AES là xong!
                }
            }
        }
    }
}