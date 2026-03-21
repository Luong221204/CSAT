using System;
namespace CSAT;

public class AESFileManual
{
    // Giả sử các hàm SubBytes, ShiftRows, MixColumns, AddRoundKey, 
    // KeyExpansion và Encrypt(byte[] input, byte[] key) đã được định nghĩa ở trên.

    public static void EncryptFileManual(string inputPath, string outputPath, byte[] key)
    {
        byte[] fileBytes = File.ReadAllBytes(inputPath);
        
        // 1. Padding (PKCS7): Đưa độ dài file về bội số của 16
        int paddingLength = 16 - (fileBytes.Length % 16);
        byte[] paddedBytes = new byte[fileBytes.Length + paddingLength];
        Array.Copy(fileBytes, paddedBytes, fileBytes.Length);
        for (int i = fileBytes.Length; i < paddedBytes.Length; i++)
        {
            paddedBytes[i] = (byte)paddingLength;
        }

        // 2. Chia khối và mã hóa từng khối 16 byte
        byte[] encryptedData = new byte[paddedBytes.Length];
        for (int i = 0; i < paddedBytes.Length; i += 16)
        {
            byte[] block = new byte[16];
            Array.Copy(paddedBytes, i, block, 0, 16);
            
            // Gọi hàm mã hóa "chay" của bạn ở đây
            byte[] encryptedBlock = AESEncryption.Encrypt(block, key); 
            
            Array.Copy(encryptedBlock, 0, encryptedData, i, 16);
        }

        File.WriteAllBytes(outputPath, encryptedData);
        Console.WriteLine("Đã mã hóa xong bằng thuật toán AES tự viết!");
        Console.WriteLine("--- KẾT QUẢ MÃ HÓA ---");
    Console.WriteLine($"Đường dẫn file đích: {outputPath}");

    // 4. In nội dung mã hóa dưới dạng HEX (Chuỗi thập lục phân - Phổ biến trong mật mã học)
    Console.WriteLine("\nNội dung mã hóa (Dạng HEX):");
    string hexString = BitConverter.ToString(encryptedData).Replace("-", " ");
    // Nếu file quá dài, chỉ in 256 byte đầu tiên để tránh tràn màn hình
    if (hexString.Length > 500) 
        Console.WriteLine(hexString.Substring(0, 500) + "...");
    else 
        Console.WriteLine(hexString);

    // 5. In nội dung mã hóa dưới dạng Base64 (Dùng để truyền tin hoặc lưu database)
    Console.WriteLine("\nNội dung mã hóa (Dạng Base64):");
    string base64String = Convert.ToBase64String(encryptedData);
    if (base64String.Length > 200)
        Console.WriteLine(base64String.Substring(0, 200) + "...");
    else
        Console.WriteLine(base64String);

    Console.WriteLine("\n-----------------------");
    }
}