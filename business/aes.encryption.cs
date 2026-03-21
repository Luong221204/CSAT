using System;
namespace Encryption;

public class AESEncryption
{
    // Bảng S-Box cho SubBytes
    private static readonly byte[] SBox = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

    private static readonly byte[] Rcon = { 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

    // 1. Key Expansion (Đã làm ở bước trước)
    public static byte[] ExpandKey(byte[] key) {
        byte[] expandedKey = new byte[176];
        Array.Copy(key, 0, expandedKey, 0, 16);
        int bytesGenerated = 16;
        int rconIter = 1;
        while (bytesGenerated < 176) {
            byte[] temp = new byte[4];
            for (int i = 0; i < 4; i++) temp[i] = expandedKey[bytesGenerated - 4 + i];
            if (bytesGenerated % 16 == 0) {
                byte t = temp[0]; temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
                for (int i = 0; i < 4; i++) temp[i] = SBox[temp[i]];
                temp[0] ^= Rcon[rconIter++];
            }
            for (int i = 0; i < 4; i++) {
                expandedKey[bytesGenerated] = (byte)(expandedKey[bytesGenerated - 16] ^ temp[i]);
                bytesGenerated++;
            }
        }
        return expandedKey;
    }

    // 2. AddRoundKey
    private static void AddRoundKey(byte[,] state, byte[] expandedKey, int round) {
        for (int c = 0; c < 4; c++)
            for (int r = 0; r < 4; r++)
                state[r, c] ^= expandedKey[round * 16 + c * 4 + r];
    }

    // 3. SubBytes
    private static void SubBytes(byte[,] state) {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                state[r, c] = SBox[state[r, c]];
    }

    // 4. ShiftRows
    private static void ShiftRows(byte[,] state) {
        byte[] temp = new byte[4];
        for (int r = 1; r < 4; r++) {
            for (int c = 0; c < 4; c++) temp[c] = state[r, (c + r) % 4];
            for (int c = 0; c < 4; c++) state[r, c] = temp[c];
        }
    }

    // 5. MixColumns (Nhân ma trận trong trường Galois GF(2^8))
    private static byte GaloMul(byte a, byte b) {
        byte p = 0;
        for (int i = 0; i < 8; i++) {
            if ((b & 1) != 0) p ^= a;
            bool hiBitSet = (a & 0x80) != 0;
            a <<= 1;
            if (hiBitSet) a ^= 0x1b;
            b >>= 1;
        }
        return p;
    }

    private static void MixColumns(byte[,] state) {
        for (int c = 0; c < 4; c++) {
            byte s0 = state[0, c], s1 = state[1, c], s2 = state[2, c], s3 = state[3, c];
            state[0, c] = (byte)(GaloMul(s0, 2) ^ GaloMul(s1, 3) ^ s2 ^ s3);
            state[1, c] = (byte)(s0 ^ GaloMul(s1, 2) ^ GaloMul(s2, 3) ^ s3);
            state[2, c] = (byte)(s0 ^ s1 ^ GaloMul(s2, 2) ^ GaloMul(s3, 3));
            state[3, c] = (byte)(GaloMul(s0, 3) ^ s1 ^ s2 ^ GaloMul(s3, 2));
        }
    }

    // HÀM MÃ HÓA TỔNG THỂ
    public static byte[] Encrypt(byte[] input, byte[] key) {
        byte[] expandedKey = ExpandKey(key);
        byte[,] state = new byte[4, 4];
        for (int i = 0; i < 16; i++) state[i % 4, i / 4] = input[i];

        // Vòng khởi đầu
        AddRoundKey(state, expandedKey, 0);

        // 9 vòng lặp chính
        for (int round = 1; round < 10; round++) {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, expandedKey, round);
        }

        // Vòng cuối (Không có MixColumns)
        SubBytes(state);
        ShiftRows(state);
        AddRoundKey(state, expandedKey, 10);

        byte[] output = new byte[16];
        for (int i = 0; i < 16; i++) output[i] = state[i % 4, i / 4];
        return output;
    }
}

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