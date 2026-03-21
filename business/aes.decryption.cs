using System;
using System.IO;
using System.Collections.Generic;
namespace Decryption;

public class AESDecryption
{
    // Bảng S-Box nghịch đảo (Inverse S-Box)
    private static readonly byte[] InvSBox = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, d9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };

    // --- CÁC HÀM NGHỊCH ĐẢO ---

    // 1. Cộng khóa vòng (Giống mã hóa vì XOR tự nghịch đảo)
    private static void AddRoundKey(byte[,] state, byte[] expandedKey, int round) {
        for (int c = 0; c < 4; c++)
            for (int r = 0; r < 4; r++)
                state[r, c] ^= expandedKey[round * 16 + c * 4 + r];
    }

    // 2. Dịch hàng ngược (Dịch sang phải)
    private static void InvShiftRows(byte[,] state) {
        byte[] temp = new byte[4];
        for (int r = 1; r < 4; r++) {
            // Dịch phải r vị trí tương đương với dịch trái (4-r) vị trí
            for (int c = 0; c < 4; c++) temp[(c + r) % 4] = state[r, c];
            for (int c = 0; c < 4; c++) state[r, c] = temp[c];
        }
    }

    // 3. Thay thế byte ngược
    private static void InvSubBytes(byte[,] state) {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                state[r, c] = InvSBox[state[r, c]];
    }

    // 4. Trộn cột ngược (Sử dụng các hệ số 0e, 0b, 0d, 09)
    private static void InvMixColumns(byte[,] state) {
        for (int c = 0; c < 4; c++) {
            byte s0 = state[0, c], s1 = state[1, c], s2 = state[2, c], s3 = state[3, c];
            state[0, c] = (byte)(GaloMul(s0, 0x0e) ^ GaloMul(s1, 0x0b) ^ GaloMul(s2, 0x0d) ^ GaloMul(s3, 0x09));
            state[1, c] = (byte)(GaloMul(s0, 0x09) ^ GaloMul(s1, 0x0e) ^ GaloMul(s2, 0x0b) ^ GaloMul(s3, 0x0d));
            state[2, c] = (byte)(GaloMul(s0, 0x0d) ^ GaloMul(s1, 0x09) ^ GaloMul(s2, 0x0e) ^ GaloMul(s3, 0x0b));
            state[3, c] = (byte)(GaloMul(s0, 0x0b) ^ GaloMul(s1, 0x0d) ^ GaloMul(s2, 0x09) ^ GaloMul(s3, 0x0e));
        }
    }

    // Hàm nhân trong trường Galois (Giữ nguyên từ code mã hóa)
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

    // --- HÀM GIẢI MÃ TỔNG THỂ ---

    public static byte[] Decrypt(byte[] input, byte[] key) {
        // 1. Mở rộng khóa từ khóa chính
        byte[] expandedKey = AESEncryption.ExpandKey(key); 
        
        byte[,] state = new byte[4, 4];
        for (int i = 0; i < 16; i++) state[i % 4, i / 4] = input[i];

        // 2. Vòng khởi đầu (Round 10): Chỉ AddRoundKey, InvShiftRows và InvSubBytes
        AddRoundKey(state, expandedKey, 10);
        InvShiftRows(state);
        InvSubBytes(state);

        // 3. 9 vòng lặp ngược (Từ vòng 9 về vòng 1)
        for (int round = 9; round >= 1; round--) {
            AddRoundKey(state, expandedKey, round);
            InvMixColumns(state);
            InvShiftRows(state);
            InvSubBytes(state);
        }

        // 4. Vòng cuối (Round 0): Chỉ AddRoundKey
        AddRoundKey(state, expandedKey, 0);

        // Chuyển ma trận state ngược lại mảng byte
        byte[] output = new byte[16];
        for (int i = 0; i < 16; i++) output[i] = state[i % 4, i / 4];
        return output;
    }
}


public class AESFileDecryptor
{
    public static void DecryptFileManual(string inputPath, string outputPath, byte[] key)
    {
        // 1. Đọc toàn bộ dữ liệu đã mã hóa từ file
        byte[] encryptedData = File.ReadAllBytes(inputPath);
        
        // Kiểm tra xem dữ liệu có phải là bội số của 16 không
        if (encryptedData.Length % 16 != 0)
        {
            throw new Exception("Dữ liệu mã hóa không hợp lệ (không chia hết cho 16).");
        }

        List<byte> decryptedList = new List<byte>();

        // 2. Giải mã từng khối 16 byte
        for (int i = 0; i < encryptedData.Length; i += 16)
        {
            byte[] block = new byte[16];
            Array.Copy(encryptedData, i, block, 0, 16);
            
            // Gọi hàm giải mã "chay" đã viết ở bước trước
            byte[] decryptedBlock = AESDecryption.Decrypt(block, key); 
            
            decryptedList.AddRange(decryptedBlock);
        }

        byte[] decryptedData = decryptedList.ToArray();

        // 3. Loại bỏ Padding (PKCS7)
        // Giá trị của byte cuối cùng chính là số lượng byte đã được bù vào
        int paddingLength = decryptedData[decryptedData.Length - 1];

        // Kiểm tra tính hợp lệ của padding để tránh lỗi
        if (paddingLength <= 0 || paddingLength > 16)
        {
            throw new Exception("Lỗi giải mã: Padding không hợp lệ. Có thể sai khóa?");
        }

        int finalLength = decryptedData.Length - paddingLength;
        byte[] finalResult = new byte[finalLength];
        Array.Copy(decryptedData, finalResult, finalLength);

        // 4. Ghi dữ liệu sạch ra file
        File.WriteAllBytes(outputPath, finalResult);
        
        Console.WriteLine($"--- GIẢI MÃ FILE THÀNH CÔNG ---");
        Console.WriteLine($"File gốc: {inputPath}");
        Console.WriteLine($"File đầu ra: {outputPath}");
        Console.WriteLine($"Kích thước sau khi loại bỏ padding: {finalLength} bytes");
    }
}
