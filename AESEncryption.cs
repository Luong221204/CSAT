using System;
using System.Security.Cryptography;

namespace CSAT
{
    /// <summary>
    /// Lớp xử lý mã hóa và giải mã AES-128
    /// </summary>
    public static class AESEncryption
    {
        /// <summary>
        /// Mã hóa dữ liệu sử dụng AES-128
        /// </summary>
        /// <param name="plainData">Dữ liệu cần mã hóa</param>
        /// <param name="key">Key 16 byte (128 bit)</param>
        /// <returns>Dữ liệu đã mã hóa kèm IV</returns>
        public static byte[] EncryptAES(byte[] plainData, byte[] key)
        {
            if (key.Length != 16)
                throw new ArgumentException("Key phải là 16 byte cho AES-128");

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                // Tạo IV ngẫu nhiên
                byte[] iv = new byte[aes.IV.Length];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(iv);
                }
                aes.IV = iv;

                // Mã hóa
                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    byte[] encryptedData = encryptor.TransformFinalBlock(plainData, 0, plainData.Length);
                    
                    // Kết hợp IV + dữ liệu mã hóa (IV ở phía trước)
                    byte[] result = new byte[iv.Length + encryptedData.Length];
                    Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                    Buffer.BlockCopy(encryptedData, 0, result, iv.Length, encryptedData.Length);
                    
                    return result;
                }
            }
        }

        /// <summary>
        /// Giải mã dữ liệu AES
        /// </summary>
        /// <param name="encryptedData">Dữ liệu đã mã hóa (IV + ciphertext)</param>
        /// <param name="key">Key 16 byte (128 bit)</param>
        /// <returns>Dữ liệu đã giải mã</returns>
        public static byte[] DecryptAES(byte[] encryptedData, byte[] key)
        {
            if (key.Length != 16)
                throw new ArgumentException("Key phải là 16 byte cho AES-128");

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                // Trích xuất IV (16 byte đầu)
                byte[] iv = new byte[aes.IV.Length];
                Buffer.BlockCopy(encryptedData, 0, iv, 0, iv.Length);
                aes.IV = iv;

                // Trích xuất dữ liệu mã hóa (phần còn lại)
                byte[] ciphertext = new byte[encryptedData.Length - iv.Length];
                Buffer.BlockCopy(encryptedData, iv.Length, ciphertext, 0, ciphertext.Length);

                // Giải mã
                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    byte[] decryptedData = decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                    return decryptedData;
                }
            }
        }
    }
}
