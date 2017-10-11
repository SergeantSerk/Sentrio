using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Sentrio
{
    public class CryptoWorks
    {
        #region Properties
        // Preconfigured password key derivation parameters
        // public const string PasswordChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!£$%^&*()_+-=[]{}'#@~,.<>/? ";
        // private static Aes AES = new AesCryptoServiceProvider() { Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
        public const CipherMode CM = CipherMode.CBC;
        public const PaddingMode PM = PaddingMode.PKCS7;
        // public const int KeySize = 256;
        // public const int IVSize = KeySize / 8;
        // public const int SaltSize = KeySize / 8;

        // Software properties
        public bool AutoEncrypt = true;
        public bool AutoDecrypt = true;
        #endregion

        #region Constructors
        public CryptoWorks()
        {

        }
        #endregion

        #region Utilities
        /// <summary>
        /// Converts the given byte array to "hexadecimal" string.
        /// </summary>
        /// <param name="ba">The byte array to convert.</param>
        /// <returns>String in hexadecimal format.</returns>
        public static string ByteArrayToString(byte[] ba)
        {
            if (ba != null && ba.Length > 0)
            {
                StringBuilder hex = new StringBuilder(ba.Length * 2);
                foreach (byte b in ba)
                {
                    hex.AppendFormat("{0:x2}", b);
                }
                return hex.ToString();
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        /// Converts the given "hexadecimal" string to byte array.
        /// </summary>
        /// <param name="hex">The hexadecimal string to convert.</param>
        /// <returns>Byte array derived from the hexadecimal string.</returns>
        public static byte[] StringToByteArray(string hex)
        {
            if (string.IsNullOrWhiteSpace(hex) == false)
            {
                int NumberChars = hex.Length;
                byte[] bytes = new byte[NumberChars / 2];
                for (int i = 0; i < NumberChars; i += 2)
                    bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
                return bytes;
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        /// Generate a cryptographically strong random key using AES.
        /// </summary>
        /// <returns>Byte array of the generated key.</returns>
        public byte[] GenerateRandomKey()
        {
            using (var aes = Aes.Create())
            {
                aes.GenerateKey();
                return aes.Key;
            }
        }

        /// <summary>
        /// Generate cryptographically strong random bytes using RNG based on given size.
        /// </summary>
        /// <param name="size">The size of byte array.</param>
        /// <returns>A byte array filled with random bytes.</returns>
        public byte[] GenerateSecureRandomBytes(int size)
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] random = new byte[size];
                rng.GetBytes(random);
                return random;
            }
        }

        /// <summary>
        /// Compare two byte arrays and return true if both are equal.
        /// </summary>
        /// <param name="a1">First byte array to compare from.</param>
        /// <param name="a2">Second byte array to compare with.</param>
        /// <returns></returns>
        public static bool CompareByteArrays(byte[] a1, byte[] a2)
        {
            if (a1 != null && a1.Length > 0 && a2 != null && a2.Length > 0)
            {
                if (a1.Length != a2.Length)
                {
                    return false;
                }

                for (int i = 0; i < a1.Length; i++)
                {
                    if (a1[i] != a2[i])
                    {
                        return false;
                    }
                }
                return true;
            }
            else
            {
                return false;
            }
        }

        /// <summary>
        /// Hashes given byte array with the given hash algorithm.
        /// </summary>
        /// <param name="data">
        /// The byte array to hash.
        /// </param>
        /// <param name="halgo">
        /// The hash algorithm to use.
        /// </param>
        /// <returns>
        /// If data is not empty and null & hash algorithm is not null, the hash of the byte array.
        /// Else, null.
        /// </returns>
        public byte[] Hash(byte[] data, HashAlgorithm halgo)
        {
            if (data.Length > 0 && halgo != null) using (var h = halgo) return h.ComputeHash(data);
            else return null;
        }

        /// <summary>
        /// Hashes given stream with the given hash algorithm.
        /// Uses <see cref="Hash(byte[], HashAlgorithm)"/> method.
        /// </summary>
        /// <param name="stream">
        /// The stream to read data from.
        /// </param>
        /// <param name="halgo">
        /// The hash algorithm to use.
        /// </param>
        /// <returns>
        /// The hash of the data from stream.
        /// </returns>
        public byte[] Hash(Stream stream, HashAlgorithm halgo)
        {
            // Reads data from FileStream to the data array
            byte[] data = new byte[stream.Length];
            stream.Read(data, 0, data.Length);

            return Hash(data, halgo);
        }
        #endregion

        #region File
        /// <summary>
        /// Encrypt a file from source file path to destination file path, using a password.
        /// </summary>
        /// <param name="FilePathIn">The path of the file to encrypt.</param>
        /// <param name="FilePathOut">The path to save the encrypted file.</param>
        /// <param name="password">The password to encrypt the file.</param>
        public async Task Encrypt(string FilePathIn, string FilePathOut, string password, int key_size, int iterations)
        {
            // Open the source file
            using (FileStream FileIn = new FileStream(FilePathIn, FileMode.Open))
            // Create the destination file
            using (FileStream FileOut = new FileStream(FilePathOut, FileMode.Create))
            // Encrypt file and get the stream
            using (MemoryStream CryptoStream = await Crypto(FileIn, password, key_size, iterations, GenerateSecureRandomBytes(key_size), GenerateSecureRandomBytes(key_size / 8), true))
            {
                byte[] data = CryptoStream.ToArray();               // Get encrypted content
                await FileOut.WriteAsync(data, 0, data.Length);     // Write to destination file
            }
        }

        /// <summary>
        /// Decrypt a file from source file path to destination file path, using a password.
        /// </summary>
        /// <param name="FilePathIn">The path of the file to decrypt.</param>
        /// <param name="FilePathOut">The path to save the decrypted file.</param>
        /// <param name="password">The password to decrypt the file.</param>
        public async Task Decrypt(string FilePathIn, string FilePathOut, string password)
        {
            // Open the source file
            using (var FileIn = new FileStream(FilePathIn, FileMode.Open))
            // Create the destination file
            using (var FileOut = new FileStream(FilePathOut, FileMode.Create))
            {
                // Hold bytes for key size, using the size from current byte
                byte[] KeySizeBytes = new byte[FileIn.ReadByte()];
                // Fill the array with bytes from file, of array length
                FileIn.Read(KeySizeBytes, 0, KeySizeBytes.Length);
                // Parse key size from the array
                int key_size = int.Parse(Encoding.ASCII.GetString(KeySizeBytes));

                // Hold bytes for iteration count, using the size from current byte
                byte[] IterationsBytes = new byte[FileIn.ReadByte()];
                // Fill the array with bytes from file, of array length
                FileIn.Read(IterationsBytes, 0, IterationsBytes.Length);
                // Parse iteration count from the array
                int iterations = int.Parse(Encoding.ASCII.GetString(IterationsBytes));

                // Hold bytes for salt, using the size from current byte
                byte[] salt = new byte[(FileIn.ReadByte())];
                // Fill the array with bytes from file, in the current position and of array length
                FileIn.Read(salt, 0, salt.Length);

                // Hold bytes for IV, using the size from current byte
                byte[] iv = new byte[FileIn.ReadByte()];
                // Fill the array with bytes from file, in the current position and of array length
                FileIn.Read(iv, 0, iv.Length);

                // Decrypt file and get the stream
                using (var CryptoStream = await Crypto(FileIn, password, key_size, iterations, salt, iv, false))
                {
                    byte[] data = CryptoStream.ToArray();               // Get decrypted content
                    await FileOut.WriteAsync(data, 0, data.Length);     // Write to destination file
                }
            }
        }
        #endregion

        #region Text
        /// <summary>
        /// Encrypts a string message using given password.
        /// </summary>
        /// <param name="message">
        /// The message to encrypt.
        /// </param>
        /// <param name="password">
        /// The password to encrypt the message with.
        /// </param>
        /// <returns>
        /// The encrypted message from the supplied message and password.
        /// </returns>
        public async Task<byte[]> Encrypt(byte[] message, string password, int key_size, int iterations)
        {
            using (MemoryStream MessageIn = new MemoryStream(message))
            using (MemoryStream MessageOut = await Crypto(MessageIn, password, key_size, iterations, GenerateSecureRandomBytes(key_size / 8), GenerateSecureRandomBytes(key_size / 8), true))
            {
                return MessageOut.ToArray();
            }
        }

        /// <summary>
        /// Decrypts a string message using given password.
        /// </summary>
        /// <param name="message">
        /// The message to decrypt.
        /// </param>
        /// <param name="password">
        /// The password to decrypt the message with.
        /// </param>
        /// <returns>
        /// The decrypted message from the supplied message and password.
        /// </returns>
        public async Task<byte[]> Decrypt(byte[] message, string password)
        {
            using (var MessageIn = new MemoryStream(message))
            {
                byte[] KeySizeBytes = new byte[MessageIn.ReadByte()];
                MessageIn.Read(KeySizeBytes, 0, KeySizeBytes.Length);
                int key_size = int.Parse(Encoding.ASCII.GetString(KeySizeBytes));

                byte[] IterationsBytes = new byte[MessageIn.ReadByte()];
                MessageIn.Read(IterationsBytes, 0, IterationsBytes.Length);
                int iterations = int.Parse(Encoding.ASCII.GetString(IterationsBytes));

                byte[] salt = new byte[(MessageIn.ReadByte())];
                MessageIn.Read(salt, 0, salt.Length);

                byte[] iv = new byte[MessageIn.ReadByte()];
                MessageIn.Read(iv, 0, iv.Length);

                using (MemoryStream MessageOut = await Crypto(MessageIn, password, key_size, iterations, salt, iv, false))
                {
                    return MessageOut.ToArray();
                }
            }
        }
        #endregion

        #region Operations
        #region New
        private async Task<MemoryStream> Crypto(Stream input, string password, int key_size, int iterations, byte[] salt, byte[] iv, bool encrypt)
        {
            using (MemoryStream output = new MemoryStream())
            using (var rfc = new Rfc2898DeriveBytes(password, salt, iterations))
            using (var aes = Aes.Create())
            {
                // Check if key size is valid
                if (!aes.ValidKeySize(key_size)) throw new Exception("The specified key size is not valid.");

                aes.KeySize = key_size;
                aes.Mode = CM;
                aes.Padding = PM;
                aes.Key = rfc.GetBytes(aes.KeySize / 8);
                aes.IV = iv;

                using (var transform = encrypt ? aes.CreateEncryptor() : aes.CreateDecryptor())
                using (var cs = new CryptoStream(output, transform, CryptoStreamMode.Write))
                {
                    if (encrypt)
                    {
                        byte[] KeySizeBytes = Encoding.ASCII.GetBytes(aes.KeySize.ToString());              // Key Size Bytes
                        output.WriteByte(Convert.ToByte(KeySizeBytes.Length));                              // Key Size Length
                        output.Write(KeySizeBytes, 0, KeySizeBytes.Length);                                 // Key Size
                        byte[] IterationBytes = Encoding.ASCII.GetBytes(rfc.IterationCount.ToString());     // Iteration Bytes
                        output.WriteByte(Convert.ToByte(IterationBytes.Length));                            // Iteration Length
                        output.Write(IterationBytes, 0, IterationBytes.Length);                             // Iteration
                        output.WriteByte(Convert.ToByte(rfc.Salt.Length));                                  // Salt Length
                        output.Write(rfc.Salt, 0, rfc.Salt.Length);                                         // Salt
                        output.WriteByte(Convert.ToByte(aes.IV.Length));                                    // IV Length
                        output.Write(aes.IV, 0, aes.IV.Length);                                             // IV

                        await input.CopyToAsync(cs);                                                        // Ciphertext
                    }
                    else
                    {
                        await input.CopyToAsync(cs);                                                        // Message
                    }

                    return output;
                }
            }
        }
        #endregion
        #endregion
    }
}