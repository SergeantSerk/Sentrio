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
        /// <param name="iterations">
        /// The amount of iterations to derive the key, from password.
        /// </param>
        /// <param name="key_size">
        /// The size of the key for AES.
        /// </param>
        /// <returns>
        /// The encrypted message from the supplied message and password.
        /// </returns>
        public async Task<byte[]> Encrypt(byte[] message, string password, int key_size, int iterations)
        {
            byte[] salt = GenerateSecureRandomBytes(key_size);
            byte[] iv = GenerateSecureRandomBytes(Aes.Create().BlockSize / 8);
            using (MemoryStream MessageIn = new MemoryStream(message))
            using (MemoryStream MessageOut = await Crypto(MessageIn, password, key_size, iterations, salt, iv, true))
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
            // Split all headers into their corresponding variables
            string[] payloads = Encoding.ASCII.GetString(message).Split(':');
            int key_size = int.Parse(payloads[0]);
            int iterations = int.Parse(payloads[1]);
            byte[] salt = Convert.FromBase64String(payloads[2]);
            byte[] iv = Convert.FromBase64String(payloads[3]);
            byte[] encrypted = Convert.FromBase64String(payloads[4]);
            byte[] received_hash = Convert.FromBase64String(payloads[5]);

            // Perform HMAC comparison for message validation and integrity
            string testing = string.Join(":", key_size, iterations, Convert.ToBase64String(salt), Convert.ToBase64String(iv), Convert.ToBase64String(encrypted));
            byte[] calculated_hash;
            using (Rfc2898DeriveBytes rfc = new Rfc2898DeriveBytes(password, salt, iterations))
            using (HMAC hmac = HMACSHA512.Create())
            {
                hmac.Key = rfc.GetBytes(key_size / 8);
                calculated_hash = hmac.ComputeHash(Encoding.ASCII.GetBytes(testing));
            }

            // Compare received hash with calculated hash
            if (!CompareByteArrays(received_hash, calculated_hash)) throw new Exception("The received HMAC does not equal the calculated HMAC, message has been tampered with.");

            // Begin decrypting
            using (MemoryStream MessageIn = new MemoryStream(encrypted))
            using (MemoryStream MessageOut = await Crypto(MessageIn, password, key_size, iterations, salt, iv, false))
            {
                return MessageOut.ToArray();
            }
        }
        #endregion

        #region Operations
        private async Task<MemoryStream> Crypto(Stream input, string password, int key_size, int iterations, byte[] salt, byte[] iv, bool encrypt)
        {
            using (MemoryStream output = new MemoryStream())
            using (var aes = Aes.Create())
            {
                aes.KeySize = key_size;
                aes.Mode = CM;
                aes.Padding = PM;
                aes.IV = iv;

                using (MemoryStream crypto = new MemoryStream())
                {
                    using (var rfc = new Rfc2898DeriveBytes(password, salt, iterations))
                    {
                        aes.Key = rfc.GetBytes(aes.KeySize / 8);

                        using (var transform = encrypt ? aes.CreateEncryptor() : aes.CreateDecryptor())
                        using (var cs = new CryptoStream(crypto, transform, CryptoStreamMode.Write))
                        {
                            // Input -> [Crpyto Functions] -> Crypto
                            await input.CopyToAsync(cs);
                        }
                    }

                    if (encrypt)
                    {
                        // Add headers
                        string salt_b64 = Convert.ToBase64String(salt);                                             // Salt Base64
                        string iv_b64 = Convert.ToBase64String(iv);                                                 // IV Base64
                        string ciphertext_b64 = Convert.ToBase64String(crypto.ToArray());                           // Ciphertext Base64
                        string final = string.Join(":", key_size, iterations, salt_b64, iv_b64, ciphertext_b64);    // Penultimate Payload

                        // Add HMAC for integrity
                        using (HMAC hmac = HMACSHA512.Create())
                        {
                            hmac.Key = aes.Key;
                            byte[] hash = hmac.ComputeHash(Encoding.ASCII.GetBytes(final));
                            string hash_b64 = Convert.ToBase64String(hash);
                            final = string.Join(":", final, hash_b64);                                                  // Final Payload
                        }

                        // Wrap all data in ASCII
                        byte[] final_data = Encoding.ASCII.GetBytes(final);
                        // Write to output
                        await output.WriteAsync(final_data, 0, final_data.Length);
                    }
                    else
                    {
                        // No headers (decrypting), get plaintext from crypto stream
                        byte[] plaintext_data = crypto.ToArray();
                        // Write to output
                        await output.WriteAsync(plaintext_data, 0, plaintext_data.Length);
                    }
                }

                return output;
            }

        }
        #endregion
    }
}