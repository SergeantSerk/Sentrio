using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Sentrio
{
    public class CryptoWorks
    {
        #region Properties
        // Preconfigured password key derivation parameters
        // public const string PasswordChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!£$%^&*()_+-=[]{}'#@~,.<>/?";
        // public bool AutoEncrypt = true;
        // public bool AutoDecrypt = true;
        public const CipherMode CM = CipherMode.CBC;
        public const PaddingMode PM = PaddingMode.PKCS7;
        public const string Identifier = "8310111011611410511";
        public const char Splitter = ':';
        #endregion

        #region Utilities
        /// <summary>
        /// Converts the given byte array to "hexadecimal" string.
        /// </summary>
        /// <param name="ba">The byte array to convert.</param>
        /// <returns>String in hexadecimal format.</returns>
        public static string ByteArrayToString(byte[] ba)
        {
            if (ba != null && ba.Length > 0) return BitConverter.ToString(ba).Replace("-", "");
            else return null;
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
                for (int i = 0; i < NumberChars; i += 2) bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
                return bytes;
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        /// Generate cryptographically strong random bytes using RNG based on given size.
        /// </summary>
        /// <param name="size">The size of byte array.</param>
        /// <returns>A byte array filled with random bytes.</returns>
        public static byte[] GenerateSecureRandomBytes(int size)
        {
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
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
            if (a1.Length != a2.Length) return false;
            for (int i = 0; i < a1.Length; ++i) if (a1[i] != a2[i]) return false;
            return true;
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
        public static byte[] Hash(byte[] data, HashAlgorithm halgo)
        {
            using (MemoryStream stream = new MemoryStream(data)) return Hash(stream, halgo);
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
        public static byte[] Hash(Stream stream, HashAlgorithm halgo)
        {
            if (stream.Length > 0 && halgo != null) using (HashAlgorithm h = halgo) return h.ComputeHash(stream);
            else throw new ArgumentException("The message to be hashed cannot be empty or null.");
        }

        /// <summary>
        /// Get item from a denominator splitted ASCII string, of given index.
        /// </summary>
        /// <param name="message">The byte array of ASCII string.</param>
        /// <param name="index">The index of the item within the protocol array.</param>
        /// <returns>The header from the formatted protocol string.</returns>
        public static string GetHeaderFromIndex(byte[] message, int index)
        {
            return Encoding.ASCII.GetString(message).Split(Splitter)[index];
        }
        #endregion

        #region File
        /// <summary>
        /// Encrypt a file from source file path to destination file path, using a password.
        /// </summary>
        /// <param name="FilePathIn">The path of the file to encrypt.</param>
        /// <param name="FilePathOut">The path to save the encrypted file.</param>
        /// <param name="password">The password to encrypt the file.</param>
        /// <param name="key_size">The size of the key for AES.</param>
        /// <param name="iterations">The amount of iterations to derive the key, from password.</param>
        public static async Task Encrypt(string FilePathIn, string FilePathOut, string password, int key_size = 256, int iterations = 10000)
        {
            if (string.IsNullOrWhiteSpace(FilePathIn)) throw new ArgumentException("The input file path cannot be empty or null.");
            else if (string.IsNullOrWhiteSpace(FilePathOut)) throw new ArgumentException("The output file path cannot be empty or null.");
            else if (string.IsNullOrWhiteSpace(password)) throw new ArgumentException("The password cannot be empty or null.");
            else if (key_size < 0 || !Aes.Create().ValidKeySize(key_size)) throw new ArgumentException("The key size is not valid.");
            else if (iterations < 1) throw new ArgumentException("The iteration count cannot be less than 1.");

            // Open the source file
            using (FileStream FileIn = new FileStream(FilePathIn, FileMode.Open))
            // Create the destination file
            using (FileStream FileOut = new FileStream(FilePathOut, FileMode.Create))
            {
                // Encrypt using text encryption
                await Encrypt(FileIn, FileOut, password, key_size, iterations);
            }
        }

        /// <summary>
        /// Decrypt a file from source file path to destination file path, using a password.
        /// </summary>
        /// <param name="FilePathIn">The path of the file to decrypt.</param>
        /// <param name="FilePathOut">The path to save the decrypted file.</param>
        /// <param name="password">The password to decrypt the file.</param>
        public static async Task Decrypt(string FilePathIn, string FilePathOut, string password)
        {
            if (string.IsNullOrWhiteSpace(FilePathIn)) throw new ArgumentException("The input file path cannot be empty or null.");
            else if (string.IsNullOrWhiteSpace(FilePathOut)) throw new ArgumentException("The output file path cannot be empty or null.");
            else if (string.IsNullOrWhiteSpace(password)) throw new ArgumentException("The password cannot be empty or null.");

            // Open the source file
            using (FileStream FileIn = new FileStream(FilePathIn, FileMode.Open))
            // Create the destination file
            using (FileStream FileOut = new FileStream(FilePathOut, FileMode.Create))
            {
                // Decrypt using text decrypt method
                await Decrypt(FileIn, FileOut, password);
            }
        }
        #endregion

        #region Text
        /// <summary>Encrypts a string message using given password.</summary>
        /// <param name="input">The message to encrypt.</param>
        /// <param name="password">The password to encrypt the message with.</param>
        /// <param name="iterations">The amount of iterations to derive the key, from password.</param>
        /// <param name="key_size">The size of the key for AES.</param>
        /// <returns>The encrypted message from the supplied message and password.</returns>
        public static async Task Encrypt(Stream input, Stream output, string password, int key_size = 256, int iterations = 10000)
        {
            if (input == null || input.Length == 0) throw new ArgumentException("The input cannot be empty or null.");
            else if (output == null) throw new ArgumentException("The output cannot be empty or null.");
            else if (string.IsNullOrWhiteSpace(password)) throw new ArgumentException("The password cannot be empty or null.");
            else if (key_size < 0 || !Aes.Create().ValidKeySize(key_size)) throw new ArgumentException("The key size is not valid.");
            else if (iterations < 1) throw new ArgumentException("The iteration count cannot be less than 1.");

            byte[] salt = GenerateSecureRandomBytes(key_size);
            byte[] iv = GenerateSecureRandomBytes(Aes.Create().BlockSize / 8);
            await Crypto(input, output, password, key_size, iterations, salt, iv, true);
        }

        /// <summary>
        /// Decrypts a string message using given password.
        /// </summary>
        /// <param name="input">
        /// The message to decrypt.
        /// </param>
        /// <param name="password">
        /// The password to decrypt the message with.
        /// </param>
        /// <returns>
        /// The decrypted message from the supplied message and password.
        /// </returns>
        public static async Task Decrypt(Stream input, Stream output, string password)
        {
            using (MemoryStream buffer = new MemoryStream())
            {
                await input.CopyToAsync(buffer);

                // Split all headers into their corresponding variables
                if (!GetHeaderFromIndex(buffer.ToArray(), 0).Equals(Identifier)) throw new FormatException("Supplied message is not applicable for decryption.");
                int key_size = int.Parse(GetHeaderFromIndex(buffer.ToArray(), 1));
                int iterations = int.Parse(GetHeaderFromIndex(buffer.ToArray(), 2));
                byte[] salt = Convert.FromBase64String(GetHeaderFromIndex(buffer.ToArray(), 3));
                byte[] iv = Convert.FromBase64String(GetHeaderFromIndex(buffer.ToArray(), 4));
                //byte[] encrypted = Convert.FromBase64String(payloads[5]);
                byte[] received_hash = Convert.FromBase64String(GetHeaderFromIndex(buffer.ToArray(), 6));

                // Perform HMAC comparison for message validation and integrity
                byte[] calculated_hash;
                using (Rfc2898DeriveBytes rfc = new Rfc2898DeriveBytes(password, salt, iterations))
                using (MemoryStream combined = new MemoryStream(Encoding.ASCII.GetBytes(string.Join(Splitter.ToString(), Identifier, key_size, iterations, Convert.ToBase64String(salt), Convert.ToBase64String(iv), Convert.ToBase64String(Convert.FromBase64String(GetHeaderFromIndex(buffer.ToArray(), 5)))))))
                using (HMAC hmac = HMAC.Create())
                {
                    hmac.Key = rfc.GetBytes(key_size / 8);
                    calculated_hash = hmac.ComputeHash(combined);
                }

                // Compare received hash with calculated hash
                if (!CompareByteArrays(received_hash, calculated_hash)) throw new HMACNotEqualException("The received HMAC does not equal the calculated HMAC.");

                // Begin decrypting
                using (MemoryStream MessageIn = new MemoryStream(Convert.FromBase64String(GetHeaderFromIndex(buffer.ToArray(), 5)))) await Crypto(MessageIn, output, password, key_size, iterations, salt, iv, false);
            }
        }
        #endregion

        #region Operations
        private static async Task Crypto(Stream input, Stream output, string password, int key_size, int iterations, byte[] salt, byte[] iv, bool encrypt)
        {
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = key_size;
                aes.Mode = CM;
                aes.Padding = PM;
                aes.IV = iv;

                // Derive key from password, salt and iterations
                using (Rfc2898DeriveBytes rfc = new Rfc2898DeriveBytes(password, salt, iterations))
                {
                    aes.Key = rfc.GetBytes(aes.KeySize / 8);
                }

                using (MemoryStream crypto = new MemoryStream())
                {
                    using (ICryptoTransform transform = encrypt ? aes.CreateEncryptor() : aes.CreateDecryptor())
                    using (CryptoStream cs = new CryptoStream(crypto, transform, CryptoStreamMode.Write))
                    {
                        // Encrypt: Input -> [Compress Functions] -> [Crypto Functions] -> Crypto
                        // Decrypt: Input -> [Crypto Functions] -> [Decompress Functions] -> Crypto
                        if (encrypt) using (GZipStream compression = new GZipStream(cs, CompressionMode.Compress)) await input.CopyToAsync(compression);
                        else await input.CopyToAsync(cs);
                    }

                    if (encrypt)
                    {
                        // Add headers
                        string salt_b64 = Convert.ToBase64String(salt);                                                         // Salt Base64
                        string iv_b64 = Convert.ToBase64String(iv);                                                             // IV Base64
                        //string ciphertext_b64 = Convert.ToBase64String(crypto.ToArray());                                       // Ciphertext Base64
                        //string final = string.Join(Splitter.ToString(), Identifier, key_size, iterations, salt_b64, iv_b64, ciphertext_b64);    // Penultimate Payload

                        // Add HMAC for integrity
                        string hash_b64 = string.Empty;
                        using (HMAC hmac = HMAC.Create())
                        {
                            hmac.Key = aes.Key;
                            byte[] hash = hmac.ComputeHash(Encoding.ASCII.GetBytes(string.Join(Splitter.ToString(), Identifier, key_size, iterations, salt_b64, iv_b64, Convert.ToBase64String(crypto.ToArray()))));
                            hash_b64 = Convert.ToBase64String(hash);
                            //final = string.Join(Splitter.ToString(), final, hash_b64);                                                          // Final Payload
                        }

                        // Wrap all data in ASCII and write to output
                        int length = Encoding.ASCII.GetByteCount(string.Join(Splitter.ToString(), Identifier, key_size, iterations, salt_b64, iv_b64, Convert.ToBase64String(crypto.ToArray()), hash_b64));
                        await output.WriteAsync(Encoding.ASCII.GetBytes(string.Join(Splitter.ToString(), Identifier, key_size, iterations, salt_b64, iv_b64, Convert.ToBase64String(crypto.ToArray()), hash_b64)), 0, length);
                    }
                    else
                    {
                        // No headers (decrypting), get plaintext (decompressed from GZipStream) from crypto stream
                        using (MemoryStream temp = new MemoryStream(crypto.ToArray()))
                        using (GZipStream compression = new GZipStream(temp, CompressionMode.Decompress))
                        {
                            // Write to output
                            await compression.CopyToAsync(output);
                        }
                    }
                }
            }
        }
        #endregion
    }
}