using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Sentrio
{
    public class Crypto
    {
        public const char Splitter = ':';
        public const string Identifier = "Sentrio.2";
        public const CipherMode CM = CipherMode.CBC;
        public const PaddingMode PM = PaddingMode.PKCS7;

        public static byte[] FromSafeBytes(byte[] array)
        {
            return Convert.FromBase64String(Encoding.ASCII.GetString(array));
        }

        public static byte[] ToSafeBytes(byte[] array)
        {
            return Encoding.ASCII.GetBytes(Convert.ToBase64String(array));
        }

        public static async Task Write(Stream stream, byte[] array)
        {
            await stream.WriteAsync(array, 0, array.Length);
        }

        /// <summary>
        /// Encrypt a file from source file path to destination file path, using a password.
        /// </summary>
        /// <param name="FilePathIn">The path of the file to encrypt.</param>
        /// <param name="FilePathOut">The path to save the encrypted file.</param>
        /// <param name="password">The password to encrypt the file.</param>
        /// <param name="key_size">The size of the key for AES.</param>
        /// <param name="iterations">The amount of iterations to derive the key, from password.</param>
        public static async Task Encrypt(string FilePathIn, string FilePathOut, string password, int key_size, int iterations)
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

        public static async Task Encrypt(Stream input, Stream output, string password, int key_size, int iterations)
        {
            #region Parameter Validation
            if (input == null || input.Length == 0)
                throw new ArgumentException("The input stream cannot be empty or null.");
            else if (output == null)
                throw new ArgumentException("The output stream cannot be null.");
            else if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("The password cannot be empty or null.");
            else if (key_size < 0 || !Utilities.ValidKeySize(key_size))
                throw new ArgumentException("The key size is not valid.");
            else if (iterations < 1)
                throw new ArgumentException("The iteration count cannot be less than 1.");
            #endregion

            #region Salt and IV Generation
            byte[] salt = Utilities.GetSecureRandomBytes(key_size / 8);
            byte[] iv = Utilities.GetSecureRandomBytes(Aes.Create().BlockSize / 8);
            #endregion

            Encoding encoding = Encoding.ASCII;

            #region Writing Headers
            for (int i = 0; i < 5; ++i)
            {
                if (i == 0)
                    await Write(output, ToSafeBytes(encoding.GetBytes(Identifier)));                // Identifier
                else if (i == 1)
                    await Write(output, ToSafeBytes(encoding.GetBytes(key_size.ToString())));       // Key Size
                else if (i == 2)
                    await Write(output, ToSafeBytes(encoding.GetBytes(iterations.ToString())));     // Iterations
                else if (i == 3)
                    await Write(output, ToSafeBytes(salt));                                         // Salt
                else if (i == 4)
                    await Write(output, ToSafeBytes(iv));                                           // IV

                await Write(output, encoding.GetBytes(Splitter.ToString()));
            }
            // State = identifier:key_size:iterations:salt_b64:iv_b64:
            #endregion

            using (Aes aes = Aes.Create())
            {
                #region AES Initialisation
                aes.KeySize = key_size;
                aes.Mode = CM;
                aes.Padding = PM;
                aes.IV = iv;
                #endregion

                #region Key Derivation
                using (Rfc2898DeriveBytes rfc = new Rfc2898DeriveBytes(password, salt, iterations))
                    aes.Key = rfc.GetBytes(aes.KeySize / 8);
                #endregion

                #region Payload Encryption
                using (MemoryStream stream = new MemoryStream())
                using (ICryptoTransform transform = aes.CreateEncryptor())
                using (CryptoStream cs = new CryptoStream(stream, transform, CryptoStreamMode.Write))
                {
                    int current;
                    long counter = 1;
                    while ((current = input.ReadByte()) != -1)
                    {
                        cs.WriteByte((byte)current);
                        if (counter % aes.BlockSize == 0)
                        {
                            cs.Flush();
                            await Write(output, ToSafeBytes(stream.ToArray()));
                            stream.Seek(0, SeekOrigin.Begin);
                        }
                        counter += 1;
                    }
                    // Flush then write to output
                    cs.FlushFinalBlock();
                    // If incomplete block
                    if (counter % aes.BlockSize != 0)
                        await Write(output, ToSafeBytes(stream.ToArray()));
                }
                await Write(output, encoding.GetBytes(Splitter.ToString()));
                // State = identifier:key_size:iterations:salt_b64:iv_b64:crypto:
                #endregion

                #region HMAC Calculation
                // Go back to the start of the output stream to perform HMAC calculation
                output.Seek(0, SeekOrigin.Begin);
                using (HMAC hmac = HMAC.Create())
                {
                    hmac.Key = aes.Key;
                    byte[] hash = hmac.ComputeHash(output);
                    await Write(output, ToSafeBytes(hash));
                }
                // State = identifier:key_size:iterations:salt_b64:iv_b64:crypto:hash_b64
                #endregion
            }
        }

        public static async Task Decrypt(Stream input, Stream output, string password)
        {
            #region Parameter Validation
            if (input == null || input.Length == 0)
                throw new ArgumentException("The input stream cannot be empty or null.");
            else if (output == null)
                throw new ArgumentException("The output stream cannot be null.");
            else if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("The password cannot be empty or null.");
            #endregion

            Encoding encoding = Encoding.ASCII;
            string identifier = string.Empty;
            int key_size = -1;
            int iterations = -1;
            byte[] salt_bytes = null;
            byte[] iv_bytes = null;
            byte[] received_hash_bytes = null;
            byte[] calculated_hash_bytes = null;

            #region Header Extraction
            for (int i = 0; i < 5; ++i)
            {
                using (MemoryStream stream = new MemoryStream())
                {
                    for (long l = input.Position; l < input.Length; ++l)
                    {
                        byte current = (byte)input.ReadByte();
                        if (current == encoding.GetBytes(Splitter.ToString())[0])
                            break;
                        else
                            stream.WriteByte(current);
                    }

                    byte[] result = FromSafeBytes(stream.ToArray());
                    if (i == 0)
                        identifier = encoding.GetString(result);                // Identifier
                    else if (i == 1)
                        key_size = int.Parse(encoding.GetString(result));       // Key Size
                    else if (i == 2)
                        iterations = int.Parse(encoding.GetString(result));     // Iterations
                    else if (i == 3)
                        salt_bytes = result;                                    // Salt
                    else if (i == 4)
                        iv_bytes = result;                                      // IV
                }
            }
            #endregion

            long payload_pos = input.Position;

            #region HMAC Extraction
            // Skip over payload to HMAC
            while ((byte)input.ReadByte() != encoding.GetBytes(Splitter.ToString())[0]) { }
            long exc_hmac = input.Position;
            using (MemoryStream stream = new MemoryStream())
            {
                for (long i = input.Position; i < input.Length; ++i)
                {
                    // No need to check for a delimiter, we've reached the tail, which has 1 item
                    stream.WriteByte((byte)input.ReadByte());
                }
                received_hash_bytes = FromSafeBytes(stream.ToArray());
            }
            #endregion

            #region Header/Trailer Validation
            if (string.IsNullOrWhiteSpace(identifier)) throw new FormatException("Identifier was not found in the input.");
            else if (!identifier.Equals(Identifier)) throw new FormatException("Identifier in stream did not equal expected identifier.");
            else if (key_size == -1 || !Utilities.ValidKeySize(key_size)) throw new ArgumentOutOfRangeException("The key size is not valid for this algorithm.");
            else if (iterations == -1 || iterations < 1) throw new ArgumentOutOfRangeException("The iteration count is not valid for this operation.");
            else if (salt_bytes == null || salt_bytes.Length == 0) throw new FormatException("The salt was not found in the input.");
            else if (iv_bytes == null || iv_bytes.Length == 0) throw new FormatException("The IV was not found in the input.");
            else if (received_hash_bytes == null || received_hash_bytes.Length == 0) throw new FormatException("The HMAC was not found in the input.");
            #endregion

            using (Aes aes = Aes.Create())
            {
                #region AES Initialisation
                aes.KeySize = key_size;
                aes.IV = iv_bytes;
                aes.Mode = CM;
                aes.Padding = PM;
                #endregion

                #region Key Derivation
                using (Rfc2898DeriveBytes rfc = new Rfc2898DeriveBytes(password, salt_bytes, iterations))
                    aes.Key = rfc.GetBytes(aes.KeySize / 8);
                #endregion

                #region HMAC Calculation and Comparison
                // Seek to the start of the input, and limit length (just before received HMAC), to perform HMAC calculation
                input.Seek(0, SeekOrigin.Begin);
                input.SetLength(exc_hmac);
                using (HMAC hmac = HMAC.Create())
                {
                    hmac.Key = aes.Key;
                    calculated_hash_bytes = hmac.ComputeHash(input);
                    if (!Utilities.CompareByteArrays(received_hash_bytes, calculated_hash_bytes)) throw new HMACNotEqualException("The received HMAC does not equal the calculated HMAC.");
                }
                #endregion

                #region Payload Decryption
                input.Seek(payload_pos, SeekOrigin.Begin);
                using (MemoryStream stream = new MemoryStream())
                using (ICryptoTransform transform = aes.CreateDecryptor())
                using (CryptoStream cs = new CryptoStream(output, transform, CryptoStreamMode.Write))
                {
                    int current;
                    long counter = 1;
                    while ((current = input.ReadByte()) != -1)
                    {
                        if ((byte)current == encoding.GetBytes(Splitter.ToString())[0]) break;
                        stream.WriteByte((byte)current);
                        // If bytes == block size
                        if (counter % aes.BlockSize == 0)
                        {
                            cs.Flush();
                            // Convert from safe bytes, then into the crypto stream
                            await Write(cs, FromSafeBytes(stream.ToArray()));
                            stream.Seek(0, SeekOrigin.Begin);
                        }
                        counter += 1;
                    }
                    // Reverse of encryption - write to crypto, then flush (done implicitly)
                    //cs.FlushFinalBlock();
                    // incomplete block
                    if (counter % aes.BlockSize != 0)
                        await Write(cs, FromSafeBytes(stream.ToArray()));
                }
                #endregion
            }
        }
    }
}
