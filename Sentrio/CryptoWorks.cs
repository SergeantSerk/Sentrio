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
        private static Aes AES = new AesCryptoServiceProvider() { Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 };
        // public const CipherMode CM = CipherMode.CBC;
        // public const PaddingMode PM = PaddingMode.PKCS7;
        // public const int KeySize = 256;
        // public const int SaltSize = KeySize / 8;
        public int iterations = 10000;

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
        /// Generate a cryptographically strong random salt using RNG based on given salt size.
        /// </summary>
        /// <param name="saltSize">The size of salt.</param>
        /// <returns>Byte array of the generated salt.</returns>
        public byte[] GenerateRandomSalt(int saltSize)
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] random = new byte[saltSize];
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
        public async Task Encrypt(string FilePathIn, string FilePathOut, string password)
        {
            // Open the source file
            using (var FileIn = new FileStream(FilePathIn, FileMode.Open))
            // Create the destination file
            using (var FileOut = new FileStream(FilePathOut, FileMode.Create))
            // Derive key using password, salt (length of IV) and iterations
            using (var RFC = new Rfc2898DeriveBytes(password, AES.IV.Length, iterations))
            {
                // Set AES key from RFC key derivation
                AES.Key = RFC.GetBytes(AES.KeySize / 8);

                // Encrypt file and get the stream
                using (var CryptoStream = await Crypto(FileIn, AES, RFC, true))
                {
                    byte[] data = CryptoStream.ToArray();               // Get encrypted content
                    await FileOut.WriteAsync(data, 0, data.Length);     // Write to destination file
                }
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
                byte[] IV = new byte[FileIn.ReadByte()];
                // Fill the array with bytes from file, in the current position and of array length
                FileIn.Read(IV, 0, IV.Length);

                // Derive key using password, retrieved salt and retrieved iterations
                using (var RFC = new Rfc2898DeriveBytes(password, salt, iterations))
                {
                    // Set AES key from RFC key derivation
                    AES.Key = RFC.GetBytes(AES.KeySize / 8);
                    // Set AES IV from IV retrieved in file
                    AES.IV = IV;

                    // Decrypt file and get the stream
                    using (var CryptoStream = await Crypto(FileIn, AES, RFC, false))
                    {
                        // Maybe use copyto?
                        byte[] data = CryptoStream.ToArray();   // Get decrypted content
                        await FileOut.WriteAsync(data, 0, data.Length);    // Write to destination file
                    }
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
        public async Task<byte[]> Encrypt(byte[] message, byte[] password)
        {
            using (var MessageIn = new MemoryStream(message))
            using (var RFC = new Rfc2898DeriveBytes(password, await Task.Run(() => GenerateRandomSalt(AES.IV.Length)), iterations))
            {
                AES.Key = RFC.GetBytes(AES.KeySize / 8);

                using (MemoryStream MessageOut = await Crypto(MessageIn, AES, RFC, true))
                {
                    return MessageOut.ToArray();
                }
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
        public async Task<byte[]> Decrypt(byte[] message, byte[] password)
        {
            using (var MessageIn = new MemoryStream(message))
            {
                byte[] IterationsBytes = new byte[MessageIn.ReadByte()];
                MessageIn.Read(IterationsBytes, 0, IterationsBytes.Length);
                int iterations = int.Parse(Encoding.ASCII.GetString(IterationsBytes));
                byte[] salt = new byte[(MessageIn.ReadByte())];
                MessageIn.Read(salt, 0, salt.Length);
                byte[] IV = new byte[MessageIn.ReadByte()];
                MessageIn.Read(IV, 0, IV.Length);

                using (var RFC = new Rfc2898DeriveBytes(password, salt, iterations))
                {
                    AES.Key = RFC.GetBytes(AES.KeySize / 8);
                    AES.IV = IV;

                    using (var MessageOut = await Crypto(MessageIn, AES, RFC, false))
                    {
                        return MessageOut.ToArray();
                    }
                }
            }
        }
        #endregion

        #region Operations
        #region Old
        /*
        private Stream Encrypt(Stream StreamIn, string password)
        {
            // Create a custom Aes object that has predefined parameters
            using (var sk = aes())
            using (var rfc = new Rfc2898DeriveBytes(password, sk.KeySize / 8))
            {
                #region Salt
                // Hold salt bytes that have been generated by the Rfc2898 class
                byte[] salt = rfc.Salt;
                // Hold the length of the salt byte array for use in decryption
                byte saltLength = Convert.ToByte(salt.Length);
                #endregion

                #region IV
                // Hold the IV bytes that have been automatically generated when initialising the Aes class
                byte[] iv = sk.IV;
                // Hold the length of the IV byte array for use in decryption
                byte IvLength = Convert.ToByte(iv.Length);
                #endregion

                #region Key Derivation
                // Derive key byte array from the given password string, salt and iterations, based on the
                // key size used
                byte[] key = rfc.GetBytes(sk.KeySize / 8);
                // Set the key of the custom Aes object to the derived key
                sk.Key = key;
                #endregion

                using (var StreamOut = new MemoryStream())
                {
                    using (var transform = sk.CreateEncryptor())
                    using (var cs = new CryptoStream(StreamOut, transform, CryptoStreamMode.Write))
                    {
                        #region Headers
                        // Write the salt length, salt, IV length and IV to the start of the
                        // file, in their respective order, then finalise with the encrypted content
                        StreamOut.WriteByte(saltLength);            // Salt Length
                        StreamOut.Write(salt, 0, salt.Length);      // Salt
                        StreamOut.WriteByte(IvLength);              // IV Length
                        StreamOut.Write(iv, 0, iv.Length);          // IV
                        StreamOut.WriteByte((byte)StreamIn.Length); // Data length
                        #endregion

                        #region Data
                        // Write the decrypted stream to file and flush final block.
                        // This is not recommended as it does not give steps where progress
                        // can be tracked.
                        StreamIn.CopyTo(cs);

                        cs.FlushFinalBlock();
                        #endregion
                    }

                    // Return encrypt output stream
                    return new MemoryStream(StreamOut.ToArray());
                }
            }
        }

        private Stream Decrypt(Stream StreamIn, string password)
        {
            using (var sk = aes())
            {
                #region Salt
                // Read from first byte which holds the salt length
                int saltLength = StreamIn.ReadByte();
                // Create a salt byte array of size saltLength that was read previously
                byte[] salt = new byte[saltLength];
                // Fill the salt byte array with bytes of given length
                StreamIn.Read(salt, 0, salt.Length);
                #endregion

                #region IV
                // Read from current byte which holds the IV length
                int IvLength = StreamIn.ReadByte();
                // Create an IV byte array of size ivLength that was read previously
                byte[] iv = new byte[IvLength];
                // Fill the IV byte array with bytes of given length
                StreamIn.Read(iv, 0, iv.Length);
                #endregion

                #region Data Information
                // Read from current byte which holds the length of data
                int DataLength = StreamIn.ReadByte();
                #endregion

                // Derive key from the password and retrieved salt from file
                using (var rfc = new Rfc2898DeriveBytes(password, salt))
                {
                    #region Key Derivation
                    // Derive key byte array from the given password string, salt and iterations, based on the
                    // key size used
                    byte[] key = rfc.GetBytes(sk.KeySize / 8);
                    #endregion

                    sk.Key = key;
                    sk.IV = iv;

                    using (var StreamOut = new MemoryStream())
                    {
                        using (var transform = sk.CreateDecryptor())
                        using (var cs = new CryptoStream(StreamOut, transform, CryptoStreamMode.Write))
                        {
                            #region Data
                            // Write the decrypted stream to file and flush final block.
                            // This is not recommended as it does not give steps where progress
                            // can be tracked.
                            StreamIn.CopyTo(cs);
                            #endregion
                        }
                        return new MemoryStream(StreamOut.ToArray());
                    }
                }
            }
            */
        #endregion

        #region New
        private async Task<MemoryStream> Crypto(Stream MessageIn, Aes AES, Rfc2898DeriveBytes RFC, bool encrypt)
        {
            MemoryStream MessageOut = new MemoryStream();
            using (var transform = encrypt ? AES.CreateEncryptor() : AES.CreateDecryptor())
            using (var CS = new CryptoStream(MessageOut, transform, CryptoStreamMode.Write))
            {
                if (encrypt)
                {
                    byte[] IterationBytes = Encoding.ASCII.GetBytes(RFC.IterationCount.ToString());
                    MessageOut.WriteByte(Convert.ToByte(IterationBytes.Length));    // Iteration Length
                    MessageOut.Write(IterationBytes, 0, IterationBytes.Length);     // Iteration
                    MessageOut.WriteByte(Convert.ToByte(RFC.Salt.Length));          // Salt Length
                    MessageOut.Write(RFC.Salt, 0, RFC.Salt.Length);                 // Salt
                    MessageOut.WriteByte(Convert.ToByte(AES.IV.Length));            // IV Length
                    MessageOut.Write(AES.IV, 0, AES.IV.Length);                     // IV

                    await MessageIn.CopyToAsync(CS);                                           // Ciphertext
                }
                else
                {
                    await MessageIn.CopyToAsync(CS);
                }
            }
            return MessageOut;
        }
        #endregion
        #endregion
    }
}