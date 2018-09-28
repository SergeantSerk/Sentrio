using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Sentrio
{
    public class Utilities
    {
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
        public static byte[] GetSecureRandomBytes(int size)
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
        /// <param name="splitter">The delimiter for the protocol array.</param>
        /// <param name="index">The index of the item within the protocol array.</param>
        /// <returns>The header from the formatted protocol string.</returns>
        public static string GetHeaderFromIndex(byte[] message, char splitter, int index)
        {
            return Encoding.ASCII.GetString(message).Split(splitter)[index];
        }

        /// <summary>
        /// Checks if supplied key size is valid.
        /// </summary>
        /// <param name="key_size">The key size.</param>
        /// <returns>Whether the supplied key size is valid for AES.</returns>
        public static bool ValidKeySize(int key_size)
        {
            return Aes.Create().ValidKeySize(key_size);
        }
    }
}
