using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Sentrio.Tests
{
    [TestClass]
    public class CryptoWorksTests
    {
        /// <summary>
        /// Tests if <see cref="CryptoWorks.ByteArrayToString(byte[])"/> works correctly.
        /// </summary>
        [TestMethod, TestCategory("Utilities")]
        public void ByteArrayToStringTest()
        {
            byte[] ba = new byte[] { 0xFF, 0x45, 0x91, 0x3A };
            string result = CryptoWorks.ByteArrayToString(ba);
            string expected = "FF45913A";
            Assert.IsTrue(result.SequenceEqual(expected));
        }

        /// <summary>
        /// Tests if <see cref="CryptoWorks.StringToByteArray(string)"/> works correctly.
        /// </summary>
        [TestMethod, TestCategory("Utilities")]
        public void StringToByteArrayTest()
        {
            string s = "BD49AA1C";
            byte[] result = CryptoWorks.StringToByteArray(s);
            byte[] expected = new byte[] { 0xBD, 0x49, 0xAA, 0x1C };
            Assert.IsTrue(result.SequenceEqual(expected));
        }

        /// <summary>
        /// Tests if <see cref="CryptoWorks.GenerateSecureRandomBytes(int)"/> works correctly, by only checking if the byte array returned is the size specified.
        /// </summary>
        [TestMethod, TestCategory("Utilities")]
        public void GenerateSecureRandomBytesTest()
        {
            int length = 32;
            int result = CryptoWorks.GenerateSecureRandomBytes(length).Length;
            Assert.IsTrue(result == length);
        }

        /// <summary>
        /// Tests if <see cref="CryptoWorks.CompareByteArrays(byte[], byte[])"/> works correctly.
        /// Uses two test cases where two arrays equal and two arrays do not equal each other.
        /// </summary>
        [TestMethod, TestCategory("Utilities")]
        public void CompareByteArraysTest()
        {
            byte[] a1 = { 0x82, 0x44, 0xF4, 0x15, 0x77, 0x05 };
            byte[] a2 = { 0x9B, 0xE2, 0xAA, 0x3A, 0x6B, 0x82 };
            bool r1 = CryptoWorks.CompareByteArrays(a1, a2);

            byte[] a3 = { 0x78, 0x8D, 0x82, 0xFD, 0x34, 0xFE };
            byte[] a4 = { 0x78, 0x8D, 0x82, 0xFD, 0x34, 0xFE };
            bool r2 = CryptoWorks.CompareByteArrays(a3, a4);

            Assert.IsTrue(!r1 && r2);
        }

        /// <summary>
        /// Tests if <see cref="CryptoWorks.Hash(byte[], HashAlgorithm)"/> works correctly.
        /// </summary>
        [TestMethod, TestCategory("Utilities")]
        public void HashTest()
        {
            byte[] data = Encoding.ASCII.GetBytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
            byte[] r_sha1 = CryptoWorks.StringToByteArray("84983e441c3bd26ebaae4aa1f95129e5e54670f1");
            byte[] r_sha256 = CryptoWorks.StringToByteArray("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
            byte[] r_sha512 = CryptoWorks.StringToByteArray("204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445");

            // SHA1
            bool cond1 = CryptoWorks.CompareByteArrays(r_sha1, CryptoWorks.Hash(data, SHA1.Create()));

            // SHA256
            bool cond2 = CryptoWorks.CompareByteArrays(r_sha256, CryptoWorks.Hash(data, SHA256.Create()));

            // SHA512
            bool cond3 = CryptoWorks.CompareByteArrays(r_sha512, CryptoWorks.Hash(data, SHA512.Create()));

            Assert.IsTrue(cond1 && cond2 && cond3);
        }

        /// <summary>
        /// Tests if <see cref="CryptoWorks.Encrypt(byte[], byte[])"/> works correctly.
        /// Incidently tests <see cref="CryptoWorks.Decrypt(byte[], byte[])"/> too.
        /// </summary>
        [TestMethod, TestCategory("Crypto")]
        public async Task TextEncryptDecryptTest()
        {
            string message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
            string password = "1234567890";
            int key_size = 128;
            int iterations = 100;

            try
            {
                // Encryption
                byte[] data = Encoding.ASCII.GetBytes(message);
                string ciphertext = string.Empty;
                using (MemoryStream input = new MemoryStream(data))
                using (MemoryStream output = new MemoryStream())
                {
                    await CryptoWorks.Encrypt(input, output, password, key_size, iterations);
                    ciphertext = Encoding.ASCII.GetString(output.ToArray());
                }

                // Decryption
                byte[] ciphertext_data = Encoding.ASCII.GetBytes(ciphertext);
                string plaintext = string.Empty;
                using (MemoryStream input = new MemoryStream(ciphertext_data))
                using (MemoryStream output = new MemoryStream())
                {
                    await CryptoWorks.Decrypt(input, output, password);
                    plaintext = Encoding.ASCII.GetString(output.ToArray());
                }

                Assert.IsTrue(plaintext.SequenceEqual(message));
            }
            catch (Exception e)
            {
                Assert.Fail(e.ToString());
            }
        }

        /// <summary>
        /// Tests if <see cref="CryptoWorks.Encrypt(string, string, string, int, int)"/> works correctly.
        /// Incidently tests <see cref="CryptoWorks.Decrypt(string, string, string)"/> too.
        /// </summary>
        [TestMethod, TestCategory("Crypto")]
        public async Task FileEncryptDecryptTest()
        {
            string password = "1234567890";
            int key_size = 128;
            int iterations = 100;

            try
            {
                // Prepare file path
                string project_path = Path.GetDirectoryName(Path.GetDirectoryName(Directory.GetCurrentDirectory()));
                string file_path = $@"{project_path}\testfile.dat";
                string encrypted_file_path = $@"{file_path}.test";

                // Data generation
                // Generate 1mb of random data
                byte[] random_data;
                using (MemoryStream input = new MemoryStream(CryptoWorks.GenerateSecureRandomBytes(1024 * 1024)))
                using (FileStream output = new FileStream(file_path, FileMode.Create))
                {
                    // Writing generated bytes to file
                    await input.CopyToAsync(output);
                    random_data = input.ToArray();
                }

                // Encryption
                await CryptoWorks.Encrypt(file_path, encrypted_file_path, password, key_size, iterations);
                File.Delete(file_path);

                // Decryption
                await CryptoWorks.Decrypt(encrypted_file_path, file_path, password);
                File.Delete(encrypted_file_path);

                byte[] read_data;
                using (FileStream input = new FileStream(file_path, FileMode.Open))
                using (MemoryStream output = new MemoryStream())
                {
                    // Reading bytes from file
                    await input.CopyToAsync(output);
                    read_data = output.ToArray();
                }
                File.Delete(file_path);

                // Compare generated with received
                Assert.IsTrue(CryptoWorks.CompareByteArrays(random_data, read_data));
            }
            catch (Exception e)
            {
                Assert.Fail(e.ToString());
            }
        }
    }
}