using Sentrio;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System;

namespace Sentrio.Tests
{
    [TestClass]
    public class CryptoWorksTests
    {
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
        /// Tests if <see cref="CryptoWorks.ByteArrayToString(byte[])"/> works correctly.
        /// </summary>
        [TestMethod, TestCategory("Utilities")]
        public void ByteArrayToStringTest()
        {
            byte[] a = { 0x76, 0x69, 0xC0, 0xDB, 0x5F, 0x3E };
            string expected = "7669c0db5f3e";
            string actual = CryptoWorks.ByteArrayToString(a);

            Assert.IsTrue(expected.SequenceEqual(actual));
        }

        /// <summary>
        /// Tests if <see cref="CryptoWorks.StringToByteArray(string)"/> works correctly.
        /// Does not depend on <see cref="CryptoWorks.CompareByteArrays(byte[], byte[])"/>.
        /// </summary>
        [TestMethod, TestCategory("Utilities")]
        public void StringToByteArrayTest()
        {
            string hex = "813C18D33137";
            byte[] expected = { 0x81, 0x3C, 0x18, 0xD3, 0x31, 0x37 };
            byte[] actual = CryptoWorks.StringToByteArray(hex);

            Assert.IsTrue(expected.SequenceEqual(actual));
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
            bool cond1, cond2, cond3 = false;

            // SHA1
            {
                byte[] actual = new CryptoWorks().Hash(data, SHA1.Create());
                cond1 = CryptoWorks.CompareByteArrays(r_sha1, actual);
            }

            // SHA256
            {
                byte[] actual = new CryptoWorks().Hash(data, SHA256.Create());
                cond2 = CryptoWorks.CompareByteArrays(r_sha256, actual);
            }

            // SHA512
            {
                byte[] actual = new CryptoWorks().Hash(data, SHA512.Create());
                cond3 = CryptoWorks.CompareByteArrays(r_sha512, actual);
            }

            Assert.IsTrue(cond1 && cond2 && cond3);
        }

        /// <summary>
        /// Tests if <see cref="CryptoWorks.Encrypt(byte[], byte[])"/> works correctly.
        /// Incidently tests <see cref="CryptoWorks.Decrypt(byte[], byte[])"/> too.
        /// </summary>
        [TestMethod, TestCategory("Crypto")]
        public void EncryptTest()
        {
            string message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
            byte[] password = Encoding.ASCII.GetBytes("1234567890");
            try
            {
                // Encryption
                byte[] data = Encoding.ASCII.GetBytes(message);
                byte[] cipherdata = new CryptoWorks().Encrypt(data, password);
                string ciphertext = Convert.ToBase64String(cipherdata);

                // Decryption
                byte[] ciphertext_data = Convert.FromBase64String(ciphertext);
                byte[] plaintext_data = new CryptoWorks().Decrypt(ciphertext_data, password);
                string plaintext = Encoding.ASCII.GetString(plaintext_data);

                Assert.IsTrue(plaintext.SequenceEqual(message));
            }
            catch (Exception e)
            {
                Assert.Fail(e.ToString());
            }
        }
    }
}