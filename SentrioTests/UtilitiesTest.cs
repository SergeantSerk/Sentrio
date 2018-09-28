using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Sentrio.Tests
{
    [TestClass]
    public class UtilitiesTest
    {
        /// <summary>
        /// Tests if <see cref="Utilities.ByteArrayToString(byte[])"/> works correctly.
        /// </summary>
        [TestMethod, TestCategory("Utilities")]
        public void ByteArrayToStringTest()
        {
            byte[] ba = new byte[] { 0xFF, 0x45, 0x91, 0x3A };
            string result = Utilities.ByteArrayToString(ba);
            string expected = "FF45913A";
            Assert.IsTrue(result.SequenceEqual(expected));
        }

        /// <summary>
        /// Tests if <see cref="Utilities.StringToByteArray(string)"/> works correctly.
        /// </summary>
        [TestMethod, TestCategory("Utilities")]
        public void StringToByteArrayTest()
        {
            string s = "BD49AA1C";
            byte[] result = Utilities.StringToByteArray(s);
            byte[] expected = new byte[] { 0xBD, 0x49, 0xAA, 0x1C };
            Assert.IsTrue(result.SequenceEqual(expected));
        }

        /// <summary>
        /// Tests if <see cref="Utilities.GetSecureRandomBytes(int)"/> works correctly, by only checking if the byte array returned is the size specified.
        /// </summary>
        [TestMethod, TestCategory("Utilities")]
        public void GenerateSecureRandomBytesTest()
        {
            int length = 32;
            int result = Utilities.GetSecureRandomBytes(length).Length;
            Assert.IsTrue(result == length);
        }

        /// <summary>
        /// Tests if <see cref="Utilities.CompareByteArrays(byte[], byte[])"/> works correctly.
        /// Uses two test cases where two arrays equal and two arrays do not equal each other.
        /// </summary>
        [TestMethod, TestCategory("Utilities")]
        public void CompareByteArraysTest()
        {
            byte[] a1 = { 0x82, 0x44, 0xF4, 0x15, 0x77, 0x05 };
            byte[] a2 = { 0x9B, 0xE2, 0xAA, 0x3A, 0x6B, 0x82 };
            bool r1 = Utilities.CompareByteArrays(a1, a2);

            byte[] a3 = { 0x78, 0x8D, 0x82, 0xFD, 0x34, 0xFE };
            byte[] a4 = { 0x78, 0x8D, 0x82, 0xFD, 0x34, 0xFE };
            bool r2 = Utilities.CompareByteArrays(a3, a4);

            Assert.IsTrue(!r1 && r2);
        }

        /// <summary>
        /// Tests if <see cref="Utilities.Hash(byte[], HashAlgorithm)"/> works correctly.
        /// </summary>
        [TestMethod, TestCategory("Utilities")]
        public void HashTest()
        {
            byte[] data = Encoding.ASCII.GetBytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
            byte[] r_sha1 = Utilities.StringToByteArray("84983e441c3bd26ebaae4aa1f95129e5e54670f1");
            byte[] r_sha256 = Utilities.StringToByteArray("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
            byte[] r_sha512 = Utilities.StringToByteArray("204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445");

            // SHA1
            bool cond1 = Utilities.CompareByteArrays(r_sha1, Utilities.Hash(data, SHA1.Create()));

            // SHA256
            bool cond2 = Utilities.CompareByteArrays(r_sha256, Utilities.Hash(data, SHA256.Create()));

            // SHA512
            bool cond3 = Utilities.CompareByteArrays(r_sha512, Utilities.Hash(data, SHA512.Create()));

            Assert.IsTrue(cond1 && cond2 && cond3);
        }

        /// <summary>
        /// Tests if <see cref="Utilities.ValidKeySize(int)"/> works correctly.
        /// </summary>
        [TestMethod, TestCategory("Utilities")]
        public void ValidKeySizeTest()
        {
            int key_size1 = 128;
            int key_size2 = 64;
            Assert.IsTrue(Utilities.ValidKeySize(key_size1) && !Utilities.ValidKeySize(key_size2));
        }
    }
}
