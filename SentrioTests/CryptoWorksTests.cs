using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Linq;

namespace Sentrio.Tests
{
    [TestClass()]
    public class CryptoWorksTests
    {
        /// <summary>
        /// Tests if <see cref="CryptoWorks.CompareByteArrays(byte[], byte[])"/> works correctly.
        /// Uses two test cases where two arrays equal and two arrays do not equal each other.
        /// </summary>
        [TestMethod()]
        public void CompareByteArraysTest()
        {
            byte[] a1 = { 0x82, 0x44, 0xF4, 0x15, 0x77, 0x05 };
            byte[] a2 = { 0x9B, 0xE2, 0xAA, 0x3A, 0x6B, 0x82 };
            bool r1 = new CryptoWorks().CompareByteArrays(a1, a2);

            byte[] a3 = { 0x78, 0x8D, 0x82, 0xFD, 0x34, 0xFE };
            byte[] a4 = { 0x78, 0x8D, 0x82, 0xFD, 0x34, 0xFE };
            bool r2 = new CryptoWorks().CompareByteArrays(a3, a4);

            Assert.IsTrue(!r1 && r2);
        }

        /// <summary>
        /// Tests if <see cref="CryptoWorks.ByteArrayToString(byte[])"/> works correctly.
        /// </summary>
        [TestMethod()]
        public void ByteArrayToStringTest()
        {
            byte[] a = { 0x76, 0x69, 0xC0, 0xDB, 0x5F, 0x3E };
            string expected = "7669c0db5f3e";
            string actual = new CryptoWorks().ByteArrayToString(a);

            Assert.IsTrue(expected.SequenceEqual(actual));
        }

        /// <summary>
        /// Tests if <see cref="CryptoWorks.StringToByteArray(string)"/> works correctly.
        /// Does not depend on <see cref="CryptoWorks.CompareByteArrays(byte[], byte[])"/>.
        /// </summary>
        [TestMethod()]
        public void StringToByteArrayTest()
        {
            string hex = "813C18D33137";
            byte[] expected = { 0x81, 0x3C, 0x18, 0xD3, 0x31, 0x37 };
            byte[] actual = new CryptoWorks().StringToByteArray(hex);

            Assert.IsTrue(expected.SequenceEqual(actual));
        }
    }
}