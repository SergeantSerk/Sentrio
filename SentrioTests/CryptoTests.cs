using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace Sentrio.Tests
{
    [TestClass]
    public class CryptoTests
    {
        [TestMethod, TestCategory("Crypto")]
        public async Task EncryptTest()
        {
            string message = "Hello world";
            string password = "123";

            byte[] ciphertext;
            using (MemoryStream input = new MemoryStream(Encoding.ASCII.GetBytes(message)))
            using (MemoryStream output = new MemoryStream())
            {
                await Crypto.Encrypt(input, output, password, 128, 1000);
                ciphertext = output.ToArray();
            }

            string result;
            using (MemoryStream input = new MemoryStream(ciphertext))
            using (MemoryStream output = new MemoryStream())
            {
                await Crypto.Decrypt(input, output, password);
                result = Encoding.ASCII.GetString(output.ToArray());
            }

            Assert.IsTrue(result.Equals(message));
        }
    }
}
