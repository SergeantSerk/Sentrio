using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Sentrio;
using System.IO;
using System.Security.Cryptography;

namespace Scratchpad
{
    class Program
    {
        public static void Main(string[] args)
        {
            Console.Write("Message: ");
            string message = Console.ReadLine();
            Console.Write("Password: ");
            string password = Console.ReadLine();

            byte[] data = Encoding.UTF8.GetBytes(message);
            using (MemoryStream output = new MemoryStream())
            using (MemoryStream ciphertext = new MemoryStream())
            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.KeySize = 256;

                using (Rfc2898DeriveBytes rfc = new Rfc2898DeriveBytes(password, aes.KeySize / 8, 10000))
                {
                    aes.Key = rfc.GetBytes(aes.KeySize / 8);

                    using (ICryptoTransform transform = aes.CreateEncryptor())
                    using (MemoryStream input = new MemoryStream(data))
                    using (CryptoStream cs = new CryptoStream(ciphertext, transform, CryptoStreamMode.Write))
                    {
                        input.CopyTo(cs);
                    }

                    string result = $"{Convert.ToBase64String(rfc.Salt)}:{Convert.ToBase64String(aes.IV)}:{Convert.ToBase64String(ciphertext.ToArray())}";
                    byte[] result_data = Encoding.ASCII.GetBytes(result);
                    output.Write(result_data, 0, result_data.Length);
                    output.Flush();

                    Console.Clear();
                    Console.WriteLine($"Message:        {message}");
                    Console.WriteLine($"Password:       {password}");
                    Console.WriteLine($"Cipher Mode:    {aes.Mode}");
                    Console.WriteLine($"Padding Mode:   {aes.Padding}");
                    Console.WriteLine($"Key Size:       {aes.KeySize}");
                    Console.WriteLine($"Block Size:     {aes.BlockSize}");
                    Console.WriteLine($"IV Size:        {aes.IV.Length}");
                    Console.WriteLine($"Salt Size:      {rfc.Salt.Length}");
                    Console.WriteLine($"Feedback Size:  {aes.FeedbackSize}");
                    Console.WriteLine($"Key:            {Convert.ToBase64String(aes.Key)}");
                    Console.WriteLine($"IV:             {Convert.ToBase64String(aes.IV)}");
                    Console.WriteLine($"Salt:           {Convert.ToBase64String(rfc.Salt)}");
                    Console.WriteLine($"Ciphertext:     {Convert.ToBase64String(ciphertext.ToArray())}");
                    Console.WriteLine($"Result:         {Encoding.ASCII.GetString(output.ToArray())}");
                }
            }

            Console.ReadLine();

            string res = Encoding.ASCII.GetString(Encrypt(Encoding.ASCII.GetBytes("hello there"), "123", 256, 10000));
            Console.WriteLine(res);

            Console.ReadLine();

            string res_dec = Encoding.ASCII.GetString(Decrypt(Encoding.ASCII.GetBytes(res), "123"));
            Console.WriteLine(res_dec);

            Console.ReadLine();
        }

        public static byte[] Decrypt(byte[] message, string password)
        {
            // Validate parametres
            if (message == null || message.Length == 0) throw new Exception("Message cannot be empty.");
            else if (string.IsNullOrWhiteSpace(password)) throw new Exception("Password cannot be empty.");

            string[] payloads = Encoding.ASCII.GetString(message).Split(':');
            int key_size = int.Parse(payloads[0]), iterations = int.Parse(payloads[1]);
            string salt = payloads[2], iv = payloads[3], encrypted = payloads[4], hmac = payloads[5];

            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.KeySize = key_size;

                using (MemoryStream plaintext = new MemoryStream())
                using (Rfc2898DeriveBytes rfc = new Rfc2898DeriveBytes(password, Convert.FromBase64String(salt), iterations))
                {
                    aes.Key = rfc.GetBytes(aes.KeySize / 8);
                    aes.IV = Convert.FromBase64String(iv);

                    // Check if received message has integrity and is valid
                    byte[] calculated_hash_data;
                    using (HMAC hmac_handler = HMACSHA256.Create())
                    {
                        hmac_handler.Key = aes.Key;
                        calculated_hash_data = hmac_handler.ComputeHash(Encoding.ASCII.GetBytes(string.Join(":", key_size, iterations, salt, iv, encrypted)));
                    }
                    byte[] received_hash_data = Convert.FromBase64String(hmac);

                    if (!calculated_hash_data.SequenceEqual(received_hash_data))
                    {
                        throw new Exception("Received HMAC data does not match the calculated HMAC data, message has been tampered with!");
                    }

                    using (ICryptoTransform transform = aes.CreateDecryptor())
                    using (MemoryStream input = new MemoryStream(Convert.FromBase64String(encrypted)))
                    using (CryptoStream cs = new CryptoStream(plaintext, transform, CryptoStreamMode.Write))
                    {
                        input.CopyTo(cs);
                    }

                    return plaintext.ToArray();
                }
            }
        }

        public static byte[] Encrypt(byte[] message, string password, int key_size, int iterations)
        {
            // Validate parametres
            if (message == null || message.Length == 0) throw new Exception("Message cannot be empty.");
            else if (string.IsNullOrWhiteSpace(password)) throw new Exception("Password cannot be empty.");
            else if (!Aes.Create().ValidKeySize(key_size)) throw new Exception("Invalid key size.");
            else if (iterations < 1) throw new Exception("Iterations cannot be less than 1.");

            string salt, iv, encrypted, hash, final;
            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.KeySize = key_size;

                using (MemoryStream ciphertext = new MemoryStream())    // Encrypted message
                using (Rfc2898DeriveBytes rfc = new Rfc2898DeriveBytes(password, aes.KeySize / 8, iterations))
                {
                    aes.Key = rfc.GetBytes(aes.KeySize / 8);

                    using (ICryptoTransform transform = aes.CreateEncryptor())
                    using (MemoryStream input = new MemoryStream(message))
                    using (CryptoStream cs = new CryptoStream(ciphertext, transform, CryptoStreamMode.Write))
                    {
                        input.CopyTo(cs);
                    }

                    salt = Convert.ToBase64String(rfc.Salt);
                    iv = Convert.ToBase64String(aes.IV);
                    encrypted = Convert.ToBase64String(ciphertext.ToArray());
                    final = string.Join(":", key_size, iterations, salt, iv, encrypted);
                }

                byte[] hash_data;
                using (HMAC hmac_handler = HMACSHA256.Create())
                {
                    hmac_handler.Key = aes.Key;
                    hash_data = hmac_handler.ComputeHash(Encoding.ASCII.GetBytes(final));
                }
                hash = Convert.ToBase64String(hash_data);
            }

            final = string.Join(":", final, hash);

            return Encoding.ASCII.GetBytes(final);
        }
    }
}
