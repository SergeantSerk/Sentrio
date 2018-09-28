using Sentrio;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Debugger
{
    public class Program
    {
        public static void Main(string[] args) => new Program().Start(args).GetAwaiter().GetResult();

        private async Task Start(string[] args)
        {
            //Identifier:key_size:iterations:salt_b64:iv_b64:crypto:hash_b64
            string message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Curabitur ultrices, erat a convallis mollis, leo diam venenatis turpis, a pellentesque est quam sit amet risus. Nam auctor, mauris sed convallis suscipit, justo magna tincidunt ipsum, eu vehicula diam nunc quis felis. Aliquam aliquam nisl id nibh consequat, quis finibus ipsum rutrum. Donec in nulla rutrum, efficitur ligula a, faucibus augue. Donec eu eleifend lorem. Nulla vestibulum dictum purus, eu venenatis justo pharetra in. Quisque ligula metus, vehicula at vulputate mattis, vulputate eu diam. Nam accumsan blandit felis, euismod fermentum sapien. Quisque eu dapibus dui, id auctor neque. Aliquam eros quam, tincidunt ut lorem a, commodo sollicitudin leo. Duis non porttitor nunc. Maecenas at dictum augue. Phasellus maximus consequat nunc. Etiam eget dolor quis tortor commodo faucibus. Aenean sit amet turpis ac lorem dignissim tincidunt.";
            string password = "1234567890";

            Console.WriteLine(message);
            byte[] ciphertext;
            using (MemoryStream input = new MemoryStream(Encoding.ASCII.GetBytes(message)))
            using (MemoryStream output = new MemoryStream())
            {
                await Crypto.Encrypt(input, output, password, 256, 10000);
                ciphertext = output.ToArray();
            }

            Console.WriteLine();

            string result;
            using (MemoryStream input = new MemoryStream(ciphertext))
            using (MemoryStream output = new MemoryStream())
            {
                await Crypto.Decrypt(input, output, password);
                result = Encoding.ASCII.GetString(output.ToArray());
            }
            Console.WriteLine(result);

            await Task.Delay(-1);
        }
    }
}
