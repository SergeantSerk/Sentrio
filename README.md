# Sentrio
A cryptography library for securely encrypting and decrypting data using custom protocol.

## Getting Started
An example console program is given below but usage is fairly simple, with main functions being Encrypt, Decrypt or Hash. Encrypt and Decrypt methods have overloads that can be used for string or file encryptions.
```
using System;
using Sentrio;

namespace Project
{
  class Program
  {
    private static CryptoWorks cw = new CryptoWorks();
    
    static void Main(string[] args)
    {
      string message = "Hello world, this is an example to help you getting started with this library.";
      string password = "abc123";
      byte[] data = Encoding.ASCII.GetBytes(message);
      byte[] key = Encoding.ASCII.GetBytes(password);
      byte[] result = cw.Encrypt(data, key);
      string ciphertext = Convert.ToBase64String(result);
      
      Console.WriteLine($"Message:      {message}");
      Console.WriteLine($"Password:     {password}");
      Console.WriteLine($"Ciphertext:   {ciphertext}");
      Console.ReadLine();
    }
  }
}
```

## Installing

1. Download the library (.dll) from [here](https://github.com/SergeantSerk/Sentrio/releases "Sentrio Releases")
2. Launch Visual Studio
3. Open your project
4. Project -> Add Reference -> Browse -> Browse Button
5. Locate the downloaded library and open it
6. Tick the library in the list and click OK
7. Add reference `using Sentrio;`

## Authors

**Serkan Sahin** - [SergeantSerk](https://github.com/SergeantSerk)

See also the list of [contributors](https://github.com/SergeantSerk/Sentrio/graphs/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
