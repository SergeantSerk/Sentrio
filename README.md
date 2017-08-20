# Sentrio
A cryptography library for securely encrypting and decrypting data using custom protocol.

## Getting Started

```
CryptoWorks cw = new CryptoWorks();
string message = "Hello world, this is an example to help you getting started with this library.";
string password = "abc123";
byte[] data = Encoding.ASCII.GetBytes(message);
byte[] key = Encoding.ASCII.GetBytes(password);
byte[] result = cw.Encrypt(data, key);
string ciphertext = Convert.ToBase64String(result);
```

### Installing

1. Download the library (.dll) from [here](https://github.com/SergeantSerk/Sentrio/releases "Sentrio Releases")
2. Launch Visual Studio
3. Open your project
4. Project -> Add Reference -> Browse -> Browse Button
5. Locate the downloaded library and open it
6. Tick the library in the list and click OK
7. Add reference `using Sentrio;`

## Authors

**Serkan Sahin** - *Initial work* - [SergeantSerk](https://github.com/SergeantSerk)

See also the list of [contributors](https://github.com/SergeantSerk/Sentrio/graphs/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
