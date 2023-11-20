using System.Numerics;
using System.Security.Cryptography;

class Program {

    public static BigInteger calculateSharedKey(int g_e, int g_c, int N_e, int N_c, int x, BigInteger gy_modN) {
    
        BigInteger G = BigInteger.Subtract(BigInteger.Pow(2, (int) g_e), g_c); // Not needed
        BigInteger N = BigInteger.Subtract(BigInteger.Pow(2, (int) N_e), N_c);
        BigInteger key = BigInteger.ModPow(gy_modN, x, N);

        return key;
    }

    private static byte[] encrypt(string PlainText, byte[] key, byte[] IV) {

        byte[] encrypted;
        using (AesManaged aes = new AesManaged()) {

            ICryptoTransform encryptor = aes.CreateEncryptor(key, IV);
            using (MemoryStream ms = new MemoryStream()) {

                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write)) {

                    using (StreamWriter sw = new StreamWriter(cs))
                        
                        sw.Write(PlainText);
                    encrypted = ms.ToArray();
                }
            }
        }

        return encrypted;
    }

    private static string decrypt(byte[] CipherText, byte[] key, byte[] IV) {

        string plaintext = null;
        using (AesManaged aes = new AesManaged()) {

            ICryptoTransform decryptor = aes.CreateDecryptor(key, IV);
            using (MemoryStream ms = new MemoryStream(CipherText)) {

                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read)) {

                    using (StreamReader reader = new StreamReader(cs))
                        
                        plaintext = reader.ReadToEnd();
                }
            }
        }

        return plaintext;
    }

    private static byte[] get_bytes_from_string(string CipherText) {

        var input_split = CipherText.Split(' ');
        byte[] inputBytes = new byte[input_split.Length];
        
        int i = 0;
        foreach (string item in input_split) {

            inputBytes.SetValue(Convert.ToByte(item, 16), i);
            i++;
        }

        return inputBytes;
    }

    static void Main(string[] args) {
        
        if (args.Length != 9) {

            Console.WriteLine("Err / Input should be 'dotnet run IV ge gc ne nc x gyModN Ciphertext Plaintext'");
            return;
        }

        byte[] IV = get_bytes_from_string(args[0]);
        int ge = int.Parse(args[1]);
        int gc = int.Parse(args[2]);
        int ne = int.Parse(args[3]);
        int nc = int.Parse(args[4]);
        int x = int.Parse(args[5]);
        BigInteger gyModN = BigInteger.Parse(args[6]);
        byte[] CipherText = get_bytes_from_string(args[7]);
        string PlainText = args[8];

        // Calling key function
        BigInteger key = calculateSharedKey(ge, gc, ne, nc, x, gyModN);

        string decryptedCipherBytes = decrypt(CipherText, key.ToByteArray(), IV);
        byte[] encryptedPlainText = encrypt(PlainText, key.ToByteArray(), IV);

        Console.WriteLine("{0}, {1}", decryptedCipherBytes, BitConverter.ToString(encryptedPlainText).Replace("-", " "));
    }

    // dotnet run "A2 2D 93 61 7F DC 0D 8E C6 3E A7 74 51 1B 24 B2" 251 465 255 1311 2101864342 8995936589171851885163650660432521853327227178155593274584417851704581358902 "F2 2C 95 FC 6B 98 BE 40 AE AD 9C 07 20 3B B3 9F F8 2F 6D 2D 69 D6 5D 40 0A 75 45 80 45 F2 DE C8 6E C0 FF 33 A4 97 8A AF 4A CD 6E 50 86 AA 3E DF" AfYw7Z6RzU9ZaGUloPhH3QpfA1AXWxnCGAXAwk3f6MoTx

    // Expected output: uUNX8P03U3J91XsjCqOJ0LVqt4I4B2ZqEBfX1gCGBH4hH, 3D E9 B7 31 42 D7 54 D8 96 12 C9 97 01 12 78 F7 A2 4F 69 1A FF F4 42 99 13 A1 BD 73 52 E5 48 63 33 7A 39 BF C5 25 AD 53 26 53 0D E4 81 51 D1 3E
}
