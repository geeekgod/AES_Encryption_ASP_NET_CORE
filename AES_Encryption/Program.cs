﻿using System.Text;
using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;

namespace AES_Encryption
{
    internal class Program
    {
        public static void Main(string[] args)
        {

            var config = new ConfigurationBuilder()
                .SetBasePath(AppDomain.CurrentDomain.BaseDirectory)
                .AddUserSecrets<Program>()
                .Build();

            UnicodeEncoding ByteConverter = new UnicodeEncoding();

            using (Aes myAes = Aes.Create())
            {
                string key = config["aes_key"];
                string iv = config["aes_iv"];

                string encr = config["encrypted"];

                byte[] encrypted = Convert.FromBase64String(encr);
                byte[] key_byte = Convert.FromBase64String(key);
                byte[] iv_byte = Convert.FromBase64String(iv);
                string roundtrip = DecryptStringFromBytes_Aes(encrypted, key_byte, iv_byte);

                string encryptedData = Convert.ToBase64String(encrypted);

                //Display the original data and the decrypted data.
                Console.WriteLine("Original:   {0}", config["dechiper_text"]);
                Console.WriteLine("Encrypted:  {0}", encryptedData);
                Console.WriteLine("Round Trip: {0}", roundtrip);
            }
        }
        static string EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;


            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            return Convert.ToBase64String(encrypted);
        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            string plaintext = null;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }
    }
}