using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace DigitalCertifiedMail.Tools
{

    internal class EncryptionTools
    {
        public readonly static int RSA_KEY_SIZE = 1024; //bits
        public readonly static int AES_KEY_SIZE = 192; //bits
        public readonly static int AES_IV_SIZE = 16; //bytes

        //RSA ENCRYPTION
        public static ReadOnlySpan<byte> RSAEncrypt(ReadOnlySpan<byte> plainText, RsaSecurityKey key, RSAEncryptionPadding padding = null)
        {
            if (padding == null)
            {
                padding = RSAEncryptionPadding.Pkcs1;
            }

            using (RSA rsa = RSA.Create())
            {
                rsa.ImportParameters(key.Parameters);
                rsa.KeySize = RSA_KEY_SIZE;
                var ciphertext = rsa.Encrypt(plainText.ToArray(), padding);
                return ciphertext;
            }
        }
        public static ReadOnlySpan<byte> RSADecrypt(ReadOnlySpan<byte> cipherText, RsaSecurityKey key, RSAEncryptionPadding padding = null)
        {
            if (padding == null)
            {
                padding = RSAEncryptionPadding.Pkcs1;
            }

            using (RSA rsa = RSA.Create())
            {
                rsa.ImportParameters(key.Parameters);
                rsa.KeySize = RSA_KEY_SIZE;
                var plaintext = rsa.Decrypt(cipherText.ToArray(), padding); //TODO: FIX (KEY ISSUES I THINK)
                return plaintext;
            }
        }

        public static string SerializeRSAKey(RsaSecurityKey key)
        {
            RSAParameters rsaParameters = key.Parameters;
            var parametersDict = new Dictionary<string, byte[]>
            {
                { "Modulus", rsaParameters.Modulus },
                { "Exponent", rsaParameters.Exponent },
                { "P", rsaParameters.P },
                { "Q", rsaParameters.Q },
                { "DP", rsaParameters.DP },
                { "DQ", rsaParameters.DQ },
                { "InverseQ", rsaParameters.InverseQ },
                { "D", rsaParameters.D }
            };
            return JsonSerializer.Serialize(parametersDict);
        }
        public static RsaSecurityKey DeserializeRSAKey(string serializedKey)
        {
            var parametersDict = JsonSerializer.Deserialize<Dictionary<string, byte[]>>(serializedKey);
            RSAParameters rsaParameters = new RSAParameters
            {
                Modulus = parametersDict["Modulus"],
                Exponent = parametersDict["Exponent"],
                P = parametersDict["P"],
                Q = parametersDict["Q"],
                DP = parametersDict["DP"],
                DQ = parametersDict["DQ"],
                InverseQ = parametersDict["InverseQ"],
                D = parametersDict["D"]
            };
            return new RsaSecurityKey(rsaParameters);
        }

        //AES ENCRYPTION
        public static ReadOnlySpan<byte> AESEncrypt(ReadOnlySpan<byte> plainText, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = AES_KEY_SIZE;
                byte[] keyArray = new byte[AES_KEY_SIZE/8];
                key.ToArray().CopyTo(keyArray, 0);
                aes.Key = keyArray;
                aes.IV = iv.ToArray();

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(plainText.ToArray(), 0, plainText.Length);
                        csEncrypt.FlushFinalBlock();
                        return msEncrypt.ToArray();
                    }
                }
            }
        }
        public static ReadOnlySpan<byte> AESDecrypt(ReadOnlySpan<byte> cipherText, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = AES_KEY_SIZE;
                aes.Key = key.ToArray();
                aes.IV = iv.ToArray();

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherText.ToArray()))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (MemoryStream resultStream = new MemoryStream())
                        {
                            csDecrypt.CopyTo(resultStream);
                            return resultStream.ToArray();
                        }
                    }
                }
            }
        }
    }
}
