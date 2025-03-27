using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Net.Configuration;

namespace DigitalCertifiedMail.Tools
{
    internal class DigitalSignatureBuilder
    {
        private DCMObject message = new DCMObject(null);
        private RsaSecurityKey private_key = null;

        public DigitalSignatureBuilder(DCMObject msg, RsaSecurityKey privateKey)
        {
            message.SetBytes(msg.GetBytes());
            private_key = privateKey;
        }

        public DigitalSignature Build()
        {
            using (RSA rsa = RSA.Create())
            {
                // Load the private key
                rsa.ImportParameters(private_key.Parameters);
                rsa.KeySize = Tools.EncryptionTools.RSA_KEY_SIZE;

                // Sign the data using SHA256 for hashing
                byte[] signatureBytes = rsa.SignData(message.GetBytes().ToArray(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                return new DigitalSignature(signatureBytes);
            }
        }
    }
}
