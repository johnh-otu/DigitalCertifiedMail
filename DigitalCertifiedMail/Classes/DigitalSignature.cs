using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DigitalCertifiedMail.Tools
{
    internal class DigitalSignature : DCMObject
    {
        public DigitalSignature(Span<byte> bytes) : base(bytes) { }
        public DigitalSignature(ReadOnlySpan<byte> bytes) : base(bytes) { }

        public bool IsValid(RsaSecurityKey signerKey, ReadOnlySpan<byte> messageBytes)
        {
            using (RSA rsa = RSA.Create())
            {
                //load public key
                rsa.ImportParameters(signerKey.Parameters);
                rsa.KeySize = Tools.EncryptionTools.RSA_KEY_SIZE;

                //verify
                return rsa.VerifyData(messageBytes.ToArray(), this.GetBytes().ToArray(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }
    }
}
