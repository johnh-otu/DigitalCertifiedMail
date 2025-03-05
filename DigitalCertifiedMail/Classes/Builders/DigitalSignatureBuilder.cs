using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

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
            //get hash
            message.SetBytes(Tools.HashingTools.SHA256Hash(message.GetBytes()));

            //encrypt
            return new DigitalSignature(Tools.EncryptionTools.RSAEncrypt(message.GetBytes(), private_key));
        }
    }
}
