using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
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
            ReadOnlySpan<byte> signatureHash = EncryptionTools.RSADecrypt(GetBytes(), signerKey);
            ReadOnlySpan<byte> messageHash = HashingTools.SHA256Hash(messageBytes);

            return signatureHash.SequenceEqual(messageHash);
        }
    }
}
