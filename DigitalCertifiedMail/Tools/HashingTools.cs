using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DigitalCertifiedMail.Tools
{
    internal class HashingTools
    {
        public readonly static int HASH_SIZE = 64;
        public readonly static int OFFSET = 0;

        public static ReadOnlySpan<byte> SHA256Hash(ReadOnlySpan<byte> data)
        {
            byte[] buffer = new byte[OFFSET + HASH_SIZE];
            data.ToArray().CopyTo(buffer, 0);
            SHA256 sha = SHA256.Create();
            return sha.ComputeHash(buffer, OFFSET, HASH_SIZE);
        }
    }
}
