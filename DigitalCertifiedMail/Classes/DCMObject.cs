using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DigitalCertifiedMail.Tools
{
    struct DCMObjectPair
    {
        public DCMObject a;
        public DCMObject b;
    }

    internal class DCMObject
    {
        private byte[] bytes;

        public ReadOnlySpan<byte> GetBytes() { return bytes; }

        public void SetBytes(Span<byte> bytes) { this.bytes = bytes.ToArray(); }
        public void SetBytes(ReadOnlySpan<byte> bytes) { this.bytes = bytes.ToArray(); }

        public DCMObject(Span<byte> bytes) { this.bytes = bytes.ToArray(); }
        public DCMObject(ReadOnlySpan<byte> bytes) { this.bytes = bytes.ToArray(); }

        public void Concat(ReadOnlySpan<byte> bytes)
        {
            this.bytes = Tools.ByteTools.Concat(this.bytes, bytes).ToArray();
        }

        // I have to do this bs because you can't use out ref in async functions...???
        // boy oh boy I love old C# versions -_-
        public DCMObjectPair Split(int length)
        {
            DCMObjectPair output = new DCMObjectPair();
            ByteTools.Split(bytes, length, 
                out ReadOnlySpan<byte> bytesA, 
                out ReadOnlySpan<byte> bytesB);
            output.a = new DCMObject(bytesA);
            output.b = new DCMObject(bytesB);
            return output;
        }
        public DCMObjectPair SplitBack(int length)
        {
            DCMObjectPair output = new DCMObjectPair();
            ByteTools.Split(bytes, bytes.Length - length,
                out ReadOnlySpan<byte> bytesA,
                out ReadOnlySpan<byte> bytesB);
            output.a = new DCMObject(bytesA);
            output.b = new DCMObject(bytesB);
            return output;
        }
    }
}
