using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DigitalCertifiedMail.Tools
{
    internal class ByteTools
    {
        public struct BytesPair
        {
            public byte[] a;
            public byte[] b;
        }

        public static ReadOnlySpan<byte> Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            return a.ToArray().Concat(b.ToArray()).ToArray();
        }
        public static void Split(ReadOnlySpan<byte> span, int length, out ReadOnlySpan<byte> a, out ReadOnlySpan<byte> b)
        {
            a = span.Slice(0,length);
            b = span.Slice(length);
        }
        public static BytesPair Split(ReadOnlySpan<byte> span, int length)
        {
            BytesPair output = new BytesPair();
            Split(span, length,
                out ReadOnlySpan<byte> bytesA,
                out ReadOnlySpan<byte> bytesB);
            output.a = bytesA.ToArray();
            output.b = bytesB.ToArray();
            return output;
        }
        public static BytesPair SplitBack(ReadOnlySpan<byte> span, int length)
        {
            BytesPair output = new BytesPair();
            Split(span, span.Length - length,
                out ReadOnlySpan<byte> bytesA,
                out ReadOnlySpan<byte> bytesB);
            output.a = bytesA.ToArray();
            output.b = bytesB.ToArray();
            return output;
        }
    }
}
