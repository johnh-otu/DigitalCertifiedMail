using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace DigitalCertifiedMail.Tools
{
    internal class SslTools
    {
        public static async Task<byte[]> ReadBytesFromStream(SslStream stream)
        {
            byte[] lengthBytes = new byte[4];

            //get length
            int bytesRead = 0;
            while (bytesRead < 4)
            {
                int read = await stream.ReadAsync(lengthBytes, bytesRead, 4 - bytesRead);
                if (read == 0)
                    throw new EndOfStreamException();
                bytesRead += read;
            }
            int length = BitConverter.ToInt32(lengthBytes, 0);

            //read from stream
            byte[] package = new byte[length];
            await stream.ReadAsync(package, 0, length);
            return package;
        }
        public static async Task<string> ReadFromStream(SslStream stream)
        {
            return Encoding.UTF8.GetString(await ReadBytesFromStream(stream));
        }

        public static async Task WriteToStream(SslStream stream, byte[] bytes)
        {
            //package with message length
            int length = bytes.Length;
            byte[] package = new byte[length + 4];
            BitConverter.GetBytes(length).CopyTo(package, 0);
            bytes.CopyTo(package, 4);

            //write
            await stream.WriteAsync(package, 0, length);
            await stream.FlushAsync();
        }
        public static async Task WriteToStream(SslStream stream, string str)
        {
            await WriteToStream(stream, Encoding.UTF8.GetBytes(str));
        }

        //public static async Task WriteBytesToStream(SslStream stream, byte[] bytes)
        //{
        //    await WriteToStream(stream, Encoding.UTF8.GetString(bytes));
        //}
        //public static async Task WriteToStream(SslStream stream, string message)
        //{
        //    using (StreamWriter writer = new StreamWriter(stream, Encoding.UTF8) { AutoFlush = true })
        //    {
        //        await writer.WriteLineAsync(message);
        //    }
        //}
        //public static async Task<byte[]> ReadBytesFromStream(SslStream stream)
        //{
        //    return Encoding.UTF8.GetBytes(await ReadFromStream(stream));
        //}
        //public static async Task<string> ReadFromStream(SslStream stream)
        //{
        //    using (StreamReader reader = new StreamReader(stream, Encoding.UTF8))
        //    {
        //        return await reader.ReadLineAsync();
        //    }
        //}

        public static async Task<SslStream> SetUpClientSslStream(string ipAddress, TcpClient client, X509Certificate2 certificate)
        {
            var sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);

            await sslStream.AuthenticateAsClientAsync(ipAddress);

            return sslStream;
        }
        public static async Task<SslStream> SetUpServerSslStream(TcpClient client, X509Certificate2 certificate)
        {
            var sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);

            await sslStream.AuthenticateAsServerAsync(certificate);

            return sslStream;
        }
        private static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true; //TODO: DEBUG
            //return sslPolicyErrors == SslPolicyErrors.None;
        }
    }
}