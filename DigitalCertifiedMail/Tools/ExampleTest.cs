using DigitalCertifiedMail.Classes.Builders;
using DigitalCertifiedMail.Classes.Communication;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace DigitalCertifiedMail.Tools
{
    internal class ExampleTest
    {
        static RsaSecurityKey public_key;
        static RsaSecurityKey private_key;
        static TCPHandler handler;
        static DCMObject envelope;
        static bool flag = true;

        public static async Task Main()
        {
            using (RSA rsa = RSA.Create())
            {
                public_key = new RsaSecurityKey(rsa.ExportParameters(false));
                private_key = new RsaSecurityKey(rsa.ExportParameters(true));
            }

            handler = new TCPHandler("127.0.0.1", 4200, "C:\\Users\\johnh\\certificate.pfx", "", IntegerityFunc, PublicKey, HandleMessages);

            await PublishMessage("Hello World");
            while (flag) ;
        }

        private static bool IntegerityFunc(byte[] bytes)
        {
            bool m = (envelope.GetBytes().SequenceEqual(bytes));
            
            return m;
        }
        private static RsaSecurityKey PublicKey()
        {
            return public_key;
        }
        private static void HandleMessages(DCMObject obj, TCPHandler t, TCPAddressee a)
        {
            flag = true;
            throw new NotImplementedException();
        }
        private async static Task PublishMessage(String message)
        {
            TCPAddressee addressee = new TCPAddressee("127.0.0.1", 4200);
            DCMFactory factory = new DCMFactory(handler);
            Console.WriteLine("Placing message in envelope...");
            envelope = await factory.MakeEnvelope(message, addressee);
            Console.WriteLine($"Sending message to {addressee.GetIP()}:{addressee.GetPort()}...");

            //Transport to Receiver
            handler.SendMail(addressee.GetIP(), addressee.GetPort(), envelope);
        }
    }
}
