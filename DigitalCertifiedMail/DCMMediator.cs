using DigitalCertifiedMail.Classes.Builders;
using DigitalCertifiedMail.Classes.Communication;
using DigitalCertifiedMail.Tools;
using Microsoft.IdentityModel.Tokens;
using System;
using System.CodeDom;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DigitalCertifiedMail
{

    internal class DCMMediator
    {
        private RsaSecurityKey public_key, private_key;
        private Random rand = new Random();
        private TCPHandler tcpHandler;
        private IDCMHandler dcmHandler;
        private string ip;
        private int port;

        public DCMMediator(string ip, int port, string certificate_path, string certificate_password)
        {
            this.ip = ip;
            this.port = port;

            using (RSA rsa = RSA.Create())
            {
                public_key = new RsaSecurityKey(rsa.ExportParameters(false));
                private_key = new RsaSecurityKey(rsa.ExportParameters(true));
            }

            dcmHandler = new DCMHandler(private_key);
            tcpHandler = new TCPHandler(ip, port, certificate_path, certificate_password, dcmHandler.checkMessageIntegrity, GetPublicKey, dcmHandler.validateMessageAndAddToQueue);
        }
        
        public string getIP() {  return ip; }
        public int getPort() { return port; }
        public RsaSecurityKey GetPublicKey() {  return public_key; }

        public async void PublishMessage(String message, TCPAddressee addressee)
        {
            DCMFactory factory = new DCMFactory(tcpHandler);
            Console.WriteLine("Placing message in envelope...");
            DCMObject digitalEnvelope = await factory.MakeEnvelope(message, addressee);
            Console.WriteLine($"Sending message to {addressee.GetIP()}:{addressee.GetPort()}...");

            //Transport to Receiver
            tcpHandler.SendMail(addressee.GetIP(), addressee.GetPort(), digitalEnvelope);
        }

        internal void NextMessage()
        {
            dcmHandler.NextMessage();
        }

        internal void DeleteCurrent()
        {
            dcmHandler.DeleteCurrent();
        }

    }
}

