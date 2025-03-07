using DigitalCertifiedMail.Tools;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

/*=====================================
 * Adapter Class for TCP Communication
 *=====================================
 *
 * Contains -> TCP Receiver
 *          -> TCP Sender
 * 
 * User-Provided Functions:
 *      bool integrityFunction(byte[])
 *      string getPublicKeyFunction()
 *      void messageHandlerFunction(DCMMessage)
 * 
 * Adapted Functions:
 *      async void SendMail(<IP>, <PORT>, DCMMessage)
 */

namespace DigitalCertifiedMail.Classes.Communication
{
    internal class TCPHandler
    {
        private readonly TCPReceiver _receiver;
        private readonly TCPSender _sender;
        private readonly X509Certificate2 _certificate;
        private readonly Func<string, bool> _integrityFunction;
        private readonly Func<string> _publicKeyFunction;
        private readonly Action<string, TCPAddressee> _messageHandlerFunction;

        public TCPHandler(string ipAddress, int port, string certificatePath, string certificatePassword, 
            Func<byte[], bool> integrityFunction, Func<RsaSecurityKey> publicKeyFunction, Action<DCMObject, TCPHandler, TCPAddressee> messageHandlerFunction)
        {
            try
            {
                _certificate = new X509Certificate2(certificatePath, certificatePassword);
            }
            catch (Exception)
            {
                throw new ArgumentException($"Could not find a certificate at {certificatePath} that matched the given password.");
            }
            
            _integrityFunction = (msg_str) =>
            {
                return integrityFunction.Invoke(JsonSerializer.Deserialize<byte[]>(msg_str));
            };
            _publicKeyFunction = () =>
            {
                RsaSecurityKey key = publicKeyFunction.Invoke();
                return EncryptionTools.SerializeRSAKey(key);
            };
            _messageHandlerFunction = (msg_str, sender) =>
            {
                DCMObject envelope = new DCMObject(Encoding.UTF8.GetBytes(msg_str));
                messageHandlerFunction.Invoke(envelope, this, sender);
            };

            _receiver = new TCPReceiver(ipAddress, port, _certificate, _integrityFunction, _publicKeyFunction, _messageHandlerFunction);
            _sender = new TCPSender(_certificate);

            //run receiver asynchronously
            _ = Task.Run(() => _receiver.Start());
        }

        public X509Certificate2 GetCertificate() { return _certificate; }

        public async void SendMail(string ip, int port, DCMObject message)
        {
            await _sender.SendMessage(ip, port, message.GetBytes().ToArray());
        }
        public void SendMail(TCPAddressee addressee, DCMObject message)
        {
            SendMail(addressee.GetIP(), addressee.GetPort(), message);
        }
        public async Task<RsaSecurityKey> RequestPublicKey(string ip, int port)
        {
            return await _sender.RequestPublicKey(ip, port);
        }
        public async Task<RsaSecurityKey> RequestPublicKey(TCPAddressee keyProvider)
        {
            return await _sender.RequestPublicKey(keyProvider.GetIP(), keyProvider.GetPort());
        }
    }
}
