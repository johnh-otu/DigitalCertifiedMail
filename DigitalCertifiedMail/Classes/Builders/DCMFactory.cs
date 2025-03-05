using DigitalCertifiedMail.Tools;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using DigitalCertifiedMail.Classes.Communication;
using System.Text.Json;

namespace DigitalCertifiedMail.Classes.Builders
{
    internal class DCMFactory
    {
        private RsaSecurityKey _publicKey;
        private RsaSecurityKey _privateKey;
        private TCPHandler _tcpHandler;
        private Random _rand;

        public DCMFactory(TCPHandler tcpHandler) 
        {
            _tcpHandler = tcpHandler;
            _rand = new Random();

            using (RSA rsa = RSA.Create())
            {
                _publicKey = new RsaSecurityKey(rsa.ExportParameters(false));
                _privateKey = new RsaSecurityKey(rsa.ExportParameters(true));
            }
        }

        public RsaSecurityKey PrivateKey { get => _privateKey; }
        public RsaSecurityKey PublicKey { get => _publicKey; }

        public async Task<DCMObject> MakeEnvelope(string message, TCPAddressee addressee)
        {
            //GetPublicKey
            Task<RsaSecurityKey> publicKeyTask = _tcpHandler.RequestPublicKey(addressee.GetIP(), addressee.GetPort());

            //Timestamped Message
            DCMTimestampedMessage timestampedMessage = new DCMTimestampedMessage(message, _tcpHandler.GetCertificate());
            DCMObject dcmMessage = new DCMObject(
                UTF8Encoding.UTF8.GetBytes(
                    JsonSerializer.Serialize(timestampedMessage)));


            //Add Digital Signature
            DigitalSignature signature = new DigitalSignatureBuilder(dcmMessage, PrivateKey).Build();
            dcmMessage.Concat(signature.GetBytes());

            //Random Symmetric Key
            byte[] symmetricalKey = new byte[EncryptionTools.AES_KEY_SIZE/8];
            byte[] symmetricalIV = new byte[EncryptionTools.AES_IV_SIZE];
            _rand.NextBytes(symmetricalKey);
            _rand.NextBytes(symmetricalIV);

            //Encrypt Message
            dcmMessage.SetBytes(Tools.EncryptionTools.AESEncrypt(dcmMessage.GetBytes(), symmetricalKey, symmetricalIV));

            //Encrypt KeyandIV
            byte[] keyIVCombo = Tools.ByteTools.Concat(symmetricalKey, symmetricalIV).ToArray();

            RsaSecurityKey publicKey = await publicKeyTask;
            byte[] encryptedSymmKey = Tools.EncryptionTools.RSAEncrypt(keyIVCombo, publicKey).ToArray();

            //Digital Envelope
            DCMObject digitalEnvelope = new DCMObject(Tools.ByteTools.Concat(dcmMessage.GetBytes(), encryptedSymmKey));

            //Add Hash
            digitalEnvelope.Concat(Tools.HashingTools.SHA256Hash(digitalEnvelope.GetBytes()));

            return digitalEnvelope;
        }
    }
}
