using DigitalCertifiedMail.Classes;
using DigitalCertifiedMail.Classes.Builders;
using DigitalCertifiedMail.Classes.Communication;
using DigitalCertifiedMail.Tools;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DigitalCertifiedMail
{
    internal interface IDCMHandler
    {
        bool checkMessageIntegrity(byte[] message);
        void validateMessageAndAddToQueue(DCMObject envelope, TCPHandler handler, TCPAddressee sender);
        DCMTimestampedMessage NextMessage();
        bool DeleteCurrent();
    }

    internal class DCMHandler : IDCMHandler
    {
        private readonly RsaSecurityKey _privateKey;
        private readonly List<DCMTimestampedMessage> _messageQueue;
        private int _cursor = -1;

        public DCMHandler(RsaSecurityKey privateKey) 
        {
            _privateKey = privateKey;
            _messageQueue = new List<DCMTimestampedMessage>();
        }

        public bool checkMessageIntegrity(byte[] envelopeBytes)
        {
            var envelope = new ReadOnlySpan<byte>(envelopeBytes);

            //split envelope
            var temp = ByteTools.SplitBack(envelope, HashingTools.HASH_SIZE); //TODO: ERROR
            ReadOnlySpan<byte> message = new ReadOnlySpan<byte>(temp.a);
            ReadOnlySpan<byte> provided_hash = new ReadOnlySpan<byte>(temp.b);

            //check hash integrity
            ReadOnlySpan<byte> calculated_hash = HashingTools.SHA256Hash(message);
            return provided_hash.SequenceEqual(calculated_hash);
        }

        // I have no idea why out ref is not available for async functions in this version, but it certainly has made my life a living hell :)
        public async void validateMessageAndAddToQueue(DCMObject envelope, TCPHandler handler, TCPAddressee sender)
        {
            //get sender public key for later
            Task<RsaSecurityKey> keyTask = handler.RequestPublicKey(sender);

            //split envelope (remove integrity hash)
            envelope = envelope.SplitBack(HashingTools.HASH_SIZE).a;

            //split envelope (get encrypted message and encrypted symmetric key/iv)
            int encryptedKeyIVComboSizeInBytes = (EncryptionTools.RSA_KEY_SIZE / 8);

            var temp = envelope.SplitBack(encryptedKeyIVComboSizeInBytes);

            byte[] encryptedMessage = temp.a.GetBytes().ToArray();
            byte[] encryptedSymmetricKeyIVCombo = temp.b.GetBytes().ToArray();

            //decrypt and split symmetric key and iv
            byte[] symmetricKeyIVCombo = EncryptionTools.RSADecrypt(
                encryptedSymmetricKeyIVCombo, _privateKey).ToArray();

            var temp2 = ByteTools.Split(symmetricKeyIVCombo, EncryptionTools.AES_KEY_SIZE/8);
            byte[] symmetricKey = temp2.a.ToArray();
            byte[] iv = temp2.b.ToArray();

            //decrypt message
            DCMObject digitallySignedMessage = new DCMObject(
                EncryptionTools.AESDecrypt(encryptedMessage, symmetricKey, iv));

            //split envelope (get digital signature and timestamped message)
            int digitalSignatureSizeInBytes = (EncryptionTools.RSA_KEY_SIZE) / 8;
            temp = digitallySignedMessage.SplitBack(digitalSignatureSizeInBytes);
            byte[] timestampedMessageBytes = temp.a.GetBytes().ToArray();
            byte[] digitalSignatureBytes = temp.b.GetBytes().ToArray();

            //verify digital signature
            DigitalSignature signature = new DigitalSignature(digitalSignatureBytes);

            if (signature.IsValid(await keyTask, timestampedMessageBytes))
            {
                DCMTimestampedMessage timestampedMessage = new DCMTimestampedMessage(timestampedMessageBytes, handler.GetCertificate());
                _messageQueue.Add(timestampedMessage);
            }
            else
            {
                Console.WriteLine("Could not verify sender identity. Message deleted.");
            }
        }

        public DCMTimestampedMessage GetMessage(int index)
        {
            return _messageQueue[index];
        }
        public DCMTimestampedMessage NextMessage()
        {
            try
            {
                return GetMessage(++_cursor);
            }
            catch (Exception)
            {
                _cursor = -1;
                Console.WriteLine("Reached final message.");
                return null;
            }
        }
        public void DeleteMessage(int index)
        {
            _messageQueue.RemoveAt(index);
        }
        public bool DeleteCurrent()
        {
            try
            {
                DeleteMessage(_cursor--);
                Console.WriteLine($"Message {_cursor + 1} deleted.");
                return true;
            }
            catch (Exception)
            {
                _cursor = -1;
                Console.WriteLine("No message selected.");
                return false;
            }
        }

    }
}
