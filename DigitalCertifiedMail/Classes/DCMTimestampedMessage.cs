using DigitalCertifiedMail.Tools;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using DotNetEnv;
using System.Security.Cryptography;
using System.Runtime.Serialization;
using System.Text.Json.Serialization;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace DigitalCertifiedMail.Classes
{
    [Serializable]
    internal class DCMTimestampedMessage : ISerializable
    {
        private enum Action
        {
            Write = 0,
            Read = 1
        };
        private struct Timestamp
        {
            public DateTime time;
            public Action action;
            public X509Certificate2 certificate;
            public override string ToString()
            {
                return time.ToUniversalTime().ToString() + "<" + ((action == Action.Write) ? "WRITE" : "READ") + "@" + certificate.GetCertHashString();
            }
        };

        //TODO: FIX SO THIS ISN'T HARDCODED
        //TODO: FIX SO THAT DESERIALIZATION IS CHECKED FOR TAMPERING
        private static readonly string _key = "YAa12WrIxeFQAsig5iNjQkeu2xXXBlrQRAdqRwbfDr+ryJTQoBA/GY4st/BEVt5eHnToqqzDIBYneZXLyXqUQRbGV95qF7YKQ/HOnLr8EgtYpe+fuWTplu0gO+NvL7loE1pKWpS5U/Y4D2I0mjt5+Xh7qiN7bhm5fVKaGhREX2Ufq6T/SfdICveE2MldWIt++9ofQFq9NaniBdo+2cGPCws47tZmk6DpTQXV6VKVUYD7aYc5X54uRe3Fq6A/OVVoQCjoEhrX30p7R0THFTX2Zg==";
        private static readonly string _iv = "q0esn8HLl2SvwLDnY+FuJkRghkjJBtFOvj+gWrvgz/w=";

        private readonly List<Timestamp> timestamps;
        private readonly string message;
        private byte[] encrypted_hash;
        
        public DCMTimestampedMessage(string message, X509Certificate2 certificate) 
        { 
            timestamps = new List<Timestamp>();
            this.message = message;
            AddTimestamp(Action.Write, certificate);
            UpdateHash();
        }
        public DCMTimestampedMessage(ReadOnlySpan<byte> bytes, X509Certificate2 certificate)
        {
            BinaryFormatter formatter = new BinaryFormatter();
            DCMTimestampedMessage temp;
            using (MemoryStream ms = new MemoryStream(bytes.ToArray()))
            {
                temp = (DCMTimestampedMessage)formatter.Deserialize(ms);
            }
            timestamps = temp.timestamps;
            message = temp.message;
            UpdateHash();
        }


        private void AddTimestamp(Action action, X509Certificate2 certificate)
        {
            Timestamp timestamp = new Timestamp
            {
                time = DateTime.UtcNow,
                action = action,
                certificate = certificate
            };
            timestamps.Add(timestamp);
        }

        public string PrintTimestamps() 
        {
            return timestamps.ToString();
        }
        public string GetMessageContent()
        {
            return message;
        }

        private void UpdateHash()
        {
            //try
            //{
            //    byte[] hash = Tools.HashingTools.SHA256Hash(Encoding.UTF8.GetBytes(timestamps.ToString() + message)).ToArray();
            //    encrypted_hash = EncryptionTools.AESEncrypt(hash, Encoding.UTF8.GetBytes(_key), Encoding.UTF8.GetBytes(_iv)).ToArray();
            //}
            //catch (Exception)
            //{
            //    throw;
            //}
        }

        // This method is called when serializing the object.
        
        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            info.AddValue("message", message);
            info.AddValue("timestamps", JsonSerializer.Serialize(timestamps));
        }
        protected DCMTimestampedMessage(SerializationInfo info, StreamingContext context)
        {
            timestamps = JsonSerializer.Deserialize<List<Timestamp>>(info.GetString("timestamps"));
            message = info.GetString("message");
        }
        //[OnDeserialized]
        //private void ValidateHash(StreamingContext context)
        //{
        //    byte[] hash = Tools.HashingTools.SHA256Hash(Encoding.UTF8.GetBytes(timestamps.ToString() + message)).ToArray();
        //    byte[] actual_encrypted_hash = EncryptionTools.AESEncrypt(hash, Encoding.UTF8.GetBytes(_key), Encoding.UTF8.GetBytes(_iv)).ToArray();

        //    if (!encrypted_hash.SequenceEqual(actual_encrypted_hash))
        //        throw new SerializationException("Invalid Hash.");
        //}
    }
}
