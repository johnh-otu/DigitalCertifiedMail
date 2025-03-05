using DigitalCertifiedMail.Tools;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace DigitalCertifiedMail.Classes
{
    internal class DCMTimestampedMessage
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

        private readonly List<Timestamp> timestamps;
        private readonly string message;
        
        public DCMTimestampedMessage(string message, X509Certificate2 certificate) 
        { 
            timestamps = new List<Timestamp>();
            this.message = message;
            AddTimestamp(Action.Write, certificate);
        }
        public DCMTimestampedMessage(ReadOnlySpan<byte> bytes, X509Certificate2 certificate)
        {
            var temp = JsonSerializer.Deserialize<DCMTimestampedMessage>(bytes);
            timestamps = temp.timestamps;
            message = temp.message;
        }

        private void AddTimestamp(Action action, X509Certificate2 certificate)
        {
            Timestamp timestamp = new Timestamp();
            timestamp.time = DateTime.UtcNow;
            timestamp.action = action;
            timestamp.certificate = certificate;
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
    }
}
