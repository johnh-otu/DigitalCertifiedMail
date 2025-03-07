using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DigitalCertifiedMail
{
    using DigitalCertifiedMail.Tools;
    using Microsoft.IdentityModel.Tokens;
    using System;
    using System.IO;
    using System.Net;
    using System.Net.Security;
    using System.Net.Sockets;
    using System.Security.Authentication;
    using System.Security.Cryptography.X509Certificates;
    using System.Text.Json;

    class TCPSender
    {
        private readonly X509Certificate2 certificate;
        private readonly int timeoutSeconds = 12;

        public TCPSender(X509Certificate2 certificate) {
            this.certificate = certificate;
        }

        
        public async Task SendMessage(string ipAddress, int port, byte[] message)
        {   
            try
            {
                using (TcpClient client = new TcpClient(ipAddress, port))
                using (SslStream sslStream = await SslTools.SetUpClientSslStream(ipAddress, client, certificate))
                using (StreamReader reader = new StreamReader(sslStream, Encoding.UTF8))
                using (StreamWriter writer = new StreamWriter(sslStream, Encoding.UTF8) { AutoFlush = true })
                {
                    Console.WriteLine("SND: SSL/TLS authentication successful.");

                    while (true)
                    {
                        await writer.WriteLineAsync(JsonSerializer.Serialize(message));
                        Console.WriteLine("SND: Message sent...");

                        string strRes = await reader.ReadLineAsync();

                        try //GET ACK
                        {
                            if (strRes.StartsWith("ACK"))
                            {
                                Console.WriteLine("SND: Message received by addressee.");
                                return;
                            }
                            else
                            {
                                Console.WriteLine("SND: Message corrupted or not received. Resending...");
                                continue;
                            }
                        }
                        catch (Exception) //NO ACK -> errors on GetString
                        {
                            Console.WriteLine("SND: Message corrupted or not received. Resending...");
                            continue;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"SND: Authentication failed: {ex.Message}");
            }
        }

        public async Task<RsaSecurityKey> RequestPublicKey(string ipAddress, int port)
        {
            var certificateCollection = new X509CertificateCollection { certificate };
            Exception latestException = new Exception();

            try
            {
                using (TcpClient client = new TcpClient(ipAddress, port))
                using (SslStream sslStream = await SslTools.SetUpClientSslStream(ipAddress, client, certificate))
                using (StreamReader reader = new StreamReader(sslStream, Encoding.UTF8))
                using (StreamWriter writer = new StreamWriter(sslStream, Encoding.UTF8) { AutoFlush = true })
                {
                    Console.WriteLine("SND: SSL/TLS authentication successful.");

                    for (int i = 0; i < 8; i++) //attempt 8 times
                    {
                        await writer.WriteLineAsync("REQPUBKEY");
                        Console.WriteLine("SND: Public key request sent...");

                        string response = await reader.ReadLineAsync();

                        try //GET KEY VALUE
                        {
                            var key = EncryptionTools.DeserializeRSAKey(response);
                            Console.WriteLine("SND: Public key received!");
                            return key;
                        }
                        catch (Exception e) //KEY VALUE DID NOT SERIALIZE PROPERLY
                        {
                            latestException = e;
                            Console.WriteLine("SND: Could not deserialize public key, requesting again...");
                            continue;
                        }

                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"SND: Authentication failed: {ex.Message}");
                throw;
            }

            //ran into deserialization errors too many times
            throw latestException;
        }

    }
}
