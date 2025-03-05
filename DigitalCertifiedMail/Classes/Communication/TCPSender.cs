using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DigitalCertifiedMail
{
    using System;
    using System.IO;
    using System.Net;
    using System.Net.Security;
    using System.Net.Sockets;
    using System.Security.Authentication;
    using System.Security.Cryptography.X509Certificates;

    class TCPSender
    {
        private readonly X509Certificate2 certificate;
        private readonly int timeoutSeconds = 12;

        public TCPSender(X509Certificate2 certificate) {
            this.certificate = certificate;
        }

        public async Task SendMessage(string ipAddress, int port, string message)
        {
            var certificateCollection = new X509CertificateCollection { certificate };

            using (var client = new TcpClient(ipAddress, port))
            {
                Console.WriteLine("SND: Connected to receiver: " + ipAddress + ":" + port);

                using (var sslStream = new SslStream(client.GetStream(), false))
                {
                    try
                    {
                        // Authenticate client with the server
                        sslStream.AuthenticateAsClient(ipAddress, certificateCollection,
                                                       SslProtocols.Tls12, checkCertificateRevocation: true);
                        Console.WriteLine("SND: SSL/TLS authentication successful.");

                        using (var writer = new StreamWriter(sslStream, Encoding.UTF8) { AutoFlush = true })
                        using (var reader = new StreamReader(sslStream, Encoding.UTF8))
                        {
                            while (true)
                            {
                                // Write the message to the SSL stream
                                await writer.WriteLineAsync(message);
                                Console.WriteLine("SND: Message sent.");

                                // Wait for ACK
                                var ackTask = reader.ReadLineAsync();
                                if (await Task.WhenAny(ackTask, Task.Delay(timeoutSeconds * 1000)) == ackTask)
                                {
                                    if (ackTask.Result == "ACK")
                                    {
                                        Console.WriteLine("SND: ACK received.");
                                        return;
                                    }
                                    else
                                    {
                                        Console.WriteLine("SND: No valid ACK received, resending...");
                                    }
                                }
                                else
                                {
                                    Console.WriteLine("Timed out....");
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"SND: Authentication failed: {ex.Message}");
                    }
                }
            }
        }

        public async Task<string> RequestPublicKey(string ipAddress, int port)
        {
            var certificateCollection = new X509CertificateCollection { certificate };

            using (var client = new TcpClient(ipAddress, port))
            {
                Console.WriteLine("SND: Connected to receiver: " + ipAddress + ":" + port);

                using (var sslStream = new SslStream(client.GetStream(), false))
                {
                    try
                    {
                        // Authenticate *NOT* client with the server
                        //sslStream.AuthenticateAsClient(ipAddress, certificateCollection,
                        //                               SslProtocols.Tls12, checkCertificateRevocation: true);
                        sslStream.AuthenticateAsClient(ipAddress, null,
                                                       SslProtocols.Tls12, checkCertificateRevocation: false);
                        Console.WriteLine("SND: SSL/TLS authentication successful.");

                        using (var writer = new StreamWriter(sslStream, Encoding.UTF8) { AutoFlush = true })
                        using (var reader = new StreamReader(sslStream, Encoding.UTF8))
                        {
                            while (true)
                            {
                                // Write the message to the SSL stream
                                await writer.WriteLineAsync("PUBKEYREQ");
                                Console.WriteLine("SND: Public key request sent.");

                                // Wait for Key
                                var keyTask = reader.ReadLineAsync();
                                if (await Task.WhenAny(keyTask, Task.Delay(timeoutSeconds * 1000)) == keyTask)
                                {
                                    if (!(keyTask.Result is null) && keyTask.Result.StartsWith("PUBKEY:"))
                                    {
                                        Console.WriteLine($"SND: Received public key");
                                        return keyTask.Result.Split(' ')[1];
                                    }
                                    else
                                    {
                                        Console.WriteLine("SND: No key received, resending...");
                                    }
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"SND: Authentication failed: {ex.Message}");
                        throw ex;
                    }
                }
            }
        }
    }

}
