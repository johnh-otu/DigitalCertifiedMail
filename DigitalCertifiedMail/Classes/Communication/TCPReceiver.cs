using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DigitalCertifiedMail
{
    using DigitalCertifiedMail.Tools;
    using System;
    using System.Collections.Concurrent;
    using System.IO;
    using System.Net;
    using System.Net.Security;
    using System.Net.Sockets;
    using System.Runtime.CompilerServices;
    using System.Security.Authentication;
    using System.Security.Cryptography.X509Certificates;

    internal class TCPReceiver
    {
        private readonly string ipAddress;
        private readonly int port;
        private readonly X509Certificate2 certificate;
        private readonly Func<string, bool> integrityFunction;
        private readonly Func<string> publicKeyFunction;
        private readonly Action<string, TCPAddressee> receiveMessageFunction;

        public TCPReceiver(string ipAddress, int port, X509Certificate2 certificate, Func<string, bool> integrityFunction, Func<string> getPublicKeyFunction, Action<string, TCPAddressee> receiveMessageFunction) 
        {
            this.ipAddress = ipAddress;
            this.port = port;
            this.certificate = certificate;
            this.integrityFunction = integrityFunction;
            this.publicKeyFunction = getPublicKeyFunction;
            this.receiveMessageFunction = receiveMessageFunction;
        }

        public string GetIPAddress() { return ipAddress; }
        public int GetPortNumber() { return port; }

        public async Task Start()
        {
            var listener = new TcpListener(IPAddress.Parse(ipAddress), port);
            listener.Start();
            Console.WriteLine("REC: Receiver is listening on " + ipAddress + ":" + port + "...");

            _ = Task.Run(async () =>
            {
                while (true)
                {
                    // Get new client and handle
                    var client = await listener.AcceptTcpClientAsync();
                    _ = Task.Run(() => HandleIncomingConnection(client));
                }
            });
        }

        private async Task HandleIncomingConnection(TcpClient client)
        {
            Console.WriteLine("REC: Client " + client.Client.ToString() + " connected.");

            try
            {
                using (SslStream sslStream = await SslTools.SetUpServerSslStream(client, certificate))
                using (StreamReader reader = new StreamReader(sslStream, Encoding.UTF8))
                using (StreamWriter writer = new StreamWriter(sslStream, Encoding.UTF8) { AutoFlush = true })
                {
                    // Clear any residual data from the stream
                    Console.WriteLine("REC: SSL/TLS authentication successful.");
                    await Task.Delay(1000);

                    while (true)
                    {
                        //wait for message
                        string receivedMessage = await reader.ReadLineAsync();
                        if (string.IsNullOrEmpty(receivedMessage)) break;

                        Console.WriteLine($"REC: Received message: {receivedMessage}");


                        if (receivedMessage.Equals("REQPUBKEY"))
                        {
                            Console.WriteLine($"REC: Processing public key request...");
                            var response = publicKeyFunction.Invoke();
                            await writer.WriteLineAsync(response);
                            break;
                        }
                        else
                        {
                            //check integrity
                            if (integrityFunction(receivedMessage))
                            {
                                Console.WriteLine("REC: Valid integrity hash. Sending ACK...");
                                await writer.WriteLineAsync("ACK");
                            }
                            else
                            {
                                Console.WriteLine("REC: Invalid integrity hash. Sending INV...");
                                await writer.WriteLineAsync("INV");
                                continue;
                            }

                            // Retrieve the client's IP address and port
                            var clientEndPoint = client.Client.RemoteEndPoint as IPEndPoint;
                            string clientIpAddress = clientEndPoint?.Address.ToString();
                            //int clientPort = clientEndPoint?.Port ?? 0;
                            int clientPort = 4200; //TODO: FIX TO MAKE ADAPTIVE TO ANY PORT

                            //Handle Message
                            receiveMessageFunction(receivedMessage, new TCPAddressee(clientIpAddress, clientPort));
                            break;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"REC: Authentication failed: {ex.Message}");
            }

            client.Close();
        }
    }
}
