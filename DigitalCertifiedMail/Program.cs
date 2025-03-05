using DigitalCertifiedMail.Classes;
using DigitalCertifiedMail.Classes.Communication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.Remoting.Messaging;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DigitalCertifiedMail
{
    internal class Program
    {
        private static string ip;
        private static int port;
        private static string certificate_path;
        private static string certificate_password;

        static void Main(string[] args)
        {
            // Verify that args contains the required parameters
            if (args.Length < 4)
            {
                Console.WriteLine("Usage: DigitalCertifiedMail.exe <Host-IP-Address> <Host-Port-Number> <Certificate-Path> <CertificatePassword>");
                return;
            }

            // Save the parameters to private variables
            ip = args[0];
            port = int.Parse(args[1]);
            certificate_path = args[2];
            certificate_password = args[3];

            //ASCII ART
            Console.WriteLine("\r\n__/\\\\\\\\\\\\\\\\\\\\\\\\___________/\\\\\\\\\\\\\\\\\\__/\\\\\\\\____________/\\\\\\\\____/\\\\\\__/\\\\\\___        \r\n _\\/\\\\\\////////\\\\\\______/\\\\\\////////__\\/\\\\\\\\\\\\________/\\\\\\\\\\\\___\\/\\\\\\_\\/\\\\\\___       \r\n  _\\/\\\\\\______\\//\\\\\\___/\\\\\\/___________\\/\\\\\\//\\\\\\____/\\\\\\//\\\\\\__/\\\\\\\\\\\\\\\\\\\\\\\\\\_      \r\n   _\\/\\\\\\_______\\/\\\\\\__/\\\\\\_____________\\/\\\\\\\\///\\\\\\/\\\\\\/_\\/\\\\\\_\\///\\\\\\///\\\\\\/__     \r\n    _\\/\\\\\\_______\\/\\\\\\_\\/\\\\\\_____________\\/\\\\\\__\\///\\\\\\/___\\/\\\\\\___\\/\\\\\\_\\/\\\\\\___    \r\n     _\\/\\\\\\_______\\/\\\\\\_\\//\\\\\\____________\\/\\\\\\____\\///_____\\/\\\\\\__/\\\\\\\\\\\\\\\\\\\\\\\\\\_   \r\n      _\\/\\\\\\_______/\\\\\\___\\///\\\\\\__________\\/\\\\\\_____________\\/\\\\\\_\\///\\\\\\///\\\\\\/__  \r\n       _\\/\\\\\\\\\\\\\\\\\\\\\\\\/______\\////\\\\\\\\\\\\\\\\\\_\\/\\\\\\_____________\\/\\\\\\___\\/\\\\\\_\\/\\\\\\___ \r\n        _\\////////////___________\\/////////__\\///______________\\///____\\///__\\///____\r\n");

            // Initialize mediator
            DCMMediator mediator;
            try
            {
                mediator = new DCMMediator(ip, port, certificate_path, certificate_password);
            }
            catch (Exception e)
            {
                Console.WriteLine("An error occurred when starting the program: " + e.Message);
                return;
            }

            Thread.Sleep(500); //wait 500ms to let "listening on" message appear
            // UI loop
            bool running = true;
            bool showOptions = true;
            while (running)
            {
                if (showOptions)
                {
                    Console.WriteLine("\nSelect an option:");
                    Console.WriteLine("1. Create and send a new message");
                    Console.WriteLine("2. Read the next message in queue");
                    Console.WriteLine("3. Delete the current message");
                    Console.WriteLine("4. Display IP and port information");
                    Console.WriteLine("5. Exit");
                }
                showOptions = true;

                Console.Write(">> ");
                switch (Console.ReadLine())
                {
                    case "1":
                        Console.WriteLine("Enter message content: >> ");
                        string messageContent = Console.ReadLine();
                        Console.WriteLine("Enter recipient IP address: >> ");
                        string addrIP = Console.ReadLine();
                        Console.WriteLine("Enter recipient port number: >> ");
                        if (!int.TryParse(Console.ReadLine(), out int addrPort)) 
                        {
                            Console.WriteLine("Port number should be a valid integer.\n");
                            continue;
                        }

                        try
                        {
                            mediator.PublishMessage(messageContent, new TCPAddressee(addrIP, addrPort));
                            Console.WriteLine("Message sent.\n");
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine($"An error occurred while sending your message: {e.Message}\n");
                        }
                        break;
                    case "2":
                        mediator.NextMessage();
                        Console.WriteLine();
                        break;
                    case "3":
                        mediator.DeleteCurrent();
                        Console.WriteLine();
                        break;
                    case "4":
                        Console.WriteLine($"IP: {ip}");
                        Console.WriteLine($"Port: {port}\n");
                        break;
                    case "5":
                        running = false;
                        Console.WriteLine("Goodbye!");
                        break;
                    case "":
                        showOptions = false;
                        break;
                    case "hello world":
                        try
                        {
                            mediator.PublishMessage("hello world\n", new TCPAddressee(ip, port));
                            Console.WriteLine("Message sent.\n");
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine($"An error occurred while sending your message: {e.Message}\n");
                        }
                        break;
                    default:
                        Console.WriteLine("Invalid option. Please try again.\n");
                        break;
                }
            }
        }
    }
}
