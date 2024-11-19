using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;

namespace TPMServer
{
    public class Server
    {
        private bool _isListening = false;
        private int _portNumber = 4567;
        private IPAddress _serverIp = IPAddress.Any;// IPAddress.Parse("192.168.8.1");
        private TcpClient _client;
        private SslStream _stream;
        private bool _isSecure = true;
        public void Listen()
        {
            if (!_isListening)
            {
                _isListening = true;
                Listen(_serverIp, _portNumber);
            }
        }

        private X509Certificate2 GetCertificate()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            Console.WriteLine("Load cert from TPM!");
            var ssl = SafeEvpPKeyHandle.OpenSslVersion;
            Console.WriteLine("OpenSSL version: " + string.Format("{0:X}", ssl));

            string handle = "0x81000006";
            Console.WriteLine("Handle : " + handle);
            SafeEvpPKeyHandle privateKey = SafeEvpPKeyHandle.OpenPrivateKeyFromEngine("tpm2tss", handle);
            RSAOpenSsl rsa = new(privateKey);
            X509Certificate2 tmpCert = new X509Certificate2("ssl_certificate.pem");
            X509Certificate2 certificate = tmpCert.CopyWithPrivateKey(rsa);
            var isValid = certificate.Verify();
            Console.WriteLine("Validation:" + isValid);

            Console.WriteLine("IssuerName:" + certificate.IssuerName.Name);
            Console.WriteLine("SubjectName:" + certificate.SubjectName.Name);
            Console.WriteLine("-----------------------------------");

            return certificate;
        }
        public void Listen(IPAddress ip, int port)
        {
            Console.WriteLine("Listen method executed!");
            // Create a TCP listener
            TcpListener listener = new TcpListener(ip, port);
        jump:
            try
            {
                Console.WriteLine("Protocol:" + ServicePointManager.SecurityProtocol);
                Console.WriteLine("Listener starting.");
                // Start listening for incoming connections
                listener.Start();
                var cert = GetCertificate();

                Console.WriteLine("TCP Server started. Listening for incoming connections...");

                while (true)
                {
                    // Accept an incoming connection
                    _client = listener.AcceptTcpClient();

                    Console.WriteLine("Incoming connection from " + _client.Client.RemoteEndPoint);
                    _stream = new SslStream(_client.GetStream(), false);
                    try
                    {
                        _stream.AuthenticateAsServer(cert, clientCertificateRequired: false, checkCertificateRevocation: true);

                        // Read and write data in a loop until the client disconnects
                        while (true)
                        {
                            // Read data from the client
                            byte[] buffer = new byte[1024];
                            int bytesRead = _stream.Read(buffer, 0, buffer.Length);
                            string receivedData = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                            if (receivedData.Length > 0)
                            {
                                Console.WriteLine("---------------Received data from client---------------");
                                Console.WriteLine(receivedData);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.ToString());
                        throw;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                goto jump;
            }
        }
    }

}
