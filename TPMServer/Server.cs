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
using System.Security.Authentication;

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

        private X509Certificate2 GetCertificateWithEngine()
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

            privateKey.Dispose();
            rsa.Dispose();
            tmpCert.Dispose();

            return certificate;
        }
        private X509Certificate2 GetCertificateWithProvider()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            Console.WriteLine("Load cert from TPM with provider!!");
            var ssl = SafeEvpPKeyHandle.OpenSslVersion;
            Console.WriteLine("OpenSSL version: " + string.Format("{0:X}", ssl));

            string handle = "handle:0x81000006";
            Console.WriteLine("Handle : " + handle);
            SafeEvpPKeyHandle privateKey = SafeEvpPKeyHandle.OpenKeyFromProvider("tpm2", handle);
            RSAOpenSsl rsa = new(privateKey);
            X509Certificate2 tmpCert = new X509Certificate2("/etc/ssl/certs/ssl_certificate.pem");
            X509Certificate2 certificate = tmpCert.CopyWithPrivateKey(rsa);
            var isValid = certificate.Verify();
            Console.WriteLine("Validation:" + isValid);

            Console.WriteLine("IssuerName:" + certificate.IssuerName.Name);
            Console.WriteLine("SubjectName:" + certificate.SubjectName.Name);
            Console.WriteLine("-----------------------------------");

            privateKey.Dispose();
            rsa.Dispose();
            tmpCert.Dispose();

            return certificate;
        }
        private static X509Certificate2 CreateSelfSignedRsaCertificate(RSASignaturePadding padding)
        {
            Console.WriteLine("CreateSelfSignedRsaCertificate method executed!");
            // We will get rid of original handle and make sure X509Certificate2's duplicate is still working.
            X509Certificate2 serverCert;
            using (SafeEvpPKeyHandle priKeyHandle = SafeEvpPKeyHandle.OpenKeyFromProvider("tpm2", "handle:0x81000009"))
            using (RSA rsaPri = new RSAOpenSsl(priKeyHandle))
            {
                serverCert = CreateSelfSignedCertificate(rsaPri, padding);
            }

            return serverCert;
        }
        private static X509Certificate2 CreateSelfSignedCertificate(RSA rsa, RSASignaturePadding padding)
        {
            var certReq = new CertificateRequest("CN=testservereku.contoso.com", rsa, HashAlgorithmName.SHA256, padding);
            return FinishCertCreation(certReq);
        }
        private static X509Certificate2 FinishCertCreation(CertificateRequest certificateRequest)
        {
            Console.WriteLine("FinishCertCreation method executed!");
            certificateRequest.CertificateExtensions.Add(X509BasicConstraintsExtension.CreateForEndEntity());
            certificateRequest.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    // We need to allow KeyEncipherment for RSA ciphersuite which doesn't use PSS.
                    // PSS is causing issues with some TPMs (ignoring salt length)
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                    critical: false)
            );

            certificateRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
            Console.WriteLine("FinishCertCreation method executed! About to create self signed certificate!!");
            return certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMonths(-1), DateTimeOffset.UtcNow.AddMonths(1));
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

                // I could directly return X509Certificate2 from CreateSelfSignedCertificate method but I am also testing if there is no lifetime issue therefore all the dancing here
                X509Certificate2 serverCert;
                SafeEvpPKeyHandle priKeyHandle = SafeEvpPKeyHandle.OpenKeyFromProvider("tpm2", /* my RSA key handle */ "handle:0x81000009");
                RSA rsaPri = new RSAOpenSsl(priKeyHandle);
                X509Certificate2 serverCertPub = new X509Certificate2("ssl_certificate.pem");
                Console.WriteLine("Load cert from TPM with provider!! About to load!!");
                serverCert = serverCertPub.CopyWithPrivateKey(rsaPri);
                Console.WriteLine("Load cert from TPM with provider!! Loaded here!!!");

                //var cert = GetCertificateWithProvider();
                //var cert = serverCert;
                var cert = CreateSelfSignedRsaCertificate(RSASignaturePadding.Pkcs1);

                Console.WriteLine("TCP Server started. Listening for incoming connections...");

                while (true)
                {
                    // Accept an incoming connection
                    _client = listener.AcceptTcpClient();

                    Console.WriteLine("Incoming connection from " + _client.Client.RemoteEndPoint);
                    _stream = new SslStream(_client.GetStream(), false);
                    try
                    {
                        X509Certificate2Collection collection = new X509Certificate2Collection(new X509Certificate2("combinedchain.pem"));

                        var sslOptions = new SslServerAuthenticationOptions()
                        {
                            ServerCertificate = cert,
                            EncryptionPolicy = EncryptionPolicy.AllowNoEncryption,
                            CipherSuitesPolicy = new CipherSuitesPolicy(new[]
                            {
                                TlsCipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256
                            }),
                            ServerCertificateContext = SslStreamCertificateContext.Create(cert, collection, trust: SslCertificateTrust.CreateForX509Collection(collection, true)),
                        };

                        _stream.AuthenticateAsServer(sslOptions);

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
                        //Console.WriteLine(ex.ToString());
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
