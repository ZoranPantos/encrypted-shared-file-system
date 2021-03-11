using EncryptedFileSystem.CryptoAlgorithms;
using System;
using System.IO;
using System.Text;

namespace EncryptedFileSystem
{
    public class CertificationAuthority
    {
        public string PublicXmlKey { get; set; }
        private string privateXmlKey;

        public CertificationAuthority(bool firstTimeBoot = false)
        {
            //If never booted, do a proper setup and load public and private key into memory
            if (firstTimeBoot)
                FirstTimeBoot();
            //Load public and private key into memory
            else
            {
                StreamReader reader = new StreamReader(@"Data\CA\ca_private_key.txt");
                privateXmlKey = reader.ReadToEnd();
                reader.Close();
                reader = new StreamReader(@"Data\CA\ca_public_key.txt");
                PublicXmlKey = reader.ReadToEnd();
                reader.Close();
            }
        }

        //Initial setup: generate and save public/private RSA keys and CA certificate
        public void FirstTimeBoot()
        {
            RSA rsa = new RSA();

            StreamWriter writer = new StreamWriter(@"Data\CA\ca_public_key.txt");
            writer.Write(rsa.PublicKeyToXmlString());
            writer.Flush();
            writer.Close();

            writer = new StreamWriter(@"Data\CA\ca_private_key.txt");
            writer.Write(rsa.PrivateKeyToXmlString());
            writer.Flush();
            writer.Close();

            Certificate certificate = new Certificate();

            certificate.Id = "1";
            certificate.Algorithm = "RSA";
            certificate.Issuer = "CA";
            certificate.IssuerNameCipher = Encoding.Unicode.GetString(rsa.Encrypt("CA"));
            certificate.Subject = "CA";
            certificate.Expiration = DateTime.Parse("01/01/2100 12:00:00");
            certificate.SubjectPublicKey = rsa.PublicKeyToXmlString();

            certificate.Save(@"Data\CA\ca_certificate.txt");

            PublicXmlKey = certificate.SubjectPublicKey;
            privateXmlKey = rsa.PrivateKeyToXmlString();
        }

        //For testing purposes
        public void PrintToConsole()
        {
            Console.WriteLine("PUBLIC KEY");
            Console.WriteLine(PublicXmlKey);

            Console.WriteLine();

            Console.WriteLine("PRIVATE KEY");
            Console.WriteLine(privateXmlKey);
        }
    }
}
