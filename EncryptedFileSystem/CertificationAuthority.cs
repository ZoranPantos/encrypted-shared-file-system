using EncryptedFileSystem.CryptoAlgorithms;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

/*
 Pronaci razlog zbog kojeg se pri svakom drugom pokretanju u fajlove sa sertifikatima umecu prane linije izmedju unosa.
 */

namespace EncryptedFileSystem
{
    public class CertificationAuthority
    {
        public string PublicXmlKey { get; set; }
        private string privateXmlKey;

        public CertificationAuthority()
        {
            //If never booted, do a proper setup and load public and private key into memory
            if (!Directory.Exists(@"Data\CA"))
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
                UpdateActive();
            }
        }

        //Initial setup: generate and save public/private RSA keys and CA certificate
        public void FirstTimeBoot()
        {
            Directory.CreateDirectory(@"Data\CA"); 

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

            //certificate.IssuerNameCipher = Encoding.Unicode.GetString(rsa.Encrypt("CA"));

            certificate.Subject = "CA";
            certificate.Expiration = DateTime.Parse("01/01/2100 12:00:00");
            certificate.SubjectPublicKey = rsa.PublicKeyToXmlString();

            certificate.Save(@"Data\CA\ca_certificate.txt");

            PublicXmlKey = certificate.SubjectPublicKey;
            privateXmlKey = rsa.PrivateKeyToXmlString();

            writer = new StreamWriter(@"Data\CA\last_issued_id.txt");
            writer.Write("1");
            writer.Flush();
            writer.Close();

            File.Create(@"Data\CA\active.txt").Close();
            File.Create(@"Data\CA\crl.txt").Close();
        }

        //TESTING
        public void PrintToConsole()
        {
            Console.WriteLine("PUBLIC KEY");
            Console.WriteLine(PublicXmlKey);
            Console.WriteLine();
            Console.WriteLine("PRIVATE KEY");
            Console.WriteLine(privateXmlKey);
        }

        //HELPER
        public int GetLastIssuedId()
        {
            StreamReader reader = new StreamReader(@"Data\CA\last_issued_id.txt");
            int lastId = int.Parse(reader.ReadToEnd());
            reader.Close();
            return lastId;
        }

        //HELPER
        public void UpdateLastIssuedId()
        {
            int previousId = GetLastIssuedId();

            //This will automatically overwrite existing file with a new one
            StreamWriter writer = new StreamWriter(@"Data\CA\last_issued_id.txt");

            writer.Write(++previousId);
            writer.Flush();
            writer.Close();
        }

        //Adds new certificate data to the list of expired certificates
        //expiredCertData is a line taken directly from active.txt
        public void UpdateCrl(string expiredCertData)
        {
            StreamWriter writer = new StreamWriter(@"Data\CA\crl.txt", append: true);
            writer.WriteLine(expiredCertData.Replace("\r\n", "\n").Replace("\r", "\n"));
            writer.Flush();
            writer.Close();
        }

        //Iterates through file of active certificates, validates each one and in the end it rewrites whole file with only
        //active certificates while expired ones are added to the crl.txt.
        //Each time CA is booted, this should run.
        public void UpdateActive()
        {
            StreamReader reader = new StreamReader(@"Data\CA\active.txt");
            string fileData = reader.ReadToEnd();
            reader.Close();

            string[] lines = fileData.Split("\n");

            LinkedList<string> currentlyActive = new LinkedList<string>();
            Regex regex = new Regex("[a-zA-Z0-9]+");

            for (int i = 0; i < lines.Length; i++)
            {
                MatchCollection matches = regex.Matches(lines[i]);

                if (matches.Count > 0)
                {
                    string[] substrings = lines[i].Split(" ");
                    string date = substrings[2] + " " + substrings[3];
                    DateTime dateTime = DateTime.Parse(date);

                    if (DateTime.Now > dateTime)
                        UpdateCrl(lines[i]);
                    else
                        currentlyActive.AddLast(lines[i]);
                }
            }

            StreamWriter writer = new StreamWriter(@"Data\CA\active.txt");
            foreach (string line in currentlyActive)
                writer.WriteLine(line.Replace("\r\n", "\n").Replace("\r", "\n")); //".Replace" added in order to solve line feed in file - partially solved
            writer.Flush();
            writer.Close();
        }

        //Adds new certificate to the list of active certificates
        public void AddActiveCert(string activeCertData)
        {
            /*FileStream file = new FileStream(@"Data\CA\active.txt", FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
            StreamWriter writer = new StreamWriter(file);
            file.Position = file.Length;
            writer.WriteLine();*/

            StreamWriter writer = new StreamWriter(@"Data\CA\active.txt", append: true);
            writer.WriteLine(activeCertData.Replace("\r\n", "\n").Replace("\r", "\n")); //".Replace" added in order to solve line feed in file - partially solved
            writer.Flush();
            writer.Close();
        }

        public LinkedList<int> GetCrlIds()
        {
            Regex regex = new Regex("[a-zA-Z0-9]+");
            LinkedList<int> crlIds = new LinkedList<int>();
            StreamReader reader = new StreamReader(@"Data\CA\crl.txt");

            string crlData = reader.ReadToEnd();
            string[] lines = crlData.Split("\n");

            foreach (string line in lines)
            {
                MatchCollection matches = regex.Matches(line);
                if (matches.Count > 0)
                {
                    string[] substrings = line.Split(" ");
                    crlIds.AddLast(int.Parse(substrings[0]));
                }
            }

            return crlIds;
        }

        public string GetCrlData()
        {
            StreamReader reader = new StreamReader(@"Data\CA\crl.txt");
            string data = reader.ReadToEnd();
            reader.Close();
            return data;
        }

        public Certificate IssueCertificate(User user)
        {
            Certificate certificate = new Certificate();
            int nextId = GetLastIssuedId();

            certificate.Id = (++nextId).ToString();
            certificate.Algorithm = "RSA";
            certificate.Issuer = "CA";
            certificate.Subject = user.Username;
            certificate.Expiration = DateTime.Now.AddDays(5);
            certificate.SubjectPublicKey = user.PublicXmlKey;

            UpdateLastIssuedId();
            AddActiveCert(certificate.Id + " " + certificate.Subject + " " + certificate.Expiration.ToString());

            return certificate;
        }

        public Certificate GetCaCertificate()
        {
            Certificate result = new Certificate();
            result.Load(@"Data\CA\ca_certificate.txt");
            return result;
        }
    }
}
