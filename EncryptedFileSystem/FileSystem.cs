using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Linq;

namespace EncryptedFileSystem
{
    public class FileSystem
    {
        private CertificationAuthority ca;
        public User currentUser { get; set; }

        public FileSystem(CertificationAuthority ca)
        {
            this.ca = ca;

            if (!Directory.Exists(@"Data\FileSystem"))
                FirstTimeBoot();
            else
                UpdateFileSystemCrl();
        }

        private void FirstTimeBoot()
        {
            Directory.CreateDirectory(@"Data\FileSystem\Users\Shared");
            Directory.CreateDirectory(@"Data\FileSystem\Certificates");
            File.Create(@"Data\FileSystem\Users\shared_connections.txt").Close();

            Certificate cert = ca.GetCaCertificate();
            cert.Save(@"Data\FileSystem\Certificates\ca_certificate.txt");

            UpdateFileSystemCrl();
        }

        //Gets data from Data\CA\crl.txt and repastes it to Data\FileSystem\Certificates\crl.txt
        private void UpdateFileSystemCrl()
        {
            StreamWriter writer = new StreamWriter(@"Data\FileSystem\Certificates\crl.txt");
            string crlData = ca.GetCrlData();
            writer.Write(crlData);
            writer.Flush();
            writer.Close();
        }

        public void Register(string username, string password)
        {
            string path = @"Data\FileSystem\Users\" + username;

            if (Directory.Exists(path))
                Console.WriteLine("Username taken");
            else
            {
                User user = new User();
                user.Username = username;

                Directory.CreateDirectory(path + @"\PersonlaFileHashes");
                Directory.CreateDirectory(path + @"\Keys");

                SHA1Managed sha1 = new SHA1Managed();
                byte[] passwordBytes = Encoding.Unicode.GetBytes(password);
                byte[] passwordHashBytes = sha1.ComputeHash(passwordBytes);

                File.WriteAllBytes(path + @"\password_hash", passwordHashBytes);

                CryptoAlgorithms.RSA rsa = new CryptoAlgorithms.RSA();

                using (var writer = new StreamWriter(path + @"\Keys\private_key.txt"))
                {
                    user.PrivateXmlKey = rsa.PrivateKeyToXmlString();
                    writer.Write(user.PrivateXmlKey);
                }

                using (var writer = new StreamWriter(path + @"\Keys\public_key.txt"))
                {
                    user.PublicXmlKey = rsa.PublicKeyToXmlString();
                    writer.Write(user.PublicXmlKey);
                }

                using (var writer = new StreamWriter(path + @"\Keys\symmetric_key.txt"))
                {
                    user.SymetricKey = user.Username.ToUpper() + "SYMMETRIC";
                    writer.Write(user.SymetricKey);
                }

                Certificate certificate = ca.IssueCertificate(user);
                certificate.Save(@"Data\FileSystem\Certificates\" + user.Username + "_certificate.txt");
            }
        }

        public void Login(string username, string password)
        {
            //1. check if user exists
            string path = @"Data\FileSystem\Users\" + username;

            if (!Directory.Exists(path))
                Console.WriteLine("User with this username does not exist");
            {

                //2. hash the password
                SHA1Managed sha1 = new SHA1Managed();
                byte[] passwordBytes = Encoding.Unicode.GetBytes(password);
                byte[] passwordHashBytes = sha1.ComputeHash(passwordBytes);

                //3. load original password hash
                byte[] originalPasswordHash = File.ReadAllBytes(path + @"\password_hash");

                //4. compare the two
                if (originalPasswordHash.SequenceEqual(passwordHashBytes))
                {
                    //5. check if certificate is valid
                    Certificate certificate = new Certificate();
                    certificate.Load(@"Data\FileSystem\Certificates\" + username + "_certificate.txt");
                    string crlData = ca.GetCrlData();

                    if (crlData.Contains(username))
                        Console.WriteLine("Certificate expired");
                    else
                    {
                        currentUser = new User()
                        {
                            Username = username,
                            PrivateXmlKey = File.ReadAllText(path + @"\Keys\private_key.txt"),
                            PublicXmlKey = File.ReadAllText(path + @"\Keys\public_key.txt"),
                            SymetricKey = File.ReadAllText(path + @"\Keys\symmetric_key.txt")
                        };
                    }
                }
                else
                    Console.WriteLine("Passwords do not match");
            }
        }

        //TEST
        public void PrintCurrentUser()
        {
            if (currentUser != null)
            {
                Console.WriteLine("USERNAME\n");
                Console.WriteLine(currentUser.Username);
                Console.WriteLine();

                Console.WriteLine("PRIVATE XML KEY\n");
                Console.WriteLine(currentUser.PrivateXmlKey);
                Console.WriteLine();

                Console.WriteLine("PUBLIC XML KEY\n");
                Console.WriteLine(currentUser.PublicXmlKey);
                Console.WriteLine();

                Console.WriteLine("SYMMETRIC KEY\n");
                Console.WriteLine(currentUser.SymetricKey);
                Console.WriteLine();
            }
        }
    }
}
