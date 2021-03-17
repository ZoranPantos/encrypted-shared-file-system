using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace EncryptedFileSystem
{
    public class FileSystem
    {
        private CertificationAuthority ca;

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
                Directory.CreateDirectory(path);

                SHA1Managed sha1 = new SHA1Managed();
                byte[] passwordBytes = Encoding.Unicode.GetBytes(password);
                byte[] passwordHashBytes = sha1.ComputeHash(passwordBytes);

                File.WriteAllBytes(path + @"\password_hash", passwordHashBytes);
                

                //generate keys

                //save keys

                //generate certificate

                //save sertificate
            }
        }
    }
}
