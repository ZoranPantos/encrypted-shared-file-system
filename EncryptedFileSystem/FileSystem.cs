using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Linq;
using System.Diagnostics;
using System.Text.RegularExpressions;

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

                Directory.CreateDirectory(path + @"\PersonalFileHashes");
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
            else
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

        //---------------------------------------------OPERATIONS-------------------------------------------------------------

        //filename has an extension
        public void CreateFile(string filename, string content = "")
        {
            if (currentUser != null)
            {
                string filePath = @"Data\FileSystem\Users\" + currentUser.Username + @"\" + filename;

                if (filename.Contains(@"\") && !Directory.Exists(Path.GetDirectoryName(filePath)))
                    Directory.CreateDirectory(Path.GetDirectoryName(filePath));

                CryptoAlgorithms.RC4 rc4 = new CryptoAlgorithms.RC4();
                string cipherContent = rc4.RC4algo(content, currentUser.SymetricKey);

                using (var writer = new StreamWriter(filePath))
                {
                    writer.Write(cipherContent);
                }

                using (var writer = new StreamWriter(@"Data\FileSystem\Users\" + currentUser.Username + @"\PersonalFileHashes\" + Path.GetFileName(filePath)))
                {
                    writer.WriteLine(cipherContent);
                }
            }
            else
                Console.WriteLine("Login required");
        }

        //Current supported file type: .txt
        //Add support to other file types
        public void OpenFile(string filename)
        {
            if (currentUser != null)
            {
                string filePath = @"Data\FileSystem\Users\" + currentUser.Username + @"\" + filename;

                if (filename.Contains(".txt"))
                {
                    //integrity check
                    string originalEncryptedData = File.ReadAllText(filePath).Replace("\r\n", "");
                    string backupEncryptedData = File.ReadAllText(@"Data\FileSystem\Users\" + currentUser.Username + @"\PersonalFileHashes\" + filename).Replace("\r\n", "");

                    if (!originalEncryptedData.Equals(backupEncryptedData))
                    {
                        Console.WriteLine("File integrity compromised");
                        return;
                    }

                    CryptoAlgorithms.RC4 rc4 = new CryptoAlgorithms.RC4();
                    string originalPlaintextData = rc4.RC4algo(originalEncryptedData, currentUser.SymetricKey);

                    File.WriteAllText(filePath, originalPlaintextData);

                    new Process
                    {
                        StartInfo = new ProcessStartInfo(filePath)
                        {
                            UseShellExecute = true
                        }
                    }.Start();

                    Console.WriteLine("Press enter to continue...");
                    Console.ReadLine();

                    string newCipher = rc4.RC4algo(File.ReadAllText(filePath), currentUser.SymetricKey);
                    File.WriteAllText(filePath, newCipher);
                    File.WriteAllText(@"Data\FileSystem\Users\" + currentUser.Username + @"\PersonalFileHashes\" + filename, newCipher);
                }
                else
                    OpenNonTextFile(filename);
            }
            else
                Console.WriteLine("Login required");
        }

        public void DeletePersonalFile(string filename)
        {
            if (currentUser != null)
            {
                string filePath = @"Data\FileSystem\Users\" + currentUser.Username + @"\" + filename;

                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                    File.Delete(@"Data\FileSystem\Users\" + currentUser.Username + @"\PersonalFileHashes\" + filename);
                }
                else
                    Console.WriteLine("File not found");
            }
            else
                Console.WriteLine("Login required");
        }

        //Tried with UTF8 encoding so that last bytes are not changed. Not working correctly.
        //Can't encrypt/decrypt with RSA since file size is too big.
        //When converting bytes to a string and then back, I don't get the original byte size when using Encoding.
        //When using Convert.FromBase64, I get the original byte size, but RC4 decrypted string to bytes contains invalid stuff

        //TO DO: Must try another symmetric encryption algorithm with bytes or find another way
        public void CreateNonTextFile(string filename, byte[] fileBytes)
        {
            /*Regex regex = new Regex("\\.[a-z]+");
            MatchCollection matches = regex.Matches(filename);

            if (matches.Count > 0)
                filename = filename.Replace(matches.Last().ToString(), "");*/

            //File will be saved with an extension

            string filePath = @"Data\FileSystem\Users\" + currentUser.Username + @"\" + filename;
            CryptoAlgorithms.RC4 rc4 = new CryptoAlgorithms.RC4();

            string fileBytesString = Encoding.UTF8.GetString(fileBytes);
            string fileBytesCipherString = rc4.RC4algo(fileBytesString, currentUser.SymetricKey);
            byte[] fileBytesCipherBytes = Encoding.UTF8.GetBytes(fileBytesCipherString);

            File.WriteAllBytes(filePath, fileBytesCipherBytes);
            File.WriteAllBytes(@"Data\FileSystem\Users\" + currentUser.Username + @"\PersonalFileHashes\" + filename, fileBytesCipherBytes);

            File.Delete(filename);
        }

        public void OpenNonTextFile(string filename)
        {
            string filePath = @"Data\FileSystem\Users\" + currentUser.Username + @"\" + filename;

            //open and decrypt
            byte[] originalEncryptedBytes = File.ReadAllBytes(filePath);
            byte[] backupEncryptedBytes = File.ReadAllBytes(@"Data\FileSystem\Users\" + currentUser.Username + @"\PersonalFileHashes\" + filename);

            Console.WriteLine("original and backup encrypted bytes comparison: " + originalEncryptedBytes.SequenceEqual(backupEncryptedBytes));
            if (!originalEncryptedBytes.SequenceEqual(backupEncryptedBytes))
            {
                Console.WriteLine("File integrity compromised");
                return;
            }
            else
                Console.WriteLine("File integrity intact");

            CryptoAlgorithms.RC4 rc4 = new CryptoAlgorithms.RC4();
            string originalEncryptedBytesString = Encoding.UTF8.GetString(originalEncryptedBytes);
            string decryptedByteString = rc4.RC4algo(originalEncryptedBytesString, currentUser.SymetricKey);
            byte[] originalFileBytes = Encoding.UTF8.GetBytes(decryptedByteString);

            File.WriteAllBytes(filePath, originalFileBytes);

            //show

            //encrypt and save
        }

        //WARNING: When creating a new file manualy, do not type .txt by hand in the file name
        public void MoveFile(string filename)
        {
            string filePath = @"Data\FileSystem\Users\" + currentUser.Username + @"\" + filename;

            if (File.Exists(filename))
            {
                if (filename.Contains(".txt"))
                    CreateFile(filename, File.ReadAllText(filename));
                else
                    CreateNonTextFile(filename, File.ReadAllBytes(filename));

                File.Delete(filename);
            }
            else
                Console.WriteLine("File not found");
        }
    }
}
