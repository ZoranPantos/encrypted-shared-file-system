using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.Linq;

namespace EncryptedFileSystem
{
    public class SharingService
    {
        private void CreateConnection(string filename, string sharer, string partaker)
        {
            using (var writer = new StreamWriter(@"Data\FileSystem\Users\shared_connections.txt", append: true))
            {
                writer.WriteLine(filename + " " + sharer + " " + partaker);
            }
        }

        private void DeleteConnection(string filename)
        {
            string data = File.ReadAllText(@"Data\FileSystem\Users\shared_connections.txt").Replace("\r", "");
            string[] connections = data.Split("\n");

            using (var writer = new StreamWriter(@"Data\FileSystem\Users\shared_connections.txt"))
            {
                foreach (string conn in connections)
                    if (!conn.Contains(filename))
                        writer.WriteLine(conn);
            }
        }

        public void ShareFile(string filename, User sharer, string partaker)
        {
            string symmetricKey;
            CryptoAlgorithms.RSA rsa = new CryptoAlgorithms.RSA();
            string partakerPublicKey = File.ReadAllText(@"Data\FileSystem\Users\" + partaker + @"\Keys\public_key.txt");
            string partakerPrivateKey = File.ReadAllText(@"Data\FileSystem\Users\" + partaker + @"\Keys\private_key.txt");

            rsa.XmlStringToPublicKey(partakerPublicKey);
            rsa.XmlStringToPrivateKey(partakerPrivateKey);

            if (filename.Contains(".txt"))
                symmetricKey = File.ReadAllText(@"Data\FileSystem\Users\" + sharer.Username + @"\Keys\symmetric_key.txt");
            else
                symmetricKey = Convert.ToBase64String(File.ReadAllBytes(@"Data\FileSystem\Users\" + sharer.Username + @"\Keys\aes_symmetric_key"));
                //symmetricKey = Encoding.Unicode.GetString(File.ReadAllBytes(@"Data\FileSystem\Users\" + sharer.Username + @"\Keys\aes_symmetric_key"));
            
            byte[] encryptedBytesSymmetricKey = rsa.Encrypt(symmetricKey);

            if (filename.Contains(".txt"))
                File.WriteAllBytes(@"Data\FileSystem\Users\Shared\EncryptedSymKeys\" + sharer.Username + "_symmetric_key", encryptedBytesSymmetricKey);
            else
            {
                File.WriteAllBytes(@"Data\FileSystem\Users\Shared\EncryptedSymKeys\" + sharer.Username + "_aes_symmetric_key", encryptedBytesSymmetricKey);

                //exception if file already exists - Fix it!
                string _source = @"Data\FileSystem\Users\" + sharer.Username + @"\Keys\aes_iv";
                string _destination = @"Data\FileSystem\Users\Shared\EncryptedSymKeys\" + sharer.Username + "_aes_iv";

                if (!File.Exists(_destination))
                    File.Copy(@"Data\FileSystem\Users\" + sharer.Username + @"\Keys\aes_iv", @"Data\FileSystem\Users\Shared\EncryptedSymKeys\" + sharer.Username + "_aes_iv");
            }

            string source = @"Data\FileSystem\Users\" + sharer.Username + @"\" + filename;
            string destination = @"Data\FileSystem\Users\Shared\" + filename;

            if (!File.Exists(destination))
                File.Move(source, destination);

            CreateConnection(filename, sharer.Username, partaker);
        }

        //check for file existance in FileSystem class
        public void OpenSharedFile(string filename, User currentUser)
        {
            string[] individualConnections = File.ReadAllText(@"Data\FileSystem\Users\shared_connections.txt").Replace("\r", "").Split("\n");
            string connection = individualConnections.Where(c => c.Contains(filename)).First();
            string[] components = connection.Split(" ");

            if (currentUser.Username.Equals(components[1]))
                OpenPersonalFile(filename, currentUser);
            else
                OpenSomeonesFile(filename, currentUser, components[1]);
        }

        //Add integrity check
        private void OpenPersonalFile(string filename, User currentUser)
        {
            string filePath = @"Data\FileSystem\Users\Shared\" + filename, processPath;
            CryptoAlgorithms.RC4 rc4 = new CryptoAlgorithms.RC4();
            CryptoAlgorithms.AES aesWrapper = new CryptoAlgorithms.AES();

            //
            processPath = @"Data\FileSystem\Users\Shared\" + filename;

            //Integrity check
            string original = File.ReadAllText(processPath).Replace("\n", "").Replace("\r", "");
            string backup = File.ReadAllText(@"Data\FileSystem\Users\" + currentUser.Username + @"\PersonalFileHashes\" + filename).Replace("\n", "").Replace("\r", "");
            if (!original.Equals(backup))
            {
                Console.WriteLine("File integrity compromised");
                return;
            }

            if (filename.Contains(".txt"))
            {
                string originalEncryptedData = File.ReadAllText(filePath).Replace("\r\n", "");
                string originalPlaintextData = rc4.RC4algo(originalEncryptedData, currentUser.SymetricKey);
                //processPath = @"Data\FileSystem\Users\Shared\" + filename;

                File.WriteAllText(@"Data\FileSystem\Users\Shared\" + filename, originalPlaintextData);
            }
            else
            {
                byte[] encryptedBytes = File.ReadAllBytes(filePath);
                //processPath = @"Data\FileSystem\Users\Shared\tmp_" + filename;

                string cipherString = aesWrapper.Decrypt(encryptedBytes, currentUser.AesSymetricKey, currentUser.AesIv);
                byte[] originalBytes = Convert.FromBase64String(cipherString);

                //tmp_
                File.WriteAllBytes(@"Data\FileSystem\Users\Shared\" + filename, originalBytes);
            }

            new Process
            {
                StartInfo = new ProcessStartInfo(processPath)
                {
                    UseShellExecute = true
                }
            }.Start();

            Console.WriteLine("Press enter to continue...");
            Console.ReadLine();

            if (filename.Contains(".txt"))
            {
                string newCipher = rc4.RC4algo(File.ReadAllText(@"Data\FileSystem\Users\Shared\" + filename), currentUser.SymetricKey);
                File.WriteAllText(@"Data\FileSystem\Users\Shared\" + filename, newCipher);
                File.WriteAllText(@"Data\FileSystem\Users\" + currentUser.Username + @"\PersonalFileHashes\" + filename, newCipher);
            }
            //comment
            else
            {
                byte[] fileBytes = File.ReadAllBytes(@"Data\FileSystem\Users\Shared\" + filename);
                string fileString = Convert.ToBase64String(fileBytes);
                byte[] newEncryptedBytes = aesWrapper.Encrypt(fileString, currentUser.AesSymetricKey, currentUser.AesIv);

                File.WriteAllBytes(@"Data\FileSystem\Users\Shared\" + filename, newEncryptedBytes);
                File.WriteAllBytes(@"Data\FileSystem\Users\" + currentUser.Username + @"\PersonalFileHashes\" + filename, newEncryptedBytes);
            }
            
            //File.Delete(@"Data\FileSystem\Users\Shared\tmp_" + filename);
        }

        //Add integrity check
        private void OpenSomeonesFile(string filename, User currentUser, string sharer)
        {
            CryptoAlgorithms.RSA rsa = new CryptoAlgorithms.RSA();
            rsa.XmlStringToPublicKey(currentUser.PublicXmlKey);
            rsa.XmlStringToPrivateKey(currentUser.PrivateXmlKey);

            string extension, processPath;

            //
            processPath = @"Data\FileSystem\Users\Shared\" + filename;

            //Integrity check
            string original = File.ReadAllText(processPath).Replace("\n", "").Replace("\r", "");
            string backup = File.ReadAllText(@"Data\FileSystem\Users\" + sharer + @"\PersonalFileHashes\" + filename).Replace("\n", "").Replace("\r", "");
            if (!original.Equals(backup))
            {
                Console.WriteLine("File integrity compromised");
                return;
            }

            if (filename.Contains(".txt"))
                extension = "_symmetric_key";
            else
                extension = "_aes_symmetric_key";

            byte[] cipherKey = File.ReadAllBytes(@"Data\FileSystem\Users\Shared\EncryptedSymKeys\" + sharer + extension);
            byte[] decryptedBytes = rsa.Decrypt(cipherKey);
            string symmetricKey = Encoding.Unicode.GetString(decryptedBytes);

            if (filename.Contains(".txt"))
            {
                CryptoAlgorithms.RC4 rc4 = new CryptoAlgorithms.RC4();
                string originalEncryptedData = File.ReadAllText(@"Data\FileSystem\Users\Shared\" + filename).Replace("\r\n", "");
                string originalPlaintextData = rc4.RC4algo(originalEncryptedData, symmetricKey);

                File.WriteAllText(@"Data\FileSystem\Users\Shared\" + filename, originalPlaintextData);

                //processPath = @"Data\FileSystem\Users\Shared\" + filename;
            }
            else
            {
                byte[] aes_iv = File.ReadAllBytes(@"Data\FileSystem\Users\Shared\EncryptedSymKeys\" + sharer + "_aes_iv");
                byte[] aes_key = Convert.FromBase64String(symmetricKey);
                byte[] cipher = File.ReadAllBytes(@"Data\FileSystem\Users\Shared\" + filename);
                CryptoAlgorithms.AES aesWrapper = new CryptoAlgorithms.AES();

                string decipher = aesWrapper.Decrypt(cipher, aes_key, aes_iv);

                //tmp_
                File.WriteAllBytes(@"Data\FileSystem\Users\Shared\" + filename, Convert.FromBase64String(decipher));

                //processPath = @"Data\FileSystem\Users\Shared\tmp_" + filename;
            }

            new Process
            {
                StartInfo = new ProcessStartInfo(processPath)
                {
                    UseShellExecute = true
                }
            }.Start();

            Console.WriteLine("Press enter to continue...");
            Console.ReadLine();

            if (filename.Contains(".txt"))
            {
                CryptoAlgorithms.RC4 rc4_new = new CryptoAlgorithms.RC4();

                string newCipher = rc4_new.RC4algo(File.ReadAllText(@"Data\FileSystem\Users\Shared\" + filename), symmetricKey);
                File.WriteAllText(@"Data\FileSystem\Users\Shared\" + filename, newCipher);
                File.WriteAllText(@"Data\FileSystem\Users\" + sharer + @"\PersonalFileHashes\" + filename, newCipher);
            }
            //comment
            else
            {
                CryptoAlgorithms.AES aesWrapper2 = new CryptoAlgorithms.AES();

                byte[] aes_iv = File.ReadAllBytes(@"Data\FileSystem\Users\Shared\EncryptedSymKeys\" + sharer + "_aes_iv");
                byte[] aes_key = Convert.FromBase64String(symmetricKey);

                byte[] fileBytes = File.ReadAllBytes(@"Data\FileSystem\Users\Shared\" + filename);
                string fileString = Convert.ToBase64String(fileBytes);
                byte[] newEncryptedBytes = aesWrapper2.Encrypt(fileString, aes_key, aes_iv);

                File.WriteAllBytes(@"Data\FileSystem\Users\Shared\" + filename, newEncryptedBytes);
                File.WriteAllBytes(@"Data\FileSystem\Users\" + currentUser.Username + @"\PersonalFileHashes\" + filename, newEncryptedBytes);
            }

            //File.Delete(@"Data\FileSystem\Users\Shared\tmp_" + filename);
        }

        public ICollection<string> GetAllSharedFiles()
        {
            DirectoryInfo dInfo = new DirectoryInfo(@"Data\FileSystem\Users\Shared");
            FileInfo[] files = dInfo.GetFiles();

            ICollection<string> fileNames = new List<string>();

            foreach (FileInfo file in files)
                fileNames.Add(file.Name);

            return fileNames;
        }

        public ICollection<string> GetAllSharedFilesWithCurrentUser(User currentUser)
        {
            ICollection<string> files = new List<string>();
            string[] individualConnections = File.ReadAllText(@"Data\FileSystem\Users\shared_connections.txt").Replace("\r", "").Split("\n");
            
            foreach (string connection in individualConnections)
            {
                if (connection.Length > 0)
                {
                    string[] components = connection.Split(" ");

                    if (components[1].Equals(currentUser.Username) || components[2].Equals(currentUser.Username))
                        files.Add(components[0]);
                }
            }

            return files;
        }
    }
}
