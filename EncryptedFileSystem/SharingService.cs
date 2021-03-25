using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Diagnostics;

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
                File.Copy(@"Data\FileSystem\Users\" + sharer.Username + @"\Keys\aes_iv", @"Data\FileSystem\Users\Shared\EncryptedSymKeys\" + sharer.Username + "_aes_iv");
            }

            string source = @"Data\FileSystem\Users\" + sharer.Username + @"\" + filename;
            string destination = @"Data\FileSystem\Users\Shared\" + filename;
            File.Move(source, destination);

            CreateConnection(filename, sharer.Username, partaker);
        }

        public void OpenSharedFile(string filename, User currentUser)
        {
            //1. check if user is a sharer or not

            //2.1 if user is a sharer - open personal file

            //2.2 if user is not a sharer - open someone else's file
        }

        //Add integrity check
        //MORAM MOCI MODIFIKOVATI FAJL KAD SE OTVORI. NE BRISATI GA NEGO GA KRIPTOVATI PONOVO
        public void OpenPersonalFile(string filename, User currentUser)
        {
            string filePath = @"Data\FileSystem\Users\Shared\" + filename;

            if (filename.Contains(".txt"))
            {
                string originalEncryptedData = File.ReadAllText(filePath).Replace("\r\n", "");

                CryptoAlgorithms.RC4 rc4 = new CryptoAlgorithms.RC4();
                string originalPlaintextData = rc4.RC4algo(originalEncryptedData, currentUser.SymetricKey);

                File.WriteAllText(@"Data\FileSystem\Users\Shared\tmp_" + filename, originalPlaintextData);
            }
            else
            {
                CryptoAlgorithms.AES aesWrapper = new CryptoAlgorithms.AES();

                byte[] encryptedBytes = File.ReadAllBytes(filePath);

                string cipherString = aesWrapper.Decrypt(encryptedBytes, currentUser.AesSymetricKey, currentUser.AesIv);
                byte[] originalBytes = Convert.FromBase64String(cipherString);

                File.WriteAllBytes(@"Data\FileSystem\Users\Shared\tmp_" + filename, originalBytes);
            }

            new Process
            {
                StartInfo = new ProcessStartInfo(@"Data\FileSystem\Users\Shared\tmp_" + filename)
                {
                    UseShellExecute = true
                }
            }.Start();

            Console.WriteLine("Press enter to continue...");
            Console.ReadLine();

            File.Delete(@"Data\FileSystem\Users\Shared\tmp_" + filename);
        }

        //Add integrity check
        //MORAM MOCI MODIFIKOVATI FAJL KAD SE OTVORI. NE BRISATI GA NEGO GA KRIPTOVATI PONOVO
        public void OpenSomeonesFile(string filename, User currentUser, string sharer)
        {
            CryptoAlgorithms.RSA rsa = new CryptoAlgorithms.RSA();
            rsa.XmlStringToPublicKey(currentUser.PublicXmlKey);
            rsa.XmlStringToPrivateKey(currentUser.PrivateXmlKey);

            string extension;

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

                File.WriteAllText(@"Data\FileSystem\Users\Shared\tmp_" + filename, originalPlaintextData);
            }
            else
            {
                byte[] aes_iv = File.ReadAllBytes(@"Data\FileSystem\Users\Shared\EncryptedSymKeys\" + sharer + "_aes_iv");
                byte[] aes_key = Convert.FromBase64String(symmetricKey);
                byte[] cipher = File.ReadAllBytes(@"Data\FileSystem\Users\Shared\stars.jpg");
                CryptoAlgorithms.AES aesWrapper = new CryptoAlgorithms.AES();

                string decipher = aesWrapper.Decrypt(cipher, aes_key, aes_iv);

                File.WriteAllBytes(@"Data\FileSystem\Users\Shared\tmp_" + filename, Convert.FromBase64String(decipher));
            }

            new Process
            {
                StartInfo = new ProcessStartInfo(@"Data\FileSystem\Users\Shared\tmp_" + filename)
                {
                    UseShellExecute = true
                }
            }.Start();

            Console.WriteLine("Press enter to continue...");
            Console.ReadLine();

            File.Delete(@"Data\FileSystem\Users\Shared\tmp_" + filename);
        }
    }
}
