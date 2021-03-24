using System;
using System.Collections.Generic;
using System.Text;
using System.IO;

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

        //Check if file exists in FileSystem class
        //Check if partaker exists in FileSystem class
        public void ShareFile(string filename, User sharer, string partaker)
        {
            string symmetricKey, encryptedSymmetricKey;
            CryptoAlgorithms.RSA rsa = new CryptoAlgorithms.RSA();
            string partakerPublicKey = File.ReadAllText(@"Data\FileSystem\Users\" + partaker + @"\Keys\public_key.txt");
            string partakerPrivateKey = File.ReadAllText(@"Data\FileSystem\Users\" + partaker + @"\Keys\private_key.txt");

            rsa.XmlStringToPublicKey(partakerPublicKey);
            rsa.XmlStringToPrivateKey(partakerPrivateKey);

            if (filename.Contains(".txt"))
                symmetricKey = File.ReadAllText(@"Data\FileSystem\Users\" + sharer.Username + @"\Keys\symmetric_key.txt");
            else
                symmetricKey = Convert.ToBase64String(File.ReadAllBytes(@"Data\FileSystem\Users\" + sharer.Username + @"\Keys\aes_symmetric_key"));
            
            byte[] encryptedBytesSymmetricKey = rsa.Encrypt(symmetricKey);

            /*if (filename.Contains(".txt"))
                //encryptedSymmetricKey = Encoding.Unicode.GetString(encryptedBytesSymmetricKey);
                encryptedSymmetricKey = Convert.ToBase64String(encryptedBytesSymmetricKey);
            else
                encryptedSymmetricKey = Convert.ToBase64String(encryptedBytesSymmetricKey);

            if (filename.Contains(".txt"))
                File.WriteAllText(@"Data\FileSystem\Users\Shared\EncryptedSymKeys\" + sharer.Username + "_symmetric_key.txt", encryptedSymmetricKey);
            else
            {
                File.WriteAllText(@"Data\FileSystem\Users\Shared\EncryptedSymKeys\" + sharer.Username + "_aes_symmetric_key.txt", encryptedSymmetricKey);
            }*/

            //Trying with raw bytes - works with .txt files as for now
            File.WriteAllBytes(@"Data\FileSystem\Users\Shared\EncryptedSymKeys\" + sharer.Username + "_symmetric_key", encryptedBytesSymmetricKey);

            if (!filename.Contains(".txt"))
                //exception if file already exists
                File.Copy(@"Data\FileSystem\Users\" + sharer.Username + @"\Keys\aes_iv", @"Data\FileSystem\Users\Shared\EncryptedSymKeys\" + sharer.Username + "_aes_iv");

            string source = @"Data\FileSystem\Users\" + sharer.Username + @"\" + filename;
            string destination = @"Data\FileSystem\Users\Shared\" + filename;
            File.Move(source, destination);

            CreateConnection(filename, sharer.Username, partaker);
        }
    }
}
