using EncryptedFileSystem.CryptoAlgorithms;
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Security.Cryptography;
using System.Linq;

namespace EncryptedFileSystem
{
    class Program
    {
        static void Main(string[] args)
        {
            CertificationAuthority ca = new CertificationAuthority();
            FileSystem fs = new FileSystem(ca);

            //fs.Register("userA", "password1234");
            fs.Login("userA", "password1234");
            fs.CreateFile("somefile.txt", "somerville");

            //fs.OpenNonTextFile("stars.jpg");

            //fs.UploadFile("jordan.pdf");
            //fs.UploadFile("stars.jpg");

            //fs.OpenFile("jodrdan.pdf");

            //fs.DownloadFile("test.txt");

            fs.DownloadFile("jordan.pdf");
            fs.DownloadFile("stars.jpg");
        }

        static void Tests()
        {
            /*SHA1Managed sha1 = new SHA1Managed();

            byte[] passwordBytes = Encoding.Unicode.GetBytes("password1234");
            byte[] passwordHashBytes = sha1.ComputeHash(passwordBytes);
            string passwordHashString = Encoding.Unicode.GetString(passwordHashBytes);
            Console.WriteLine(passwordHashString);

            byte[] passwordBytes2 = Encoding.Unicode.GetBytes("password1234");
            byte[] passwordHashBytes2 = sha1.ComputeHash(passwordBytes2);
            string passwordHashString2 = Encoding.Unicode.GetString(passwordHashBytes2);
            Console.WriteLine(passwordHashString2);

            if (passwordHashString.Equals(passwordHashString2))
                Console.WriteLine("equal");
            else
                Console.WriteLine("not equal");

            Console.WriteLine("passwordBytes");
            Console.WriteLine(passwordBytes.SequenceEqual(passwordBytes2));

            Console.WriteLine("passwordHashBytes");
            Console.WriteLine(passwordHashBytes.SequenceEqual(passwordHashBytes2));

            byte[] arr1 = Encoding.Unicode.GetBytes(passwordHashString);
            byte[] arr2 = Encoding.Unicode.GetBytes(passwordHashString2);

            Console.WriteLine();
            Console.WriteLine(arr1.SequenceEqual(arr2));

            Console.WriteLine("------------------");

            FileStream fout = new FileStream(@"Data\test", FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite);
            BinaryWriter writer = new BinaryWriter(fout);
            writer.Write(passwordHashBytes);
            writer.Flush();
            writer.Close();
            fout.Close();

            File.WriteAllBytes(@"Data\test", passwordHashBytes);

            FileStream fin = new FileStream(@"Data\test", FileMode.OpenOrCreate, FileAccess.Read, FileShare.ReadWrite);//
            BinaryReader reader = new BinaryReader(fin);//
            byte[] redBytes = File.ReadAllBytes(@"Data\test");

            Console.WriteLine(redBytes.SequenceEqual(passwordHashBytes));*/
        }
    }
}
