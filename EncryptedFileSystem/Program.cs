using EncryptedFileSystem.CryptoAlgorithms;
using System;
using System.IO;
using System.Text;

namespace EncryptedFileSystem
{
    class Program
    {
        static void Main(string[] args)
        {
            Directory.CreateDirectory(@"Data\CA");
            CertificationAuthority ca = new CertificationAuthority();
            ca.PrintToConsole();
            Certificate cert = new Certificate();
            cert.Load(@"Data\CA\ca_certificate.txt");
            cert.PrintToConsole();
        }
    }
}
