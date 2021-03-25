using System.IO;
using System;

namespace EncryptedFileSystem
{
    class Program
    {
        static void Main(string[] args)
        {
            CertificationAuthority ca = new CertificationAuthority();
            FileSystem fs = new FileSystem(ca);

            fs.Login("adele", "adele");
            //fs.OpenSharedTest("forzoky.txt", "adele");
            fs.OpenPersonalSharedTest("forzoky.txt");
            

            //fs.PrintDecryptedAES();

            
            //fs.TestRSA();
        }
    }
}
