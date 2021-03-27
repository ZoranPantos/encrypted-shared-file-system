using System.IO;
using System;

namespace EncryptedFileSystem
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.White;

            CertificationAuthority ca = new CertificationAuthority();
            FileSystem fs = new FileSystem(ca);

            fs.Login("zoran", "zoran");
            fs.OpenPersonalSharedTest("odin.txt");
            //fs.OpenSharedTest("odin.txt", "zoran");
        }
    }
}
