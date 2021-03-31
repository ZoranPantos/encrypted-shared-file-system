using System.IO;
using System;

namespace EncryptedFileSystem
{
    class Program
    {
        static void Main(string[] args)
        {
            Terminal terminal = new Terminal(new CertificationAuthority());

            terminal.Run();
        }
    }
}

/*
 NOTE: Certificates in FileSystem\Certificates aren't updated along with crl.txt if I modify expiration
 date in CA and start file system again. They are not meant for modifying because they are legit with their expiration date.
 Modification by hand is just for the demonstration purposes.
 */

//NOTE: User cannot download shared file, only personal

