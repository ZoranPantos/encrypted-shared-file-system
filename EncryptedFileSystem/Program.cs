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

//TODO: Block users to open shared files which they don't share

//NOTE: User cannot download shared file, only personal