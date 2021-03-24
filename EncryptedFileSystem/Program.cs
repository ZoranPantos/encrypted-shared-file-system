namespace EncryptedFileSystem
{
    class Program
    {
        static void Main(string[] args)
        {
            CertificationAuthority ca = new CertificationAuthority();
            FileSystem fs = new FileSystem(ca);

            fs.Login("zoran", "zoran");
            //fs.CreateFile("zoranfile.txt", "my name is zoran pantos");
            //fs.ShareFile("zoranfile.txt", "adele");

            fs.PrintDecrypted();
            //fs.TestRSA();
        }
    }
}
