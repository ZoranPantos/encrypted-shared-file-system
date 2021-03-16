using EncryptedFileSystem.CryptoAlgorithms;
using System;
using System.IO;
using System.Text;
using System.Threading;

namespace EncryptedFileSystem
{
    class Program
    {
        static void Main(string[] args)
        {
            CertificationAuthority ca = new CertificationAuthority();

            /*ca.AddActiveCert("1 zoran 14/03/2021 21:50:10");
            ca.AddActiveCert("2 amanda 14/03/2021 21:51:10");
            ca.AddActiveCert("3 sigmund 14/03/2021 10:50:10");
            ca.AddActiveCert("4 goran 14/03/2021 11:50:10");
            ca.AddActiveCert("5 boran 14/03/2021 21:52:10");*/

            /*Certificate cert2 = ca.IssueCertificate(new User { Username = "c", PublicXmlKey = "tdfghjdfPublicKey" });
            Certificate cert3 = ca.IssueCertificate(new User { Username = "DDDDD", PublicXmlKey = "tddfgfghjPublicKey" });
            Certificate cert4 = ca.IssueCertificate(new User { Username = "EeEeE", PublicXmlKey = "tdfghjPufghjhhblicKey" });*/
            
        }
    }
}
