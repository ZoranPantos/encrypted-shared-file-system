using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Serialization;

namespace EncryptedFileSystem.CryptoAlgorithms
{
    public class RSA
    {
        private RSACryptoServiceProvider csp;
        public RSAParameters PublicKey { get; set; }
        public RSAParameters PrivateKey { get; set; }

        public RSA(int bitSize = 2048)
        {
            csp = new RSACryptoServiceProvider(bitSize);
            PrivateKey = csp.ExportParameters(true);
            PublicKey = csp.ExportParameters(false);
        }

        public string PublicKeyToXmlString()
        {
            StringWriter writer = new StringWriter();
            XmlSerializer serializer = new XmlSerializer(typeof(RSAParameters));

            serializer.Serialize(writer, PublicKey);

            return writer.ToString();
        }

        public void XmlStringToPublicKey(string xmlPublicKey)
        {
            StringReader reader = new StringReader(xmlPublicKey);
            XmlSerializer serializer = new XmlSerializer(typeof(RSAParameters));

            PublicKey = (RSAParameters)serializer.Deserialize(reader);
        }

        public string PrivateKeyToXmlString()
        {
            StringWriter writer = new StringWriter();
            XmlSerializer serializer = new XmlSerializer(typeof(RSAParameters));

            serializer.Serialize(writer, PrivateKey);

            return writer.ToString();
        }

        public void XmlStringToPrivateKey(string xmlPrivateKey)
        {
            StringReader reader = new StringReader(xmlPrivateKey);
            XmlSerializer serializer = new XmlSerializer(typeof(RSAParameters));

            PrivateKey = (RSAParameters)serializer.Deserialize(reader);
        }

        public byte[] Encrypt(string plainText)
        {
            byte[] plainTextBytes = Encoding.Unicode.GetBytes(plainText);
            RSACryptoServiceProvider csp2 = new RSACryptoServiceProvider();

            csp2.ImportParameters(PublicKey);
            byte[] cipher = csp2.Encrypt(plainTextBytes, false);

            return cipher;
        }

        public byte[] Decrypt(byte[] cipher)
        {
            RSACryptoServiceProvider csp3 = new RSACryptoServiceProvider();
            csp3.ImportParameters(PrivateKey);
            byte[] decryptedCipher = csp3.Decrypt(cipher, false);
            return decryptedCipher;
        }
    }
}
