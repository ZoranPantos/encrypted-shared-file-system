using System;
using System.IO;

namespace EncryptedFileSystem
{
    public class Certificate
    {
        public string Id { get; set; }
        public string Algorithm { get; set; }
        public string Issuer { get; set; }
        
        /*Sifruje se string "CA" privatnim kljucem i sifrat se sacuva. Onaj ko povuce ovaj sertifikat,
        moze povuci i javni kljuc CA tijela i desifrovati sifrat. Ako dobije string "CA", onda je to potvrda
        da je sertifikat izdan od strane datog CA tijela.*/
        public string IssuerNameCipher { get; set; }

        public string Subject { get; set; }
        public DateTime Expiration { get; set; }
        public string SubjectPublicKey { get; set; }

        public void Save(string path)
        {
            StreamWriter writer = new StreamWriter(path);

            writer.WriteLine("----- DIGITAL CERTIFICATE -----");
            writer.WriteLine("\nID");
            writer.WriteLine(Id);
            writer.WriteLine("\nALGORITHM");
            writer.WriteLine(Algorithm);
            writer.WriteLine("\nISSUER");
            writer.WriteLine(Issuer);
            writer.WriteLine("\nISSUER NAME CIPHER");
            writer.WriteLine(IssuerNameCipher);
            writer.WriteLine("\nSUBJECT");
            writer.WriteLine(Subject);
            writer.WriteLine("\nEXPIRATION");
            writer.WriteLine(Expiration);
            writer.WriteLine("\nSUBJECT PUBLIC KEY");
            writer.WriteLine(SubjectPublicKey);

            writer.Flush();
            writer.Close();
        }

        public Certificate Load(string path)
        {
            StreamReader reader = new StreamReader(path);
            Certificate result = new Certificate();

            while (!reader.EndOfStream)
            {
                string line = reader.ReadLine();

                if (line.Equals("ID"))
                    Id = reader.ReadLine();
                else if (line.Equals("ALGORITHM"))
                    Algorithm = reader.ReadLine();
                else if (line.Equals("ISSUER"))
                    Issuer = reader.ReadLine();
                else if (line.Equals("ISSUER NAME CIPHER"))
                    IssuerNameCipher = reader.ReadLine();
                else if (line.Equals("SUBJECT"))
                    Subject = reader.ReadLine();
                else if (line.Equals("EXPIRATION"))
                    Expiration = DateTime.Parse(reader.ReadLine());
                else if (line.Equals("SUBJECT PUBLIC KEY"))
                    SubjectPublicKey = reader.ReadToEnd();
            }

            reader.Close();
            return result;
        }

        //For testing purposes
        public void PrintToConsole()
        {
            Console.WriteLine("ID");
            Console.WriteLine(Id);
            Console.WriteLine();

            Console.WriteLine("ALGORITHM");
            Console.WriteLine(Algorithm);
            Console.WriteLine();

            Console.WriteLine("ISSUER");
            Console.WriteLine(Issuer);
            Console.WriteLine();

            Console.WriteLine("ISSUER NAME CIPHER");
            Console.WriteLine(IssuerNameCipher);
            Console.WriteLine();

            Console.WriteLine("SUBJECT");
            Console.WriteLine(Subject);
            Console.WriteLine();

            Console.WriteLine("EXPIRATION");
            Console.WriteLine(Expiration);
            Console.WriteLine();

            Console.WriteLine("SUBJECT PUBLIC KEY");
            Console.WriteLine(SubjectPublicKey);
        }

        public bool IsValid() => Expiration > DateTime.Now;
    }
}
