﻿namespace EncryptedFileSystem
{
    public class User
    {
        public string Username { get; set; }
        public string PublicXmlKey { get; set; }
        public string PrivateXmlKey { get; set; }
        public string SymetricKey { get; set; }
    }
}
