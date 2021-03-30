using System;

namespace EncryptedFileSystem
{
    public class Terminal
    {
        private readonly FileSystem fileSystem;
        private bool loggedIn = false;
        private string loggedUser = "";

        public Terminal(CertificationAuthority ca) => fileSystem = new FileSystem(ca);

        public void Run()
        {
            Console.ForegroundColor = ConsoleColor.White;
            string command = "";

            while (!command.Equals("exit"))
            {
                Console.Write(loggedUser + "> ");
                command = Console.ReadLine();

                if (!command.Contains("login") && !loggedIn)
                {
                    Console.WriteLine("Login required");
                }
                else
                {
                    string[] parameters = command.Split(" ");

                    //login username password
                    if (parameters[0].Equals("login") && parameters.Length == 3)
                    {
                        bool result = fileSystem.Login(parameters[1], parameters[2]);

                        if (result)
                        {
                            loggedIn = true;
                            loggedUser = parameters[1];
                        }
                    }
                    //logout
                    else if (parameters[0].Equals("logout"))
                    {
                        fileSystem.Logout();
                        loggedIn = false;
                        loggedUser = "";
                    }
                    //clear
                    else if (parameters[0].Equals("clear"))
                    {
                        ClearTerminalAndPrintFiles();
                    }
                    //create file.txt file_data
                    else if (parameters[0].Equals("create") && parameters.Length == 3)
                    {
                        fileSystem.CreateFile(parameters[1], parameters[2]);
                    }
                    //delete personalfile.txt
                    else if (parameters[0].Equals("delete") && parameters.Length == 2)
                    {
                        fileSystem.DeletePersonalFile(parameters[1]);
                    }
                    //upload stars.jpg
                    else if (parameters[0].Equals("upload") && parameters.Length == 2)
                    {
                        fileSystem.UploadFile(parameters[1]);
                    }
                    //download jordan.pdf
                    else if (parameters[0].Equals("download") && parameters.Length == 2)
                    {
                        fileSystem.DownloadFile(parameters[1]);
                    }
                    //share file.txt user_X
                    else if (parameters[0].Equals("share") && parameters.Length == 3)
                    {
                        fileSystem.ShareFile(parameters[1], parameters[2]);
                    }
                    //open file.extension
                    else if (parameters[0].Equals("open") && parameters.Length == 2)
                    {
                        fileSystem.OpenFile(parameters[1]);
                    }
                    //open shared file.extension
                    else if (parameters[0].Equals("open") && parameters[1].Equals("shared") && parameters.Length == 3)
                    {
                        fileSystem.OpenSharedFile(parameters[2]);
                    }
                    //register username password
                    else if (parameters[0].Equals("register") && parameters.Length == 3 && !loggedIn)
                    {
                        fileSystem.Register(parameters[1], parameters[2]);
                    }
                    else
                        Console.WriteLine("Invalid input");
                }
            }
        }

        private void PrintPersonalFiles()
        {
            var currentUserFiles = fileSystem.GetAllCurrentUserFiles();

            Console.WriteLine("---------- Personal files ----------\n");

            foreach (var file in currentUserFiles)
                Console.WriteLine(file);

            Console.WriteLine();
        }

        private void PrintSharedFiles()
        {
            var sharedFiles = fileSystem.GetAllSharedFiles();
            var currentUserSharedFiles = fileSystem.GetAllSharedFilesWithCurrentUser();

            Console.WriteLine("---------- Shared files ----------\n");

            foreach (var file in sharedFiles)
            {
                if (currentUserSharedFiles.Contains(file))
                    Console.ForegroundColor = ConsoleColor.Yellow;

                Console.WriteLine(file);

                Console.ForegroundColor = ConsoleColor.Gray;
            }

            Console.WriteLine();
        }

        private void ClearTerminalAndPrintFiles()
        {
            Console.Clear();
            PrintPersonalFiles();
            PrintSharedFiles();
        }

    }
}
