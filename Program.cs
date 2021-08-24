using ImagePlayer;
using Microsoft.CSharp;
using NoSussyExe.Dumper;
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;

namespace NoSussyExe
{
    class Program
    {
        private static void Main(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Title = "NoSussyExe";

            ImagePlayer.ImagePlayer player = new ImagePlayer.ImagePlayer();
            player.SetScale(5);
            player.LoadSource("https://media1.giphy.com/media/02UcS4abtGiipuMkBa/giphy.gif?cid=6c09b9522swr6wwz4zl5uaotn7livxg4shtw5urhpg4w7yqh&rid=giphy.gif&ct=s");

            if (args.Length < 1)
            {
                while (true)
                {
                    string text = "Please drag & drop your sussy exe!";
                    string text2 = "Not inside the console, but on the NoSussyExe.exe";

                    for (int i = 0; i < text.Length; i++)
                    {
                        Console.Write(text[i].ToString());
                        Thread.Sleep(5);
                    }
                    Thread.Sleep(2500);
                    Console.Clear();
                    for (int i = 0; i < text2.Length; i++)
                    {
                        Console.Write(text2[i].ToString());
                        Thread.Sleep(5);
                    }
                    Thread.Sleep(2500);
                    Console.Clear();
                }
            }
            else if (args.Length > 1)
            {
                while (true)
                {
                    string text = "Please only drag & drop 1 file!";

                    for (int i = 0; i < text.Length; i++)
                    {
                        Console.Write(text[i].ToString());
                        Thread.Sleep(5);
                    }
                    Console.ReadKey();
                    Environment.Exit(1);
                }
            }
            else if (!Utils.IsDotNet(args[0]))
            {
                while (true)
                {
                    string text = "Please only drag & drop valid .NET files!";

                    for (int i = 0; i < text.Length; i++)
                    {
                        Console.Write(text[i].ToString());
                        Thread.Sleep(5);
                    }
                    Console.ReadKey();
                    Environment.Exit(1);
                }
            }

            int lineCount = 1;
            bool autoDump = false;
            bool restoreOriginalFilenames = false;
            bool dumpNative = false;
            lineCount++;
            Console.SetCursorPosition(40, lineCount);
            Console.WriteLine($"Dump Automatically? [Y/N]");
            ConsoleKeyInfo key = Console.ReadKey();

            if (key.Key == ConsoleKey.Y)
            {
                autoDump = true;
                Console.SetCursorPosition(83, lineCount);
                Console.Write("Y");
            }
            else
            {
                Console.SetCursorPosition(83, lineCount);
                Console.Write("N");
            }

            if (autoDump)
            {
                lineCount++;
                Console.SetCursorPosition(40, lineCount);
                Console.WriteLine($"Dump Native? [Y/N] ");
                ConsoleKeyInfo key2 = Console.ReadKey();
                if (key2.Key == ConsoleKey.Y)
                {
                    dumpNative = true;
                    Console.SetCursorPosition(83, lineCount);
                    Console.Write("Y");
                }
                else
                {
                    Console.SetCursorPosition(83, lineCount);
                    Console.Write("N");
                }

                lineCount++;
                Console.SetCursorPosition(40, lineCount);
                Console.WriteLine($"Restore Original Filenames? [Y/N] ");
                ConsoleKeyInfo key3 = Console.ReadKey();
                if (key3.Key == ConsoleKey.Y)
                {
                    restoreOriginalFilenames = true;
                    Console.SetCursorPosition(83, lineCount);
                    Console.Write("Y");
                }
                else
                {
                    Console.SetCursorPosition(83, lineCount);
                    Console.Write("N");
                }
            }

            try
            {
                string SusExePath = args[0];
                Process SusProcess = new Process();
                SusProcess.StartInfo.CreateNoWindow = true;
                SusProcess.StartInfo.UseShellExecute = false;
                SusProcess.StartInfo.FileName = SusExePath;
                try
                {
                    SusProcess.Start();
                }
                catch
                {
                    Console.Clear();
                    while (true)
                    {
                        string text = "Please only drag & drop valid .NET files!";

                        for (int i = 0; i < text.Length; i++)
                        {
                            Console.Write(text[i].ToString());
                            Thread.Sleep(5);
                        }
                        Console.ReadKey();
                        Environment.Exit(1);
                    }
                }

                int ProcessID = SusProcess.Id;

                new Thread(() => player.PrintImage(40, true, true, 3, 0)).Start();

                while (true)
                {
                    if (Utils.GetCLRModule(ProcessID))
                    {
                        Utils.SuspendProcess(ProcessID);

                        lineCount++;
                        Console.SetCursorPosition(40, lineCount);
                        Console.WriteLine($"{Path.GetFileName(SusExePath)} has been loaded!");

                        lineCount++;
                        if (autoDump)
                        {
                            Console.SetCursorPosition(40, lineCount);
                            Console.WriteLine($"Now dumping...");

                            Dumper.Dumper dumper = new Dumper.Dumper();
                            dumper.DumpProcess(ProcessID, Path.GetDirectoryName(SusExePath), dumpNative, restoreOriginalFilenames);
                            SusProcess.Kill();

                            lineCount++;
                            Console.SetCursorPosition(40, lineCount);
                            Console.WriteLine($"{dumper.DumpLog}");

                            lineCount += 2;
                            Console.SetCursorPosition(40, lineCount);
                        }
                        else
                        {
                            Console.SetCursorPosition(40, lineCount);
                            Console.WriteLine($"Press any key to kill process!");
                            Console.ReadKey();
                            SusProcess.Kill();
                            lineCount += 2;
                            Console.SetCursorPosition(40, lineCount);
                        }

                        Console.WriteLine($"Press any key to close!");
                        Console.ReadKey();
                        Environment.Exit(0);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Clear();
                Console.WriteLine(ex.ToString());
            }
        }
    }
}