using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;

namespace NoSussyExe
{
    internal class Utils
    {
        public static bool GetCLRModule(int pID)
        {
            ProcessModuleCollection pModuleCollection = Process.GetProcessById(pID).Modules;
            for (int i = 0; i < pModuleCollection.Count; i++)
            {
                if (pModuleCollection[i].ModuleName.ToLower() == "clr.dll")
                    return true;
            }
            return false;
        }

        [Flags]
        public enum ThreadAccess : int
        {
            TERMINATE = (0x0001),
            SUSPEND_RESUME = (0x0002),
            GET_CONTEXT = (0x0008),
            SET_CONTEXT = (0x0010),
            SET_INFORMATION = (0x0020),
            QUERY_INFORMATION = (0x0040),
            SET_THREAD_TOKEN = (0x0080),
            IMPERSONATE = (0x0100),
            DIRECT_IMPERSONATION = (0x0200)
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll")]
        private static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        public static void SuspendProcess(int pid)
        {
            var pID = Process.GetProcessById(pid);

            if (string.IsNullOrEmpty(pID.ProcessName))
                return;

            foreach (ProcessThread pThread in pID.Threads)
            {
                IntPtr pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)pThread.Id);

                if (pOpenThread == IntPtr.Zero) continue;

                SuspendThread(pOpenThread);

                CloseHandle(pOpenThread);
            }
        }

        internal static bool IsDotNet(string peFile)
        {
            try
            {
                uint peHeader;
                uint peHeaderSignature;
                ushort machine;
                ushort sections;
                uint timestamp;
                uint pSymbolTable;
                uint noOfSymbol;
                ushort optionalHeaderSize;
                ushort characteristics;
                ushort dataDictionaryStart;
                uint[] dataDictionaryRVA = new uint[16];
                uint[] dataDictionarySize = new uint[16];


                Stream fs = new FileStream(peFile, FileMode.Open, FileAccess.Read);
                BinaryReader reader = new BinaryReader(fs);

                fs.Position = 0x3C;

                peHeader = reader.ReadUInt32();

                fs.Position = peHeader;
                peHeaderSignature = reader.ReadUInt32();

                machine = reader.ReadUInt16();
                sections = reader.ReadUInt16();
                timestamp = reader.ReadUInt32();
                pSymbolTable = reader.ReadUInt32();
                noOfSymbol = reader.ReadUInt32();
                optionalHeaderSize = reader.ReadUInt16();
                characteristics = reader.ReadUInt16();

                dataDictionaryStart = Convert.ToUInt16(Convert.ToUInt16(fs.Position) + 0x60);
                fs.Position = dataDictionaryStart;
                for (int i = 0; i < 15; i++)
                {
                    dataDictionaryRVA[i] = reader.ReadUInt32();
                    dataDictionarySize[i] = reader.ReadUInt32();
                }
                fs.Close();
                if (dataDictionaryRVA[14] == 0) return false; else return true;
            }
            catch
            {
                return false;
            }
        }
    }
}