using System;
using System.Diagnostics;
using System.Threading;

namespace X64dbgMcpFixtures
{
    internal static class SpawnChild
    {
        private static int Main(string[] args)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "notepad.exe",
                    UseShellExecute = false,
                };
                Process.Start(psi);
                Thread.Sleep(8000);
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex);
                return 1;
            }
        }
    }
}
