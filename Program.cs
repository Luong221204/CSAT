namespace CSAT;
using System;
using System.Windows.Forms;
using System.Runtime.InteropServices;
static class Program
{
    /// <summary>
    ///  The main entry point for the application.
    /// </summary>
    [STAThread]

      [DllImport("kernel32.dll")]
    static extern bool AllocConsole();
    static void Main()
    {
        AllocConsole(); // 👈 thêm dòng này

        Console.WriteLine("Hello bro!");
        // To customize application configuration such as set high DPI settings or default font,
        // see https://aka.ms/applicationconfiguration
        // .
        ApplicationConfiguration.Initialize();
        Application.Run(new Form1());
    }    
}