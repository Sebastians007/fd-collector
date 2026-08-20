using System;
using System.Windows.Forms;

namespace FieldDeskCollector;

internal static class Program
{
    [STAThread]
    static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }
}
