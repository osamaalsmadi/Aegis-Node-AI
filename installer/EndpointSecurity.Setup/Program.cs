using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;
using System.Security.Principal;

internal static class Program
{
    private const string PayloadResource =
        "EndpointSecurityPlatform.Payload.zip";

    public static int Main()
    {
        try
        {
            if (!IsAdministrator())
            {
                return RelaunchAsAdministrator();
            }

            return RunInstaller();
        }
        catch (Exception exception)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Error.WriteLine();
            Console.Error.WriteLine("Endpoint Security Platform setup failed.");
            Console.Error.WriteLine(exception.Message);
            Console.ResetColor();
            Console.WriteLine();
            Console.WriteLine("Press Enter to close.");
            Console.ReadLine();
            return 1;
        }
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);

        return principal.IsInRole(
            WindowsBuiltInRole.Administrator);
    }

    private static int RelaunchAsAdministrator()
    {
        var executable = Environment.ProcessPath
            ?? throw new InvalidOperationException(
                "Could not determine the Setup executable path.");

        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = true,
            Verb = "runas"
        };

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException(
                "Could not start the elevated Setup process.");

        process.WaitForExit();
        return process.ExitCode;
    }

    private static int RunInstaller()
    {
        var installerRoot = Path.Combine(
            Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData),
            "EndpointSecurityPlatform",
            $"Installer-{Guid.NewGuid():N}");

        var archivePath = Path.Combine(
            installerRoot,
            "Payload.zip");
        var extractPath = Path.Combine(
            installerRoot,
            "Payload");

        Directory.CreateDirectory(installerRoot);

        try
        {
            using var resource = Assembly
                .GetExecutingAssembly()
                .GetManifestResourceStream(PayloadResource)
                ?? throw new InvalidOperationException(
                    "The embedded installer payload is missing.");

            using (var archive = File.Create(archivePath))
            {
                resource.CopyTo(archive);
            }

            ZipFile.ExtractToDirectory(
                archivePath,
                extractPath);

            var installScript = Path.Combine(
                extractPath,
                "Install.ps1");

            if (!File.Exists(installScript))
            {
                throw new FileNotFoundException(
                    "Install.ps1 is missing from the payload.",
                    installScript);
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                UseShellExecute = false
            };

            startInfo.ArgumentList.Add("-NoProfile");
            startInfo.ArgumentList.Add("-ExecutionPolicy");
            startInfo.ArgumentList.Add("Bypass");
            startInfo.ArgumentList.Add("-File");
            startInfo.ArgumentList.Add(installScript);

            using var process = Process.Start(startInfo)
                ?? throw new InvalidOperationException(
                    "Could not start the PowerShell installer.");

            process.WaitForExit();
            return process.ExitCode;
        }
        finally
        {
            try
            {
                Directory.Delete(installerRoot, recursive: true);
            }
            catch
            {
            }
        }
    }
}