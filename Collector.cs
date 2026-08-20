using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace FieldDeskCollector;

/// <summary>
/// Reads read-only security posture from THIS computer only and returns the
/// path to a Markdown report. Touches no other machine. Changes nothing.
/// </summary>
public static class Collector
{
    private const string Version = "1.0.0";

    public static string Run(Action<string> log)
    {
        var sb = new StringBuilder();
        var start = DateTime.Now;

        void Line(string s) => sb.AppendLine(s);
        void KV(string k, object? v) => sb.AppendLine($"- **{k}:** {v}");
        void Section(string t) { sb.AppendLine(); sb.AppendLine($"## {t}"); sb.AppendLine(); }
        void Note(string s) => sb.AppendLine($"> {s}");

        bool isAdmin = IsAdmin();
        string host = Environment.MachineName;

        // ---------------- HEADER ----------------
        Line("# FieldDesk Collection Report");
        Line("");
        KV("Hostname", host);
        KV("Collected (local)", start.ToString("yyyy-MM-dd HH:mm:ss zzz"));
        KV("Collected (UTC)", start.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss"));
        KV("Collector version", Version);
        KV("Run as", Environment.UserName);
        KV("Elevated (admin)", isAdmin);
        Line("");
        Note("This report describes only this one computer. Read-only. Nothing was changed or installed.");
        log("Header written.");

        // ---------------- DEVICE ----------------
        Section("Device");
        try
        {
            var cs = QueryFirst("SELECT * FROM Win32_ComputerSystem");
            var os = QueryFirst("SELECT * FROM Win32_OperatingSystem");
            var bios = QueryFirst("SELECT * FROM Win32_BIOS");

            if (cs != null)
            {
                KV("Manufacturer", cs["Manufacturer"]);
                KV("Model", cs["Model"]);
            }
            if (bios != null) KV("Serial", bios["SerialNumber"]);
            if (os != null)
            {
                KV("OS", os["Caption"]);
                KV("OS version", os["Version"]);
                KV("OS build", os["BuildNumber"]);
                KV("Architecture", os["OSArchitecture"]);
                KV("Installed on", ToDate(os["InstallDate"]));
                KV("Last boot", ToDate(os["LastBootUpTime"]));
            }
            bool partOfDomain = cs != null && ToBool(cs["PartOfDomain"]);
            if (partOfDomain) KV("Domain/Workgroup", $"Domain: {cs!["Domain"]}");
            else KV("Domain/Workgroup", $"Workgroup: {cs?["Workgroup"]}");
        }
        catch (Exception ex) { Note("Device section error: " + ex.Message); }
        log("Device collected.");

        // ---------------- PATCH POSTURE ----------------
        Section("Patch posture");
        try
        {
            var fixes = Query("SELECT * FROM Win32_QuickFixEngineering").ToList();
            if (fixes.Count > 0)
            {
                var ordered = fixes
                    .OrderByDescending(f => ParseDate(f["InstalledOn"]?.ToString()))
                    .ToList();
                var latest = ordered[0];
                KV("Most recent update", $"{latest["HotFixID"]} ({latest["InstalledOn"]})");
                KV("Total hotfixes listed", fixes.Count);
                Line("");
                Line("Recent updates:");
                foreach (var h in ordered.Take(8))
                    Line($"  - {h["HotFixID"]}  {h["InstalledOn"]}  {h["Description"]}");
            }
            else
            {
                Note("No hotfix history returned (common on feature-updated Windows 11; not necessarily a gap).");
            }
        }
        catch (Exception ex) { Note("Patch section error: " + ex.Message); }
        log("Patch posture collected.");

        // ---------------- DISK ENCRYPTION ----------------
        Section("Disk encryption (BitLocker)");
        if (isAdmin)
        {
            try
            {
                string outp = RunProc("manage-bde.exe", "-status");
                if (!string.IsNullOrWhiteSpace(outp))
                {
                    foreach (var raw in outp.Split('\n'))
                    {
                        var t = raw.Trim();
                        if (t.StartsWith("Volume ", StringComparison.OrdinalIgnoreCase) ||
                            t.StartsWith("Conversion Status", StringComparison.OrdinalIgnoreCase) ||
                            t.StartsWith("Protection Status", StringComparison.OrdinalIgnoreCase) ||
                            t.StartsWith("Encryption Method", StringComparison.OrdinalIgnoreCase))
                        {
                            Line("  " + t);
                        }
                    }
                }
                else
                {
                    Note("manage-bde returned nothing. BitLocker may be unavailable on this edition.");
                }
            }
            catch (Exception ex) { Note("Encryption section error: " + ex.Message); }
        }
        else
        {
            Note("UNAVAILABLE without administrator rights. Re-run elevated to capture encryption status.");
        }
        log("Encryption collected.");

        // ---------------- WINDOWS FIREWALL ----------------
        Section("Windows Firewall");
        try
        {
            string fw = RunProc("netsh.exe", "advfirewall show allprofiles state");
            string currentProfile = "";
            bool any = false;
            foreach (var raw in fw.Split('\n'))
            {
                var t = raw.Trim();
                if (t.EndsWith("Profile Settings:", StringComparison.OrdinalIgnoreCase))
                    currentProfile = t.Replace(" Profile Settings:", "", StringComparison.OrdinalIgnoreCase).Trim();
                else if (t.StartsWith("State", StringComparison.OrdinalIgnoreCase))
                {
                    var state = t.Length > 5 ? t.Substring(5).Trim() : "";
                    KV($"{currentProfile} profile", $"State: {state}");
                    any = true;
                }
            }
            if (!any) Note("Firewall profile state unavailable.");
        }
        catch (Exception ex) { Note("Firewall section error: " + ex.Message); }
        log("Firewall collected.");

        // ---------------- DEFENDER / ANTIVIRUS ----------------
        Section("Antivirus / Microsoft Defender");
        try
        {
            var mp = QueryFirst("SELECT * FROM MSFT_MpComputerStatus", @"root\Microsoft\Windows\Defender");
            if (mp != null)
            {
                KV("Antivirus enabled", mp["AntivirusEnabled"]);
                KV("Real-time protection", mp["RealTimeProtectionEnabled"]);
                KV("Signature version", mp["AntivirusSignatureVersion"]);
                KV("Signature age (days)", mp["AntivirusSignatureAge"]);
                KV("Tamper protection", mp["IsTamperProtected"]);
            }
            else
            {
                Note("Defender status unavailable (may be replaced by third-party antivirus).");
            }
        }
        catch (Exception ex) { Note("Defender section error: " + ex.Message); }

        try
        {
            var avs = Query("SELECT * FROM AntiVirusProduct", @"root\SecurityCenter2").ToList();
            if (avs.Count > 0)
            {
                Line("");
                Line("Registered antivirus products (Security Center):");
                foreach (var a in avs) Line($"  - {a["displayName"]}");
            }
        }
        catch { /* Security Center may be unavailable on server SKUs */ }
        log("Antivirus collected.");

        // ---------------- LOCAL ACCOUNTS ----------------
        Section("Local accounts");
        try
        {
            var users = Query("SELECT * FROM Win32_UserAccount WHERE LocalAccount=True").ToList();
            if (users.Count > 0)
            {
                Line("Local users:");
                foreach (var u in users)
                {
                    bool disabled = ToBool(u["Disabled"]);
                    Line($"  - {u["Name"]}  (Enabled: {!disabled}; PasswordRequired: {u["PasswordRequired"]})");
                }
            }
        }
        catch (Exception ex) { Note("Local users error: " + ex.Message); }

        Line("");
        try
        {
            string grp = RunProc("net.exe", "localgroup Administrators");
            var lines = grp.Split('\n').Select(x => x.TrimEnd('\r')).ToList();
            int dash = lines.FindIndex(x => x.StartsWith("----"));
            if (dash >= 0)
            {
                Line("Members of local Administrators group:");
                for (int i = dash + 1; i < lines.Count; i++)
                {
                    var m = lines[i].Trim();
                    if (m.Length == 0) continue;
                    if (m.StartsWith("The command completed", StringComparison.OrdinalIgnoreCase)) break;
                    Line($"  - {m}");
                }
            }
            else
            {
                Note("Could not enumerate the Administrators group.");
            }
        }
        catch (Exception ex) { Note("Administrators group error: " + ex.Message); }
        log("Local accounts collected.");

        // ---------------- MANAGEMENT ENROLLMENT ----------------
        Section("Management enrollment");
        try
        {
            string ds = RunProc("dsregcmd.exe", "/status");
            if (!string.IsNullOrWhiteSpace(ds))
            {
                foreach (var raw in ds.Split('\n'))
                {
                    var t = raw.Trim();
                    if (t.StartsWith("AzureAdJoined", StringComparison.OrdinalIgnoreCase) ||
                        t.StartsWith("DomainJoined", StringComparison.OrdinalIgnoreCase) ||
                        t.StartsWith("MdmUrl", StringComparison.OrdinalIgnoreCase))
                    {
                        Line("  - " + t);
                    }
                }
            }
            else
            {
                Note("dsregcmd did not return status.");
            }
        }
        catch (Exception ex) { Note("Management enrollment error: " + ex.Message); }
        log("Management enrollment collected.");

        // ---------------- INSTALLED SOFTWARE ----------------
        Section("Installed software");
        try
        {
            var appMap = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string[] roots =
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            };
            foreach (var r in roots)
            {
                using var key = Registry.LocalMachine.OpenSubKey(r);
                if (key == null) continue;
                foreach (var subName in key.GetSubKeyNames())
                {
                    using var k = key.OpenSubKey(subName);
                    if (k == null) continue;
                    var name = k.GetValue("DisplayName") as string;
                    if (string.IsNullOrWhiteSpace(name)) continue;
                    if (appMap.ContainsKey(name)) continue;
                    var ver = k.GetValue("DisplayVersion") as string ?? "";
                    var pub = k.GetValue("Publisher") as string ?? "";
                    appMap[name] = $"  - {name}  {ver}  [{pub}]";
                }
            }
            if (appMap.Count > 0)
            {
                KV("Applications found", appMap.Count);
                Line("");
                foreach (var v in appMap.Values) Line(v);
            }
            else
            {
                Note("No installed applications enumerated.");
            }
        }
        catch (Exception ex) { Note("Installed software error: " + ex.Message); }
        log("Installed software collected.");

        // ---------------- NETWORK (LOCAL ONLY) ----------------
        Section("Network configuration (this host only)");
        try
        {
            foreach (var n in Query("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True"))
            {
                var ips = n["IPAddress"] as string[];
                var gws = n["DefaultIPGateway"] as string[];
                string ip = ips?.FirstOrDefault(a => a != null && !a.Contains(':')) ?? (ips?.FirstOrDefault() ?? "");
                string gw = gws?.FirstOrDefault() ?? "";
                KV($"Interface {n["Description"]}", $"IPv4: {ip}; Gateway: {gw}");
            }
        }
        catch (Exception ex) { Note("Network section error: " + ex.Message); }
        Note("Only this host's own adapter configuration is read. No other hosts are contacted or scanned.");
        log("Network collected.");

        // ---------------- FOOTER ----------------
        var elapsed = DateTime.Now - start;
        Section("Collection summary");
        KV("Elapsed", $"{elapsed.TotalSeconds:N1} seconds");
        KV("Elevated", isAdmin);
        Line("");
        Line("### What was NOT collected (by design)");
        Line("- No documents, spreadsheets, or personal files");
        Line("- No passwords, secrets, or credential material");
        Line("- No email content or mailboxes");
        Line("- No browser history or saved data");
        Line("- No keystrokes or screen contents");
        Line("- No data from any other computer on the network");
        Line("");
        Line($"_Report generated by FieldDesk Collector v{Version}. Read-only. Open source (MIT)._");

        // ---------------- WRITE FILE ----------------
        string dir = Path.GetDirectoryName(Environment.ProcessPath) ?? Directory.GetCurrentDirectory();
        string fileName = $"FieldDesk_{Sanitize(host)}_{start:yyyyMMdd-HHmmss}.md";
        string fullPath = Path.Combine(dir, fileName);
        try
        {
            File.WriteAllText(fullPath, sb.ToString(), new UTF8Encoding(true));
        }
        catch
        {
            fullPath = Path.Combine(Directory.GetCurrentDirectory(), fileName);
            File.WriteAllText(fullPath, sb.ToString(), new UTF8Encoding(true));
        }
        return fullPath;
    }

    // ===================== helpers =====================

    private static IEnumerable<ManagementObject> Query(string wql, string ns = @"root\CIMV2")
    {
        var scope = new ManagementScope($@"\\.\{ns}");
        scope.Connect();
        using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(wql));
        foreach (ManagementObject mo in searcher.Get())
            yield return mo;
    }

    private static ManagementObject? QueryFirst(string wql, string ns = @"root\CIMV2")
    {
        foreach (var mo in Query(wql, ns))
            return mo;
        return null;
    }

    private static string RunProc(string file, string args)
    {
        try
        {
            var psi = new ProcessStartInfo(file, args)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p == null) return "";
            string o = p.StandardOutput.ReadToEnd();
            p.WaitForExit(20000);
            return o;
        }
        catch
        {
            return "";
        }
    }

    private static bool IsAdmin()
    {
        try
        {
            using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            var p = new System.Security.Principal.WindowsPrincipal(id);
            return p.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private static string ToDate(object? wmiDate)
    {
        try
        {
            if (wmiDate == null) return "";
            return ManagementDateTimeConverter
                .ToDateTime(wmiDate.ToString())
                .ToString("yyyy-MM-dd HH:mm:ss");
        }
        catch
        {
            return wmiDate?.ToString() ?? "";
        }
    }

    private static DateTime ParseDate(string? s)
    {
        return DateTime.TryParse(s, out var d) ? d : DateTime.MinValue;
    }

    private static bool ToBool(object? o)
    {
        if (o == null) return false;
        if (o is bool b) return b;
        return bool.TryParse(o.ToString(), out var r) && r;
    }

    private static string Sanitize(string s)
    {
        return Regex.Replace(s, "[^A-Za-z0-9_-]", "_");
    }
}
