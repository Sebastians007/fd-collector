using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace FieldDeskCollector;

/// <summary>
/// Reads read-only security posture from THIS computer only and returns the
/// path to a Markdown report. Touches no other machine. Changes nothing.
/// Never writes a BitLocker recovery key into the report.
/// </summary>
public static class Collector
{
    private const string Version = "1.1.0";

    // Recovery-key shape: 8 groups of 6 digits. Used only to REDACT, never to emit.
    private static readonly Regex RecoveryKeyPattern =
        new(@"\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}", RegexOptions.Compiled);

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

        // Reused across sections.
        var adminMembers = new List<string>();
        string loggedInUser = "";

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
                loggedInUser = cs["UserName"]?.ToString() ?? "";
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
            if (!string.IsNullOrEmpty(loggedInUser)) KV("Logged-in user", loggedInUser);
        }
        catch (Exception ex) { Note("Device section error: " + ex.Message); }
        log("Device collected.");

        // ---------------- TIME & TIMEZONE ----------------
        Section("System time");
        try
        {
            KV("Local time", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss zzz"));
            KV("UTC time", DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"));
            KV("Time zone", TimeZoneInfo.Local.DisplayName);
        }
        catch (Exception ex) { Note("Time section error: " + ex.Message); }

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

        // ---------------- WINDOWS UPDATE CONFIG ----------------
        Section("Windows Update configuration");
        try
        {
            object? au = ReadReg(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "AUOptions");
            object? noAuto = ReadReg(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate");
            if (au != null) KV("AUOptions (policy)", $"{au} ({AuOptionText(au)})");
            else Note("No Windows Update policy set (managed by default Windows settings).");
            if (noAuto != null) KV("NoAutoUpdate (policy)", noAuto);
        }
        catch (Exception ex) { Note("Windows Update section error: " + ex.Message); }

        // ---------------- DISK ENCRYPTION ----------------
        Section("Disk encryption (BitLocker)");
        if (isAdmin)
        {
            try
            {
                string status = RunProc("manage-bde.exe", "-status");
                if (!string.IsNullOrWhiteSpace(status))
                {
                    foreach (var raw in status.Split('\n'))
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

                // Recovery-key protector presence ONLY. The key value is never emitted.
                Line("");
                Line("Recovery protection (key value is never collected):");
                string prot = RunProc("manage-bde.exe", "-protectors -get C:");
                if (!string.IsNullOrWhiteSpace(prot))
                {
                    bool hasNumeric = false, hasTpm = false, hasPassword = false, hasExternal = false;
                    foreach (var raw in prot.Split('\n'))
                    {
                        // Never emit any line that contains a recovery-key pattern.
                        if (RecoveryKeyPattern.IsMatch(raw)) continue;
                        var t = raw.Trim();
                        if (t.StartsWith("Numerical Password", StringComparison.OrdinalIgnoreCase)) hasNumeric = true;
                        if (t.StartsWith("TPM", StringComparison.OrdinalIgnoreCase)) hasTpm = true;
                        if (t.StartsWith("Password", StringComparison.OrdinalIgnoreCase)) hasPassword = true;
                        if (t.StartsWith("External Key", StringComparison.OrdinalIgnoreCase)) hasExternal = true;
                    }
                    KV("Recovery password protector present", hasNumeric);
                    KV("TPM protector present", hasTpm);
                    KV("Password protector present", hasPassword);
                    KV("External key protector present", hasExternal);
                    if (!hasNumeric)
                        Note("No recovery-password protector found. If the disk is encrypted, a lost TPM or reset could make data unrecoverable. Verify a recovery key is escrowed.");
                }
                else
                {
                    Note("No protector information returned (volume may be unencrypted).");
                }
            }
            catch (Exception ex) { Note("Encryption section error: " + ex.Message); }
        }
        else
        {
            Note("UNAVAILABLE without administrator rights. Re-run elevated to capture encryption status.");
        }
        log("Encryption collected.");

        // ---------------- TPM & SECURE BOOT ----------------
        Section("TPM and Secure Boot");
        try
        {
            var tpm = QueryFirst("SELECT * FROM Win32_Tpm", @"root\CIMV2\Security\MicrosoftTpm");
            if (tpm != null)
            {
                KV("TPM present", true);
                KV("TPM enabled", tpm["IsEnabled_InitialValue"]);
                KV("TPM activated", tpm["IsActivated_InitialValue"]);
                KV("TPM spec version", tpm["SpecVersion"]);
            }
            else
            {
                KV("TPM present", false);
            }
        }
        catch { KV("TPM present", "Unknown (query failed; TPM may be absent)"); }

        try
        {
            object? sb2 = ReadReg(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled");
            if (sb2 != null) KV("Secure Boot enabled", ToInt(sb2) == 1);
            else KV("Secure Boot", "State key absent (likely legacy BIOS or disabled)");
        }
        catch (Exception ex) { Note("Secure Boot read error: " + ex.Message); }
        log("TPM and Secure Boot collected.");

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

        // Defender exclusions — a common malware persistence trick.
        try
        {
            var pref = QueryFirst("SELECT * FROM MSFT_MpPreference", @"root\Microsoft\Windows\Defender");
            if (pref != null)
            {
                Line("");
                Line("Defender exclusions:");
                EmitArray(Line, "Path", pref["ExclusionPath"] as string[]);
                EmitArray(Line, "Extension", pref["ExclusionExtension"] as string[]);
                EmitArray(Line, "Process", pref["ExclusionProcess"] as string[]);
            }
        }
        catch { /* preference class may be unavailable */ }
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
                    string name = u["Name"]?.ToString() ?? "";
                    bool disabled = ToBool(u["Disabled"]);
                    string lastLogon = LastLogon(name);
                    Line($"  - {name}  (Enabled: {!disabled}; PasswordRequired: {u["PasswordRequired"]}; Last logon: {lastLogon})");
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
                    adminMembers.Add(m);
                    Line($"  - {m}");
                }
            }
            else
            {
                Note("Could not enumerate the Administrators group.");
            }
        }
        catch (Exception ex) { Note("Administrators group error: " + ex.Message); }

        // Is the interactive user an administrator?
        try
        {
            if (!string.IsNullOrEmpty(loggedInUser))
            {
                string shortName = loggedInUser.Contains('\\') ? loggedInUser.Split('\\').Last() : loggedInUser;
                bool inAdmins = adminMembers.Any(a =>
                    a.EndsWith("\\" + shortName, StringComparison.OrdinalIgnoreCase) ||
                    a.Equals(shortName, StringComparison.OrdinalIgnoreCase) ||
                    a.Equals(loggedInUser, StringComparison.OrdinalIgnoreCase));
                Line("");
                KV("Logged-in user is a local administrator", inAdmins);
                if (inAdmins)
                    Note("The account in daily use has administrator rights. This is a standing-privilege finding.");
            }
        }
        catch (Exception ex) { Note("Admin-user check error: " + ex.Message); }
        log("Local accounts collected.");

        // ---------------- PASSWORD & LOCKOUT POLICY ----------------
        Section("Password and lockout policy");
        try
        {
            string acc = RunProc("net.exe", "accounts");
            foreach (var raw in acc.Split('\n'))
            {
                var t = raw.TrimEnd('\r');
                if (t.Contains(':')) Line("  " + t.Trim());
            }
        }
        catch (Exception ex) { Note("Password policy error: " + ex.Message); }

        // ---------------- LOCAL SECURITY SETTINGS ----------------
        Section("Local security settings");
        try
        {
            object? lmCompat = ReadReg(@"SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel");
            KV("LM compatibility level", lmCompat ?? "Not set (default)");
            object? restrictAnon = ReadReg(@"SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymous");
            KV("RestrictAnonymous", restrictAnon ?? "Not set");
            object? restrictAnonSam = ReadReg(@"SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymousSAM");
            KV("RestrictAnonymousSAM", restrictAnonSam ?? "Not set");
            object? uac = ReadReg(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA");
            KV("UAC enabled (EnableLUA)", uac == null ? "Not set" : (ToInt(uac) == 1).ToString());
            object? consent = ReadReg(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin");
            KV("UAC admin prompt level", consent ?? "Not set");
            object? autorun = ReadReg(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun");
            KV("Autorun policy (NoDriveTypeAutoRun)", autorun ?? "Not set");
            // Guest / Administrator rename check comes from the users list.
        }
        catch (Exception ex) { Note("Local security settings error: " + ex.Message); }

        // ---------------- SMBv1 ----------------
        Section("SMBv1 protocol");
        try
        {
            object? smb1 = ReadReg(@"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start");
            object? smb1Srv = ReadReg(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1");
            KV("SMBv1 client service start", smb1 == null ? "Unknown" : SmbStartText(smb1));
            KV("SMBv1 server enabled", smb1Srv == null ? "Default" : (ToInt(smb1Srv) == 1).ToString());
        }
        catch (Exception ex) { Note("SMBv1 section error: " + ex.Message); }

        // ---------------- SCREEN LOCK ----------------
        Section("Screen lock");
        try
        {
            // Machine policy first, then current user hive (admin's) as a fallback.
            object? active = ReadRegAny(@"Control Panel\Desktop", "ScreenSaveActive");
            object? timeout = ReadRegAny(@"Control Panel\Desktop", "ScreenSaveTimeOut");
            object? secure = ReadRegAny(@"Control Panel\Desktop", "ScreenSaverIsSecure");
            KV("Screensaver active", active ?? "Not set");
            KV("Screensaver timeout (sec)", timeout ?? "Not set");
            KV("Password on resume", secure ?? "Not set");
            Note("Screen-lock values reflect the hive readable while elevated and may not equal the daily user's settings.");
        }
        catch (Exception ex) { Note("Screen lock error: " + ex.Message); }

        // ---------------- AUDIT POLICY & EVENT LOGS ----------------
        Section("Audit policy and event logs");
        if (isAdmin)
        {
            try
            {
                string ap = RunProc("auditpol.exe", "/get /category:*");
                var wanted = new[] { "Logon", "Logoff", "Account Lockout", "Special Logon",
                                     "User Account Management", "Security Group Management",
                                     "Audit Policy Change", "Process Creation" };
                foreach (var raw in ap.Split('\n'))
                {
                    var t = raw.Trim();
                    if (wanted.Any(w => t.StartsWith(w, StringComparison.OrdinalIgnoreCase)))
                        Line("  " + Regex.Replace(t, "\\s{2,}", "  "));
                }
            }
            catch (Exception ex) { Note("Audit policy error: " + ex.Message); }

            try
            {
                Line("");
                Line("Event log limits:");
                foreach (var logName in new[] { "Security", "System", "Application" })
                {
                    string g = RunProc("wevtutil.exe", $"gl {logName}");
                    string max = "", retain = "";
                    foreach (var raw in g.Split('\n'))
                    {
                        var t = raw.Trim();
                        if (t.StartsWith("maxSize", StringComparison.OrdinalIgnoreCase)) max = t;
                        if (t.StartsWith("retention", StringComparison.OrdinalIgnoreCase)) retain = t;
                    }
                    Line($"  - {logName}: {max}; {retain}");
                }
            }
            catch (Exception ex) { Note("Event log read error: " + ex.Message); }
        }
        else
        {
            Note("UNAVAILABLE without administrator rights.");
        }
        log("Audit policy collected.");

        // ---------------- LISTENING PORTS ----------------
        Section("Listening ports");
        try
        {
            string ns = RunProc("netstat.exe", "-ano");
            var seen = new List<string>();
            foreach (var raw in ns.Split('\n'))
            {
                var t = raw.Trim();
                if (!t.Contains("LISTENING", StringComparison.OrdinalIgnoreCase)) continue;
                var parts = Regex.Split(t, "\\s+");
                if (parts.Length >= 5)
                {
                    string local = parts[1];
                    string pid = parts[4];
                    string entry = $"  - {parts[0]}  {local}  PID {pid}  ({ProcName(pid)})";
                    if (!seen.Contains(entry)) { seen.Add(entry); Line(entry); }
                }
            }
            if (seen.Count == 0) Note("No listening ports parsed.");
        }
        catch (Exception ex) { Note("Listening ports error: " + ex.Message); }
        log("Listening ports collected.");

        // ---------------- SHARED FOLDERS ----------------
        Section("Shared folders");
        try
        {
            var shares = Query("SELECT * FROM Win32_Share").ToList();
            if (shares.Count > 0)
                foreach (var s in shares)
                    Line($"  - {s["Name"]}  ->  {s["Path"]}  ({s["Description"]})");
            else
                Note("No shares enumerated.");
        }
        catch (Exception ex) { Note("Shares error: " + ex.Message); }

        // ---------------- PRINTERS ----------------
        Section("Printers and spooler");
        try
        {
            var spooler = QueryFirst("SELECT * FROM Win32_Service WHERE Name='Spooler'");
            if (spooler != null) KV("Print Spooler service", $"State: {spooler["State"]}; StartMode: {spooler["StartMode"]}");
            var printers = Query("SELECT * FROM Win32_Printer").ToList();
            foreach (var p in printers)
                Line($"  - {p["Name"]}  (Shared: {p["Shared"]}; Network: {p["Network"]})");
        }
        catch (Exception ex) { Note("Printer section error: " + ex.Message); }

        // ---------------- MAPPED DRIVES ----------------
        Section("Mapped drives");
        try
        {
            string nu = RunProc("net.exe", "use");
            foreach (var raw in nu.Split('\n'))
            {
                var t = raw.TrimEnd('\r');
                if (t.Contains(":\\") || t.Contains("\\\\")) Line("  " + t.Trim());
            }
            Note("Mapped drives are per-user; this reflects the elevated context.");
        }
        catch (Exception ex) { Note("Mapped drives error: " + ex.Message); }

        // ---------------- SCHEDULED TASKS (NON-MICROSOFT) ----------------
        Section("Scheduled tasks (non-Microsoft)");
        try
        {
            string st = RunProc("schtasks.exe", "/query /fo csv");
            var lines = st.Split('\n').Select(x => x.Trim()).Where(x => x.Length > 0).ToList();
            int shown = 0;
            foreach (var l in lines)
            {
                if (l.StartsWith("\"TaskName\"", StringComparison.OrdinalIgnoreCase)) continue;
                if (l.StartsWith("\"\\Microsoft\\", StringComparison.OrdinalIgnoreCase)) continue;
                if (!l.StartsWith("\"\\")) continue;
                Line("  - " + l.Replace("\"", ""));
                shown++;
                if (shown >= 60) { Line("  - ... (list truncated)"); break; }
            }
            if (shown == 0) Note("No non-Microsoft scheduled tasks found.");
        }
        catch (Exception ex) { Note("Scheduled tasks error: " + ex.Message); }
        log("Tasks and shares collected.");

        // ---------------- THIRD-PARTY UPDATER SERVICES ----------------
        Section("Third-party updater services");
        try
        {
            string[] wanted = { "gupdate", "gupdatem", "MozillaMaintenance", "AdobeARMservice",
                                "jusched", "Google Update", "edgeupdate", "edgeupdatem", "brave" };
            var svcs = Query("SELECT * FROM Win32_Service").ToList();
            bool any = false;
            foreach (var s in svcs)
            {
                string name = s["Name"]?.ToString() ?? "";
                string disp = s["DisplayName"]?.ToString() ?? "";
                if (wanted.Any(w => name.Contains(w, StringComparison.OrdinalIgnoreCase) ||
                                    disp.Contains(w, StringComparison.OrdinalIgnoreCase)))
                {
                    Line($"  - {disp} [{name}]  State: {s["State"]}; StartMode: {s["StartMode"]}");
                    any = true;
                }
            }
            if (!any) Note("No common third-party updater services found.");
        }
        catch (Exception ex) { Note("Updater services error: " + ex.Message); }

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

        // ---------------- BROWSER EXTENSIONS ----------------
        Section("Browser extensions (all user profiles)");
        try
        {
            bool any = false;
            string usersRoot = @"C:\Users";
            if (Directory.Exists(usersRoot))
            {
                foreach (var userDir in Directory.GetDirectories(usersRoot))
                {
                    any |= EmitExtensions(Line, userDir, @"AppData\Local\Google\Chrome\User Data", "Chrome");
                    any |= EmitExtensions(Line, userDir, @"AppData\Local\Microsoft\Edge\User Data", "Edge");
                }
            }
            if (!any) Note("No browser extensions found (or profiles not readable).");
            Note("Extension IDs can be looked up in the Chrome/Edge web stores to identify each add-on.");
        }
        catch (Exception ex) { Note("Browser extensions error: " + ex.Message); }
        log("Browser extensions collected.");

        // ---------------- ROOT CERTIFICATE ANOMALIES ----------------
        Section("Machine root certificate review");
        try
        {
            using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            int total = store.Certificates.Count;
            var flagged = new List<string>();
            foreach (var c in store.Certificates)
            {
                if (!IsKnownCaIssuer(c.Issuer))
                    flagged.Add($"  - {ShortName(c.Subject)}  (thumbprint {c.Thumbprint})");
            }
            store.Close();
            KV("Root certificates in machine store", total);
            if (flagged.Count > 0)
            {
                Line("");
                Line("Roots not matching a common public CA (review these):");
                foreach (var f in flagged.Take(40)) Line(f);
                if (flagged.Count > 40) Line("  - ... (list truncated)");
            }
            else
            {
                Note("All machine roots matched common public CAs.");
            }
        }
        catch (Exception ex) { Note("Certificate review error: " + ex.Message); }
        log("Certificate review collected.");

        // ---------------- DISK VOLUMES ----------------
        Section("Disk volumes and free space");
        try
        {
            foreach (var d in Query("SELECT * FROM Win32_LogicalDisk WHERE DriveType=3 OR DriveType=2"))
            {
                long size = ToLong(d["Size"]);
                long free = ToLong(d["FreeSpace"]);
                string type = ToInt(d["DriveType"]) == 2 ? "Removable" : "Fixed";
                KV($"Drive {d["DeviceID"]}", $"{type}; Free {Gb(free)} of {Gb(size)}");
            }
        }
        catch (Exception ex) { Note("Disk volumes error: " + ex.Message); }

        // ---------------- NETWORK (LOCAL ONLY) ----------------
        Section("Network configuration (this host only)");
        try
        {
            foreach (var n in Query("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True"))
            {
                var ips = n["IPAddress"] as string[];
                var gws = n["DefaultIPGateway"] as string[];
                var dns = n["DNSServerSearchOrder"] as string[];
                string ip = ips?.FirstOrDefault(a => a != null && !a.Contains(':')) ?? (ips?.FirstOrDefault() ?? "");
                string gw = gws?.FirstOrDefault() ?? "";
                string dnsList = dns != null ? string.Join(", ", dns) : "";
                KV($"Interface {n["Description"]}", $"IPv4: {ip}; Gateway: {gw}; DNS: {dnsList}");
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
        Line("- No BitLocker recovery key values (presence only)");
        Line("- No email content or mailboxes");
        Line("- No browser history, bookmarks, or saved data (extension IDs only)");
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

    private static string LastLogon(string user)
    {
        try
        {
            string o = RunProc("net.exe", $"user \"{user}\"");
            foreach (var raw in o.Split('\n'))
            {
                var t = raw.Trim();
                if (t.StartsWith("Last logon", StringComparison.OrdinalIgnoreCase))
                    return t.Substring("Last logon".Length).Trim();
            }
        }
        catch { }
        return "Unknown";
    }

    private static string ProcName(string pid)
    {
        try
        {
            if (int.TryParse(pid, out int id))
                return Process.GetProcessById(id).ProcessName;
        }
        catch { }
        return "?";
    }

    private static void EmitArray(Action<string> line, string label, string[]? values)
    {
        if (values == null || values.Length == 0) return;
        foreach (var v in values) line($"  - {label}: {v}");
    }

    private static bool EmitExtensions(Action<string> line, string userDir, string relative, string browser)
    {
        try
        {
            string userData = Path.Combine(userDir, relative);
            if (!Directory.Exists(userData)) return false;
            bool any = false;
            foreach (var profile in Directory.GetDirectories(userData))
            {
                string extRoot = Path.Combine(profile, "Extensions");
                if (!Directory.Exists(extRoot)) continue;
                foreach (var ext in Directory.GetDirectories(extRoot))
                {
                    string id = Path.GetFileName(ext);
                    if (id.Equals("Temp", StringComparison.OrdinalIgnoreCase)) continue;
                    line($"  - {browser} [{Path.GetFileName(userDir)}/{Path.GetFileName(profile)}]  {id}");
                    any = true;
                }
            }
            return any;
        }
        catch { return false; }
    }

    private static bool IsKnownCaIssuer(string issuer)
    {
        string[] known =
        {
            "Microsoft", "DigiCert", "VeriSign", "Sectigo", "Comodo", "GlobalSign",
            "Entrust", "Baltimore", "USERTrust", "Go Daddy", "Starfield", "Amazon",
            "Google Trust", "Thawte", "GeoTrust", "Symantec", "ISRG", "Let's Encrypt",
            "DST Root", "Certum", "IdenTrust", "QuoVadis", "T-Systems", "SwissSign",
            "Actalis", "Buypass", "AffirmTrust", "SecureTrust", "Network Solutions",
            "COMODO", "AAA Certificate", "DTRUST", "D-TRUST", "SSL.com", "HARICA"
        };
        return known.Any(k => issuer.Contains(k, StringComparison.OrdinalIgnoreCase));
    }

    private static string ShortName(string dn)
    {
        var m = Regex.Match(dn, "CN=([^,]+)");
        return m.Success ? m.Groups[1].Value.Trim() : dn;
    }

    private static object? ReadReg(string path, string value)
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(path);
            return k?.GetValue(value);
        }
        catch { return null; }
    }

    private static object? ReadRegAny(string path, string value)
    {
        return ReadRegHive(Registry.CurrentUser, path, value)
            ?? ReadRegHive(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\" + path, value);
    }

    private static object? ReadRegHive(RegistryKey hive, string path, string value)
    {
        try
        {
            using var k = hive.OpenSubKey(path);
            return k?.GetValue(value);
        }
        catch { return null; }
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

    private static DateTime ParseDate(string? s) => DateTime.TryParse(s, out var d) ? d : DateTime.MinValue;

    private static bool ToBool(object? o)
    {
        if (o == null) return false;
        if (o is bool b) return b;
        return bool.TryParse(o.ToString(), out var r) && r;
    }

    private static int ToInt(object? o)
    {
        if (o == null) return 0;
        return int.TryParse(o.ToString(), out var r) ? r : 0;
    }

    private static long ToLong(object? o)
    {
        if (o == null) return 0;
        return long.TryParse(o.ToString(), out var r) ? r : 0;
    }

    private static string Gb(long bytes) => $"{bytes / 1024.0 / 1024.0 / 1024.0:N1} GB";

    private static string AuOptionText(object au) => ToInt(au) switch
    {
        2 => "notify before download",
        3 => "auto-download, notify to install",
        4 => "auto-download and schedule install",
        5 => "local admin chooses",
        _ => "other"
    };

    private static string SmbStartText(object start) => ToInt(start) switch
    {
        0 => "Boot",
        1 => "System",
        2 => "Automatic",
        3 => "Manual",
        4 => "Disabled",
        _ => start.ToString() ?? "?"
    };

    private static string Sanitize(string s) => Regex.Replace(s, "[^A-Za-z0-9_-]", "_");
}
