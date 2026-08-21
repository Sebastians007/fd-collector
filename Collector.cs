using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
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
///
/// HARD DENYLIST — this tool NEVER reads any of the following. This boundary
/// is enforced by simply never issuing a query for them, and is surfaced in
/// the report so a client can see it:
///   - Passwords or password hashes
///   - LSA secrets
///   - Cached domain credentials
///   - Browser passwords, cookies, autofill, or history
///   - Authentication or session tokens
///   - Private keys
///   - BitLocker recovery-key values (presence only)
///   - Credential Manager secret contents
/// Event logs are read for COUNTS and DATES only, never message bodies,
/// command lines, or file contents.
/// </summary>
public static class Collector
{
    private const string Version = "1.5.0";

    private const long Days30 = 2_592_000_000L;
    private const long Days90 = 7_776_000_000L;
    private const long Days365 = 31_536_000_000L;

    // Single source of truth for the denylist, shown in the report.
    private static readonly string[] NeverCollect =
    {
        "Passwords or password hashes",
        "LSA secrets",
        "Cached domain credentials",
        "Browser passwords, cookies, autofill, or history",
        "Authentication or session tokens",
        "Private keys",
        "BitLocker recovery-key values (presence only)",
        "Credential Manager secret contents",
        "Event-log message bodies, command lines, or file contents"
    };

    private static readonly Regex RecoveryKeyPattern =
        new(@"\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}", RegexOptions.Compiled);

    // Short label for each machine-checkable CIS v8 safeguard the tool assesses.
    private static readonly Dictionary<string, string> CisLabels = new()
    {
        ["2.2"] = "Supported software",
        ["3.6"] = "Encrypt end-user devices",
        ["4.1"] = "Secure configuration",
        ["4.3"] = "Automatic session lock",
        ["4.5"] = "Host firewall",
        ["4.6"] = "Securely manage assets",
        ["4.7"] = "Manage default accounts",
        ["5.1"] = "Account inventory",
        ["5.2"] = "Unique passwords",
        ["5.3"] = "Disable dormant accounts",
        ["5.4"] = "Restrict admin privileges",
        ["7.3"] = "Automated OS patching",
        ["8.1"] = "Audit log management",
        ["8.2"] = "Collect audit logs",
        ["8.3"] = "Adequate log storage",
        ["10.1"] = "Anti-malware deployed",
        ["10.3"] = "Disable autorun/autoplay",
        ["11.2"] = "Automated backups"
    };

    // Cross-framework pointers keyed by CIS v8 safeguard.
    // Order per row: NIST CSF 2.0, NIST IR 7621 (topic), HIPAA Security Rule, PCI DSS v4, SOC 2 TSC.
    // A tag points to a RELEVANT control; it is not a completed assessment of it.
    private static readonly Dictionary<string, string[]> FrameworkMap = new()
    {
        ["2.2"]  = new[] { "ID.AM-08", "Protect", "164.308(a)(5)(ii)(B)", "6.3.3", "CC7.1" },
        ["3.6"]  = new[] { "PR.DS-01", "Protect", "164.312(a)(2)(iv)", "3.5.1", "CC6.1" },
        ["4.1"]  = new[] { "PR.PS-01", "Protect", "164.308(a)(1)", "2.2", "CC6.1" },
        ["4.3"]  = new[] { "PR.AA-05", "Protect", "164.312(a)(2)(iii)", "8.2.8", "CC6.1" },
        ["4.5"]  = new[] { "PR.IR-01", "Protect", "164.312(c)(1)", "1.4.1", "CC6.6" },
        ["4.6"]  = new[] { "PR.PS-01", "Protect", "164.312(e)(1)", "2.2.7", "CC6.7" },
        ["4.7"]  = new[] { "PR.AA-01", "Protect", "164.308(a)(4)", "2.2.2", "CC6.1" },
        ["5.1"]  = new[] { "ID.AM-05", "Identify", "164.308(a)(4)", "8.2.1", "CC6.1" },
        ["5.2"]  = new[] { "PR.AA-01", "Protect", "164.308(a)(5)(ii)(D)", "8.3.6", "CC6.1" },
        ["5.3"]  = new[] { "PR.AA-01", "Protect", "164.308(a)(3)(ii)(C)", "8.2.6", "CC6.2" },
        ["5.4"]  = new[] { "PR.AA-05", "Protect", "164.308(a)(4)", "7.2.1", "CC6.3" },
        ["7.3"]  = new[] { "PR.PS-02", "Protect", "164.308(a)(5)(ii)(B)", "6.3.3", "CC7.1" },
        ["8.1"]  = new[] { "PR.PS-04", "Detect", "164.312(b)", "10.2.1", "CC7.2" },
        ["8.2"]  = new[] { "DE.CM-01", "Detect", "164.312(b)", "10.2.1", "CC7.2" },
        ["8.3"]  = new[] { "PR.PS-04", "Detect", "164.312(b)", "10.5.1", "CC7.2" },
        ["10.1"] = new[] { "DE.CM-01", "Detect", "164.308(a)(5)(ii)(B)", "5.2.1", "CC6.8" },
        ["10.3"] = new[] { "PR.PS-01", "Protect", "164.308(a)(5)(ii)(B)", "5.2.2", "CC6.8" },
        ["11.2"] = new[] { "RC.RP-01", "Recover", "164.308(a)(7)(ii)(A)", "N/A", "A1.2" }
    };

    private sealed class Finding
    {
        public string Cis = "", Item = "", Status = "", Detail = "";
    }

    private sealed class Prov
    {
        public string Name = "", Source = "", Status = "", Reason = "";
        public long Ms;
    }

    public static string Run(Action<string> log)
    {
        var body = new StringBuilder();
        var findings = new List<Finding>();
        var prov = new List<Prov>();
        var start = DateTime.Now;

        void Line(string s) => body.AppendLine(s);
        void KV(string k, object? v) => body.AppendLine($"- **{k}:** {v}");
        void Section(string t) { body.AppendLine(); body.AppendLine($"## {t}"); body.AppendLine(); }
        void Note(string s) => body.AppendLine($"> {s}");
        void Flag(string cis, string item, string status, string detail)
            => findings.Add(new Finding { Cis = cis, Item = item, Status = status, Detail = detail });

        bool isAdmin = IsAdmin();
        string host = Environment.MachineName;

        // Shared across modules — declared here so each module can read them.
        var adminMembers = new List<string>();
        string loggedInUser = "";
        bool isHomeEdition = false;
        var allApps = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // Module wrapper: times the work, records provenance, and turns an
        // access failure into "Failed: reason" instead of a silent blank.
        void Module(string name, string source, Action work, bool requiresAdmin = false)
        {
            if (requiresAdmin && !isAdmin)
            {
                prov.Add(new Prov { Name = name, Source = source, Status = "Skipped", Reason = "Not elevated" });
                return;
            }
            var sw = Stopwatch.StartNew();
            string status = "Success", reason = "";
            try { work(); }
            catch (Exception ex) { status = "Failed"; reason = ex.Message; }
            sw.Stop();
            prov.Add(new Prov { Name = name, Source = source, Status = status, Ms = sw.ElapsedMilliseconds, Reason = reason });
            log($"{name}: {status}");
        }

        // ==================== DENYLIST (shown first in detail) ====================
        Section("Data this tool never collects");
        foreach (var d in NeverCollect) Line($"- {d}");
        Note("These are never queried. Blanks elsewhere mean 'not detected' within a successful module, or 'not collected' where the provenance table marks a module Skipped or Failed.");

        // ==================== DEVICE ====================
        Section("Device");
        Module("Device", "CIM Win32_ComputerSystem/OperatingSystem/BIOS", () =>
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
                string caption = os["Caption"]?.ToString() ?? "";
                KV("OS", caption);
                KV("OS version", os["Version"]);
                KV("OS build", os["BuildNumber"]);
                KV("Architecture", os["OSArchitecture"]);
                KV("Installed on", ToDate(os["InstallDate"]));
                KV("Last boot", ToDate(os["LastBootUpTime"]));
                isHomeEdition = caption.Contains("Home", StringComparison.OrdinalIgnoreCase);
            }
            bool partOfDomain = cs != null && ToBool(cs["PartOfDomain"]);
            KV("Domain/Workgroup", partOfDomain ? $"Domain: {cs!["Domain"]}" : $"Workgroup: {cs?["Workgroup"]}");
            if (!string.IsNullOrEmpty(loggedInUser)) KV("Logged-in user", loggedInUser);
            if (isHomeEdition)
            {
                KV("Edition note", "Windows Home — cannot join a domain or apply Group Policy baselines.");
                Flag("4.1", "Windows edition", "Concern", "Home edition on a business machine; central configuration baselines cannot be applied.");
            }
        });

        // ==================== SYSTEM TIME ====================
        Section("System time");
        Module("System time", "OS clock", () =>
        {
            KV("Local time", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss zzz"));
            KV("UTC time", DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"));
            KV("Time zone", TimeZoneInfo.Local.DisplayName);
        });

        // ==================== PATCH POSTURE ====================
        Section("Patch posture");
        Module("Patch history", "CIM Win32_QuickFixEngineering", () =>
        {
            var fixes = Query("SELECT * FROM Win32_QuickFixEngineering").ToList();
            if (fixes.Count > 0)
            {
                var ordered = fixes.OrderByDescending(f => ParseDate(f["InstalledOn"]?.ToString())).ToList();
                var latest = ordered[0];
                KV("Most recent update (registry)", $"{latest["HotFixID"]} ({latest["InstalledOn"]})");
                KV("Total hotfixes listed", fixes.Count);
                Line("");
                Line("Recent updates:");
                foreach (var h in ordered.Take(8))
                    Line($"  - {h["HotFixID"]}  {h["InstalledOn"]}  {h["Description"]}");
            }
            else Note("No hotfix history returned (common on feature-updated Windows 11).");
        });

        Module("Last update install", "Event log System/19", () =>
        {
            var lastWu = NewestEventTime("System",
                "*[System[(EventID=19) and Provider[@Name='Microsoft-Windows-WindowsUpdateClient']]]");
            if (lastWu.HasValue)
            {
                KV("Last successful update install (event log)", lastWu.Value.ToString("yyyy-MM-dd HH:mm:ss"));
                int daysSince = (int)(DateTime.Now - lastWu.Value).TotalDays;
                if (daysSince > 35)
                    Flag("7.3", "OS patching", "Concern", $"Last update installed {daysSince} days ago; cadence exceeds one month.");
            }
            else Note("No update-install events found in the log window.");
        });

        Module("Pending reboot", "Registry", () =>
        {
            bool pending =
                RegKeyExists(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") ||
                RegKeyExists(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") ||
                (ReadReg(@"SYSTEM\CurrentControlSet\Control\Session Manager", "PendingFileRenameOperations") != null);
            KV("Pending reboot", pending);
            if (pending) Flag("7.3", "Pending reboot", "Concern", "Updates are staged but not active until restart.");
        });

        // ==================== WINDOWS UPDATE CONFIG ====================
        Section("Windows Update configuration");
        Module("Windows Update policy", "Registry", () =>
        {
            object? au = ReadReg(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "AUOptions");
            object? noAuto = ReadReg(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate");
            if (au != null) KV("AUOptions (policy)", $"{au} ({AuOptionText(au)})");
            else Note("No Windows Update policy set (default Windows behavior).");
            if (noAuto != null) KV("NoAutoUpdate (policy)", noAuto);
        });

        // ==================== DISK ENCRYPTION ====================
        Section("Disk encryption (BitLocker)");
        Module("BitLocker status", "manage-bde", () =>
        {
            string status = RunProc("manage-bde.exe", "-status");
            bool decrypted = status.Contains("Fully Decrypted", StringComparison.OrdinalIgnoreCase) ||
                             status.Contains("Protection Off", StringComparison.OrdinalIgnoreCase);
            foreach (var raw in status.Split('\n'))
            {
                var t = raw.Trim();
                if (t.StartsWith("Volume ", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("Conversion Status", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("Protection Status", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("Encryption Method", StringComparison.OrdinalIgnoreCase))
                    Line("  " + t);
            }
            if (decrypted) Flag("3.6", "Disk encryption", "Concern", "OS volume is not encrypted.");

            Line("");
            Line("Recovery protection (key value is never collected):");
            string protx = RunProc("manage-bde.exe", "-protectors -get C:");
            bool hasNumeric = false, hasTpm = false, hasPassword = false, hasExternal = false;
            foreach (var raw in protx.Split('\n'))
            {
                if (RecoveryKeyPattern.IsMatch(raw)) continue; // never emit key digits
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
            if (!decrypted && !hasNumeric)
                Flag("3.6", "Recovery key", "Concern", "Encrypted volume without a recovery-password protector; data-loss risk if TPM is reset.");
        }, requiresAdmin: true);

        // ==================== TPM & SECURE BOOT ====================
        Section("TPM and Secure Boot");
        Module("TPM", "CIM Win32_Tpm", () =>
        {
            var tpm = QueryFirst("SELECT * FROM Win32_Tpm", @"root\CIMV2\Security\MicrosoftTpm");
            if (tpm != null)
            {
                KV("TPM present", true);
                KV("TPM enabled", tpm["IsEnabled_InitialValue"]);
                KV("TPM activated", tpm["IsActivated_InitialValue"]);
                KV("TPM spec version", tpm["SpecVersion"]);
            }
            else KV("TPM present", false);
        });

        Module("Secure Boot", "Registry", () =>
        {
            object? sb2 = ReadReg(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled");
            if (sb2 != null) KV("Secure Boot enabled", ToInt(sb2) == 1);
            else KV("Secure Boot", "State key absent (likely legacy BIOS or disabled)");
        });

        // ==================== FIREWALL ====================
        Section("Windows Firewall");
        Module("Firewall profiles", "netsh advfirewall", () =>
        {
            string fw = RunProc("netsh.exe", "advfirewall show allprofiles state");
            string profile = "";
            bool any = false, allOn = true;
            foreach (var raw in fw.Split('\n'))
            {
                var t = raw.Trim();
                if (t.EndsWith("Profile Settings:", StringComparison.OrdinalIgnoreCase))
                    profile = t.Replace(" Profile Settings:", "", StringComparison.OrdinalIgnoreCase).Trim();
                else if (t.StartsWith("State", StringComparison.OrdinalIgnoreCase))
                {
                    var state = t.Length > 5 ? t.Substring(5).Trim() : "";
                    KV($"{profile} profile", $"State: {state}");
                    any = true;
                    if (!state.Equals("ON", StringComparison.OrdinalIgnoreCase)) allOn = false;
                }
            }
            if (!any) Note("Firewall profile state unavailable.");
            else if (allOn) Flag("4.5", "Host firewall", "OK", "All firewall profiles are on.");
            else Flag("4.5", "Host firewall", "Concern", "One or more firewall profiles are off.");
        });

        Module("Inbound allow rules", "netsh firewall rules", () =>
        {
            string rules = RunProc("netsh.exe", "advfirewall firewall show rule name=all dir=in");
            var blocks = rules.Split(new[] { "Rule Name:" }, StringSplitOptions.RemoveEmptyEntries);
            int shown = 0, allow = 0;
            Line("");
            Line("Enabled inbound ALLOW rules (first 30):");
            foreach (var b in blocks)
            {
                if (!Regex.IsMatch(b, @"Enabled:\s*Yes", RegexOptions.IgnoreCase)) continue;
                if (!Regex.IsMatch(b, @"Action:\s*Allow", RegexOptions.IgnoreCase)) continue;
                allow++;
                if (shown < 30)
                {
                    string name = b.Split('\n')[0].Trim();
                    var portM = Regex.Match(b, @"LocalPort:\s*(.+)", RegexOptions.IgnoreCase);
                    string port = portM.Success ? portM.Groups[1].Value.Trim() : "";
                    Line($"  - {name}  (LocalPort: {port})");
                    shown++;
                }
            }
            KV("Total enabled inbound allow rules", allow);
        });

        // ==================== RDP ====================
        Section("Remote Desktop (RDP)");
        Module("RDP", "Registry", () =>
        {
            object? deny = ReadReg(@"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections");
            bool rdpEnabled = deny != null && ToInt(deny) == 0;
            KV("RDP enabled", rdpEnabled);
            if (rdpEnabled)
            {
                object? nla = ReadReg(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication");
                bool nlaOn = nla != null && ToInt(nla) == 1;
                KV("Network Level Authentication required", nlaOn);
                if (!nlaOn) Flag("4.6", "RDP", "Concern", "RDP is enabled without Network Level Authentication.");
                else Flag("4.6", "RDP", "Info", "RDP is enabled with NLA required.");
            }
        });

        // ==================== DEFENDER / AV ====================
        Section("Antivirus / Microsoft Defender");
        Module("Defender status", "CIM MSFT_MpComputerStatus", () =>
        {
            var mp = QueryFirst("SELECT * FROM MSFT_MpComputerStatus", @"root\Microsoft\Windows\Defender");
            if (mp != null)
            {
                KV("Antivirus enabled", mp["AntivirusEnabled"]);
                KV("Real-time protection", mp["RealTimeProtectionEnabled"]);
                KV("Signature version", mp["AntivirusSignatureVersion"]);
                KV("Signature age (days)", mp["AntivirusSignatureAge"]);
                KV("Tamper protection", mp["IsTamperProtected"]);
                if (!ToBool(mp["RealTimeProtectionEnabled"]))
                    Flag("10.1", "Real-time protection", "Concern", "Defender real-time protection is off.");
            }
            else Note("Defender status unavailable (may be replaced by third-party antivirus).");
        });

        Module("Registered AV products", "CIM SecurityCenter2", () =>
        {
            var avs = Query("SELECT * FROM AntiVirusProduct", @"root\SecurityCenter2").ToList();
            if (avs.Count > 0)
            {
                Line("");
                Line("Registered antivirus products (Security Center):");
                foreach (var a in avs) Line($"  - {a["displayName"]}");
            }
        });

        Module("Defender exclusions", "CIM MSFT_MpPreference", () =>
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
        });

        Module("Defender history", "Event log Defender/Operational", () =>
        {
            const string dfd = "Microsoft-Windows-Windows Defender/Operational";
            int detections = CountEvents(dfd, $"*[System[(EventID=1116) and TimeCreated[timediff(@SystemTime)<={Days90}]]]");
            var lastDetect = NewestEventTime(dfd, "*[System[(EventID=1116)]]");
            int rtpOff = CountEvents(dfd, $"*[System[(EventID=5001) and TimeCreated[timediff(@SystemTime)<={Days90}]]]");
            Line("");
            KV("Defender detections (90 days)", CountText(detections));
            KV("Last detection", lastDetect.HasValue ? lastDetect.Value.ToString("yyyy-MM-dd") : "None in window");
            KV("Real-time-protection-disabled events (90 days)", CountText(rtpOff));
            if (rtpOff > 0) Flag("10.1", "Protection disabled", "Concern", $"Real-time protection was turned off {rtpOff} time(s) in 90 days.");
        });

        // ==================== LOCAL ACCOUNTS ====================
        Section("Local accounts");
        Module("Local users", "CIM Win32_UserAccount", () =>
        {
            var users = Query("SELECT * FROM Win32_UserAccount WHERE LocalAccount=True").ToList();
            if (users.Count > 0)
            {
                Line("Local users:");
                foreach (var u in users)
                {
                    string name = u["Name"]?.ToString() ?? "";
                    bool disabled = ToBool(u["Disabled"]);
                    bool pwdExpires = ToBool(u["PasswordExpires"]);
                    string lastLogon = LastLogon(name);
                    Line($"  - {name}  (Enabled: {!disabled}; PasswordRequired: {u["PasswordRequired"]}; PasswordExpires: {pwdExpires}; Last logon: {lastLogon})");
                    if (name.Equals("Administrator", StringComparison.OrdinalIgnoreCase) && !disabled)
                        Flag("4.7", "Default admin account", "Concern", "Built-in Administrator account is enabled and not renamed.");
                    if (name.Equals("Guest", StringComparison.OrdinalIgnoreCase) && !disabled)
                        Flag("4.7", "Guest account", "Concern", "Built-in Guest account is enabled.");
                    if (!disabled && !pwdExpires)
                        Flag("5.3", "Password expiry", "Info", $"Account '{name}' has a non-expiring password.");
                }
            }
        });

        Module("Administrators group", "net localgroup", () =>
        {
            string grp = RunProc("net.exe", "localgroup Administrators");
            var lines = grp.Split('\n').Select(x => x.TrimEnd('\r')).ToList();
            int dash = lines.FindIndex(x => x.StartsWith("----"));
            if (dash >= 0)
            {
                Line("");
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
            else Note("Could not enumerate the Administrators group.");
        });

        Module("Admin-user check", "Derived", () =>
        {
            if (string.IsNullOrEmpty(loggedInUser)) return;
            string shortName = loggedInUser.Contains('\\') ? loggedInUser.Split('\\').Last() : loggedInUser;
            bool inAdmins = adminMembers.Any(a =>
                a.EndsWith("\\" + shortName, StringComparison.OrdinalIgnoreCase) ||
                a.Equals(shortName, StringComparison.OrdinalIgnoreCase) ||
                a.Equals(loggedInUser, StringComparison.OrdinalIgnoreCase));
            Line("");
            KV("Logged-in user is a local administrator", inAdmins);
            if (inAdmins) Flag("5.4", "Admin privilege", "Concern", "The account in daily use has local administrator rights.");
        });

        // ==================== PASSWORD POLICY ====================
        Section("Password and lockout policy");
        Module("Password policy", "net accounts", () =>
        {
            string acc = RunProc("net.exe", "accounts");
            foreach (var raw in acc.Split('\n'))
            {
                var t = raw.TrimEnd('\r');
                if (t.Contains(':')) Line("  " + t.Trim());
            }
            var mlM = Regex.Match(acc, @"Minimum password length[^:]*:\s*(\d+)", RegexOptions.IgnoreCase);
            if (mlM.Success && int.TryParse(mlM.Groups[1].Value, out int ml) && ml < 14)
                Flag("5.2", "Password length", "Concern", $"Minimum password length is {ml}; IG1 expects at least 14 (non-MFA).");
        });

        // ==================== LOCAL SECURITY SETTINGS ====================
        Section("Local security settings");
        Module("Local security settings", "Registry LSA/Policies", () =>
        {
            KV("LM compatibility level", ReadReg(@"SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel") ?? "Not set (default)");
            KV("RestrictAnonymous", ReadReg(@"SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymous") ?? "Not set");
            KV("RestrictAnonymousSAM", ReadReg(@"SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymousSAM") ?? "Not set");
            object? uac = ReadReg(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA");
            KV("UAC enabled (EnableLUA)", uac == null ? "Not set" : (ToInt(uac) == 1).ToString());
            KV("UAC admin prompt level", ReadReg(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin") ?? "Not set");
            object? autorun = ReadReg(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun");
            KV("Autorun policy (NoDriveTypeAutoRun)", autorun ?? "Not set");
            if (autorun == null || ToInt(autorun) == 0)
                Flag("10.3", "Autorun/Autoplay", "Concern", "Autorun is not disabled by policy.");
        });

        // ==================== SMBv1 ====================
        Section("SMBv1 protocol");
        Module("SMBv1", "Registry", () =>
        {
            object? clientStart = ReadReg(@"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start");
            object? srv = ReadReg(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1");
            KV("SMBv1 client", clientStart == null ? "Not present (feature removed)" : SmbStartText(clientStart));
            KV("SMBv1 server enabled", srv == null ? "Default (check OS feature state)" : (ToInt(srv) == 1).ToString());
            if ((clientStart != null && ToInt(clientStart) != 4) || (srv != null && ToInt(srv) == 1))
                Flag("4.1", "SMBv1", "Concern", "Legacy SMBv1 appears enabled; it should be disabled.");
        });

        // ==================== SCREEN LOCK ====================
        Section("Screen lock");
        Module("Screen lock", "Registry policy", () =>
        {
            object? inactivity = ReadReg(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "InactivityTimeoutSecs");
            KV("Machine inactivity lock (sec)", inactivity ?? "Not set");
            KV("Screensaver timeout (sec)", ReadRegAny(@"Control Panel\Desktop", "ScreenSaveTimeOut") ?? "Not set");
            KV("Password on resume", ReadRegAny(@"Control Panel\Desktop", "ScreenSaverIsSecure") ?? "Not set");
            if (!(inactivity != null && ToInt(inactivity) > 0))
                Flag("4.3", "Session lock", "Concern", "No enforced inactivity screen lock policy on this machine.");
            Note("Per-user screensaver values reflect the elevated context; the machine inactivity policy above is authoritative.");
        });

        // ==================== AUDIT POLICY & LOGS ====================
        Section("Audit policy and event logs");
        Module("Audit policy", "auditpol", () =>
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
        }, requiresAdmin: true);

        Module("Event log limits", "wevtutil", () =>
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
        }, requiresAdmin: true);

        Module("Security history", "Event log Security (counts/dates)", () =>
        {
            Line("");
            Line("History (counts and dates only, no event contents):");
            var oldest = OldestEventTime("Security");
            if (oldest.HasValue)
            {
                int daysBack = (int)(DateTime.Now - oldest.Value).TotalDays;
                KV("Oldest Security-log event", $"{oldest.Value:yyyy-MM-dd} ({daysBack} days of history)");
                if (daysBack < 30)
                    Flag("8.3", "Log retention", "Concern", $"Security log holds only {daysBack} days; investigations beyond that are impossible.");
            }
            KV("Failed logons (30 days)", CountText(CountEvents("Security", $"*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime)<={Days30}]]]")));
            KV("Remote (RDP) logons type 10 (30 days)", CountText(CountEvents("Security",
                $"*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime)<={Days30}]]] and *[EventData[Data[@Name='LogonType']='10']]")));
            KV("Account lockouts (90 days)", CountText(CountEvents("Security", $"*[System[(EventID=4740) and TimeCreated[timediff(@SystemTime)<={Days90}]]]")));
            KV("Accounts created (90 days)", CountText(CountEvents("Security", $"*[System[(EventID=4720) and TimeCreated[timediff(@SystemTime)<={Days90}]]]")));
            KV("Accounts enabled (90 days)", CountText(CountEvents("Security", $"*[System[(EventID=4722) and TimeCreated[timediff(@SystemTime)<={Days90}]]]")));
            KV("Accounts deleted (90 days)", CountText(CountEvents("Security", $"*[System[(EventID=4726) and TimeCreated[timediff(@SystemTime)<={Days90}]]]")));
            KV("Security-group member adds (90 days)", CountText(CountEvents("Security", $"*[System[(EventID=4732) and TimeCreated[timediff(@SystemTime)<={Days90}]]]")));
            int cleared = CountEvents("Security", $"*[System[(EventID=1102) and TimeCreated[timediff(@SystemTime)<={Days365}]]]");
            KV("Audit-log-cleared events (365 days)", CountText(cleared));
            if (cleared > 0) Flag("8.1", "Log integrity", "Concern", $"Security log was cleared {cleared} time(s) in the last year.");
        }, requiresAdmin: true);

        Module("Reliability history", "Event log System (counts)", () =>
        {
            Line("");
            Line("System reliability (counts only):");
            KV("Unexpected shutdowns (90 days)", CountText(CountEvents("System", $"*[System[(EventID=6008) and TimeCreated[timediff(@SystemTime)<={Days90}]]]")));
            KV("Kernel-power unexpected (90 days)", CountText(CountEvents("System", $"*[System[(EventID=41) and TimeCreated[timediff(@SystemTime)<={Days90}]]]")));
            KV("Service install events (90 days)", CountText(CountEvents("System", $"*[System[(EventID=7045) and TimeCreated[timediff(@SystemTime)<={Days90}]]]")));
        });

        // ==================== LISTENING PORTS ====================
        Section("Listening ports");
        Module("Listening ports", "netstat -ano", () =>
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
                    string entry = $"  - {parts[0]}  {parts[1]}  PID {parts[4]}  ({ProcName(parts[4])})";
                    if (!seen.Contains(entry)) { seen.Add(entry); Line(entry); }
                }
            }
            if (seen.Count == 0) Note("No listening ports parsed.");
        });

        // ==================== SHARES ====================
        Section("Shared folders");
        Module("Shares", "CIM Win32_Share", () =>
        {
            var shares = Query("SELECT * FROM Win32_Share").ToList();
            if (shares.Count > 0)
                foreach (var s in shares) Line($"  - {s["Name"]}  ->  {s["Path"]}  ({s["Description"]})");
            else Note("No shares enumerated.");
        });

        // ==================== PRINTERS ====================
        Section("Printers and spooler");
        Module("Printers", "CIM Win32_Printer/Service", () =>
        {
            var spooler = QueryFirst("SELECT * FROM Win32_Service WHERE Name='Spooler'");
            if (spooler != null) KV("Print Spooler service", $"State: {spooler["State"]}; StartMode: {spooler["StartMode"]}");
            foreach (var p in Query("SELECT * FROM Win32_Printer"))
                Line($"  - {p["Name"]}  (Shared: {p["Shared"]}; Network: {p["Network"]})");
        });

        // ==================== MAPPED DRIVES ====================
        Section("Mapped drives");
        Module("Mapped drives", "net use", () =>
        {
            string nu = RunProc("net.exe", "use");
            foreach (var raw in nu.Split('\n'))
            {
                var t = raw.TrimEnd('\r');
                if (t.Contains(":\\") || t.Contains("\\\\")) Line("  " + t.Trim());
            }
            Note("Mapped drives are per-user; this reflects the elevated context.");
        });

        // ==================== STARTUP PROGRAMS ====================
        Section("Startup programs and autoruns");
        Module("Startup programs", "Registry Run keys + Startup folder", () =>
        {
            EmitRun(Line, Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run");
            EmitRun(Line, Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce");
            EmitRun(Line, Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU Run");
            string commonStartup = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
            if (Directory.Exists(commonStartup))
                foreach (var f in Directory.GetFiles(commonStartup))
                    Line($"  - Startup folder: {Path.GetFileName(f)}");
        });

        // ==================== SCHEDULED TASKS ====================
        Section("Scheduled tasks (non-Microsoft)");
        Module("Scheduled tasks", "schtasks", () =>
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
                if (++shown >= 60) { Line("  - ... (truncated)"); break; }
            }
            if (shown == 0) Note("No non-Microsoft scheduled tasks found.");
        });

        // ==================== UPDATER SERVICES ====================
        Section("Third-party updater services");
        Module("Updater services", "CIM Win32_Service", () =>
        {
            string[] wanted = { "gupdate", "gupdatem", "MozillaMaintenance", "AdobeARMservice",
                                "jusched", "Google Update", "edgeupdate", "edgeupdatem", "brave" };
            bool any = false;
            foreach (var s in Query("SELECT * FROM Win32_Service"))
            {
                string name = s["Name"]?.ToString() ?? "";
                string disp = s["DisplayName"]?.ToString() ?? "";
                if (wanted.Any(w => name.Contains(w, StringComparison.OrdinalIgnoreCase) || disp.Contains(w, StringComparison.OrdinalIgnoreCase)))
                { Line($"  - {disp} [{name}]  State: {s["State"]}; StartMode: {s["StartMode"]}"); any = true; }
            }
            if (!any) Note("No common third-party updater services found.");
        });

        // ==================== SOFTWARE ====================
        Section("Software of interest");
        Module("Installed software scan", "Registry Uninstall", () =>
        {
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
                    var name = k?.GetValue("DisplayName") as string;
                    if (string.IsNullOrWhiteSpace(name) || allApps.ContainsKey(name)) continue;
                    var ver = k?.GetValue("DisplayVersion") as string ?? "";
                    var pub = k?.GetValue("Publisher") as string ?? "";
                    allApps[name] = $"  - {name}  {ver}  [{pub}]";
                }
            }
            string[] remote = { "TeamViewer", "AnyDesk", "RemotePC", "LogMeIn", "GoTo", "VNC", "Chrome Remote", "Splashtop", "ScreenConnect" };
            string[] eol = { "Java 8", "Java 7", "Python 2", ".NET Framework 3", "Adobe Flash", "Internet Explorer" };
            bool flagged = false;
            foreach (var name in allApps.Keys)
            {
                if (remote.Any(rr => name.Contains(rr, StringComparison.OrdinalIgnoreCase)))
                { Line($"  - REMOTE ACCESS: {name}"); flagged = true; Flag("4.6", "Remote-access software", "Concern", $"{name} present; provides standing remote access."); }
                else if (eol.Any(e => name.Contains(e, StringComparison.OrdinalIgnoreCase)))
                { Line($"  - END-OF-LIFE: {name}"); flagged = true; Flag("2.2", "Unsupported software", "Concern", $"{name} may be past vendor support."); }
            }
            if (!flagged) Note("No remote-access or obviously end-of-life software matched the shortlist.");
        });

        Section("Installed software (full inventory)");
        Module("Full inventory render", "Derived", () =>
        {
            if (allApps.Count > 0)
            {
                KV("Applications found", allApps.Count);
                Line("");
                foreach (var v in allApps.Values) Line(v);
            }
            else Note("No installed applications enumerated.");
        });

        // ==================== BROWSER EXTENSIONS ====================
        Section("Browser extensions (all user profiles)");
        Module("Browser extensions", "Filesystem", () =>
        {
            bool any = false;
            const string usersRoot = @"C:\Users";
            if (Directory.Exists(usersRoot))
                foreach (var userDir in Directory.GetDirectories(usersRoot))
                {
                    any |= EmitExtensions(Line, userDir, @"AppData\Local\Google\Chrome\User Data", "Chrome");
                    any |= EmitExtensions(Line, userDir, @"AppData\Local\Microsoft\Edge\User Data", "Edge");
                }
            if (!any) Note("No browser extensions found (or profiles not readable).");
            Note("Extension IDs can be looked up in the Chrome/Edge web stores.");
        });

        // ==================== ROOT CERT REVIEW ====================
        Section("Machine root certificate review");
        Module("Root certificates", "X509 machine Root store", () =>
        {
            using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            int total = store.Certificates.Count;
            var flagged = new List<string>();
            foreach (var c in store.Certificates)
                if (!IsKnownCaIssuer(c.Issuer))
                    flagged.Add($"  - {ShortName(c.Subject)}  (thumbprint {c.Thumbprint})");
            store.Close();
            KV("Root certificates in machine store", total);
            if (flagged.Count > 0)
            {
                Line("");
                Line("Roots not matching a common public CA (review):");
                foreach (var f in flagged.Take(40)) Line(f);
            }
            else Note("All machine roots matched common public CAs.");
        });

        // ==================== DISK VOLUMES ====================
        Section("Disk volumes and free space");
        Module("Disk volumes", "CIM Win32_LogicalDisk", () =>
        {
            foreach (var d in Query("SELECT * FROM Win32_LogicalDisk WHERE DriveType=3 OR DriveType=2"))
            {
                long size = ToLong(d["Size"]); long free = ToLong(d["FreeSpace"]);
                string type = ToInt(d["DriveType"]) == 2 ? "Removable" : "Fixed";
                KV($"Drive {d["DeviceID"]}", $"{type}; Free {Gb(free)} of {Gb(size)}");
            }
        });

        // ==================== NETWORK ====================
        Section("Network configuration (this host only)");
        Module("Network", "CIM Win32_NetworkAdapterConfiguration", () =>
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
            Note("Only this host's own adapter configuration is read. No other hosts are contacted or scanned.");
        });

        // ==================== BATCH 1B: SERVICES ====================
        Section("Services (non-Microsoft and risky configurations)");
        Module("Services", "CIM Win32_Service", () =>
        {
            var svcs = Query("SELECT * FROM Win32_Service").ToList();
            KV("Total services", svcs.Count);
            int localSystem = 0, nonMs = 0, unquoted = 0, outside = 0;
            var risky = new List<string>();
            var thirdParty = new List<string>();

            foreach (var s in svcs)
            {
                string name = s["Name"]?.ToString() ?? "";
                string disp = s["DisplayName"]?.ToString() ?? "";
                string state = s["State"]?.ToString() ?? "";
                string startMode = s["StartMode"]?.ToString() ?? "";
                string account = s["StartName"]?.ToString() ?? "";
                string pathName = s["PathName"]?.ToString() ?? "";

                bool isSystemAcct = account.Equals("LocalSystem", StringComparison.OrdinalIgnoreCase);
                if (isSystemAcct) localSystem++;

                string exe = ExtractExePath(pathName);
                bool msLoc = IsStandardExeLocation(exe);
                if (!msLoc && exe.Length > 0)
                {
                    outside++;
                    nonMs++;
                    thirdParty.Add($"  - {disp} [{name}]  State: {state}; Start: {startMode}; Account: {account}");
                    thirdParty.Add($"      Path: {exe}");
                }

                bool unq = HasUnquotedServicePath(pathName);
                if (unq)
                {
                    unquoted++;
                    risky.Add($"  - UNQUOTED PATH: {disp} [{name}]  ->  {pathName}");
                    Flag("4.6", "Unquoted service path", "Concern", $"Service '{name}' has an unquoted path with spaces; a privilege-escalation risk.");
                }
                if (!msLoc && exe.Length > 0 && isSystemAcct && startMode.Equals("Auto", StringComparison.OrdinalIgnoreCase))
                    risky.Add($"  - AUTO + LocalSystem + non-standard path: {disp} [{name}]  ->  {exe}");
            }

            KV("Services running as LocalSystem", localSystem);
            KV("Services with executables outside standard locations", outside);
            KV("Unquoted service paths", unquoted);

            if (risky.Count > 0)
            {
                Line("");
                Line("Risky service configurations:");
                foreach (var r in risky.Take(60)) Line(r);
            }
            if (thirdParty.Count > 0)
            {
                Line("");
                Line("Non-standard-location services (first 40):");
                foreach (var t in thirdParty.Take(80)) Line(t);
            }
            Note("Not every LocalSystem service is a problem; Windows runs many core services that way. The flagged items are the combinations worth a look.");
        });

        // ==================== BATCH 1C: DEFENDER ADVANCED + SECURITY FEATURES ====================
        Section("Defender advanced settings");
        Module("Defender advanced", "CIM MSFT_MpPreference/MpComputerStatus", () =>
        {
            var pref = QueryFirst("SELECT * FROM MSFT_MpPreference", @"root\Microsoft\Windows\Defender");
            var stat = QueryFirst("SELECT * FROM MSFT_MpComputerStatus", @"root\Microsoft\Windows\Defender");
            if (stat != null)
            {
                KV("Cloud-delivered protection (MAPS)", MapsText(pref?["MAPSReporting"]));
                KV("Automatic sample submission", SampleText(pref?["SubmitSamplesConsent"]));
                KV("PUA protection", PuaText(pref?["PUAProtection"]));
                KV("Antimalware engine version", stat["AMEngineVersion"]);
                KV("Antimalware platform version", stat["AMServiceVersion"]);
            }
            if (pref != null)
            {
                KV("Network protection", NpText(pref["EnableNetworkProtection"]));
                KV("Controlled Folder Access", CfaText(pref["EnableControlledFolderAccess"]));
                if (ToInt(pref["EnableNetworkProtection"]) == 0)
                    Flag("10.1", "Network protection", "Info", "Defender network protection is off.");
                if (ToInt(pref["EnableControlledFolderAccess"]) == 0)
                    Flag("10.1", "Controlled Folder Access", "Info", "Controlled Folder Access (ransomware guard) is off.");
            }
            else Note("Defender preference class unavailable.");
        });

        Section("Attack Surface Reduction (ASR) rules");
        Module("ASR rules", "CIM MSFT_MpPreference", () =>
        {
            var pref = QueryFirst("SELECT * FROM MSFT_MpPreference", @"root\Microsoft\Windows\Defender");
            var ids = ToStringArray(pref?["AttackSurfaceReductionRules_Ids"]);
            var acts = ToStringArray(pref?["AttackSurfaceReductionRules_Actions"]);
            if (ids.Length == 0)
            {
                Note("No ASR rules are configured.");
                Flag("10.1", "ASR rules", "Info", "No Attack Surface Reduction rules are configured.");
                return;
            }
            for (int i = 0; i < ids.Length; i++)
            {
                string id = ids[i];
                string act = (acts != null && i < acts.Length) ? AsrActionText(acts[i]) : "Unknown";
                Line($"  - {AsrRuleName(id)}  [{id}]  =>  {act}");
            }
        });

        Section("Windows security features");
        Module("Device Guard (VBS/HVCI/Credential Guard)", "CIM Win32_DeviceGuard", () =>
        {
            var dg = QueryFirst("SELECT * FROM Win32_DeviceGuard", @"root\Microsoft\Windows\DeviceGuard");
            if (dg != null)
            {
                var running = ToIntArray(dg["SecurityServicesRunning"]);
                var configured = ToIntArray(dg["SecurityServicesConfigured"]);
                int vbs = ToInt(dg["VirtualizationBasedSecurityStatus"]);
                KV("VBS status", VbsText(vbs));
                bool credGuard = running.Contains(1);
                bool hvci = running.Contains(2);
                KV("Credential Guard running", credGuard);
                KV("HVCI / Memory Integrity running", hvci);
                KV("Configured services", string.Join(", ", configured.Select(SecSvcText)));
                if (!credGuard) Flag("5.4", "Credential Guard", "Info", "Credential Guard is not running.");
                if (!hvci) Flag("4.1", "Memory Integrity (HVCI)", "Info", "HVCI / Memory Integrity is not running.");
            }
            else Note("Device Guard WMI class unavailable on this edition.");
        });

        Module("LSA protection", "Registry", () =>
        {
            object? runAsPPL = ReadReg(@"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL");
            KV("LSA protection (RunAsPPL)", runAsPPL == null ? "Not set" : (ToInt(runAsPPL) >= 1).ToString());
            if (runAsPPL == null || ToInt(runAsPPL) == 0)
                Flag("5.4", "LSA protection", "Info", "LSA protection (RunAsPPL) is not enabled.");
        });

        // ==================== BATCH 1D: FIRMWARE + POWERSHELL + WINRM ====================
        Section("Firmware / BIOS");
        Module("Firmware", "CIM Win32_BIOS + registry", () =>
        {
            var bios = QueryFirst("SELECT * FROM Win32_BIOS");
            if (bios != null)
            {
                KV("BIOS vendor", bios["Manufacturer"]);
                KV("BIOS version", bios["SMBIOSBIOSVersion"]);
                KV("BIOS release date", ToDate(bios["ReleaseDate"]));
            }
            object? mode = ReadReg(@"SYSTEM\CurrentControlSet\Control", "PEFirmwareType");
            KV("Firmware type", mode == null ? "Unknown" : (ToInt(mode) == 2 ? "UEFI" : ToInt(mode) == 1 ? "Legacy BIOS" : "Unknown"));
        });

        Section("PowerShell security");
        Module("PowerShell", "Registry + version", () =>
        {
            object? psv = ReadRegHive(Registry.LocalMachine, @"SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine", "PowerShellVersion");
            KV("Windows PowerShell version", psv ?? "Unknown");
            KV("PowerShell 7 present", RegKeyExists(@"SOFTWARE\Microsoft\PowerShellCore\InstalledVersions"));
            object? sbl = ReadReg(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging");
            object? ml = ReadReg(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging", "EnableModuleLogging");
            object? tr = ReadReg(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription", "EnableTranscripting");
            KV("Script Block Logging", sbl == null ? "Not set" : (ToInt(sbl) == 1).ToString());
            KV("Module Logging", ml == null ? "Not set" : (ToInt(ml) == 1).ToString());
            KV("Transcription", tr == null ? "Not set" : (ToInt(tr) == 1).ToString());
            if (sbl == null || ToInt(sbl) == 0)
                Flag("8.2", "PowerShell logging", "Info", "PowerShell Script Block Logging is not enabled.");
        });

        Section("WinRM / PowerShell remoting");
        Module("WinRM", "CIM Win32_Service + netsh", () =>
        {
            var winrm = QueryFirst("SELECT * FROM Win32_Service WHERE Name='WinRM'");
            if (winrm != null)
                KV("WinRM service", $"State: {winrm["State"]}; StartMode: {winrm["StartMode"]}");
            else KV("WinRM service", "Not found");
            string listeners = RunProc("netsh.exe", "http show servicestate view=session");
            bool has5985 = listeners.Contains(":5985", StringComparison.OrdinalIgnoreCase);
            bool has5986 = listeners.Contains(":5986", StringComparison.OrdinalIgnoreCase);
            KV("WinRM HTTP listener (5985) seen", has5985);
            KV("WinRM HTTPS listener (5986) seen", has5986);
        });

        // ==================== BATCH 1E: SOFTWARE CLASSIFICATION + MANAGEMENT ====================
        Section("Software classification");
        Module("Software classification", "Derived from inventory", () =>
        {
            if (allApps.Count == 0) { Note("No inventory available to classify."); return; }
            var cats = new (string Label, string[] Keys)[]
            {
                ("Remote access", new[] { "TeamViewer", "AnyDesk", "RemotePC", "LogMeIn", "GoTo", "VNC", "Chrome Remote", "Splashtop", "ScreenConnect", "DWService" }),
                ("RMM", new[] { "NinjaRMM", "Datto", "ConnectWise", "Atera", "Kaseya", "N-able", "Syncro", "Action1" }),
                ("VPN", new[] { "OpenVPN", "WireGuard", "NordVPN", "ExpressVPN", "Cisco AnyConnect", "FortiClient", "GlobalProtect", "Pulse Secure" }),
                ("File sync", new[] { "Dropbox", "Google Drive", "OneDrive", "Box", "Nextcloud", "Sync.com", "pCloud" }),
                ("Password manager", new[] { "LastPass", "1Password", "Bitwarden", "KeePass", "Dashlane", "Keeper" }),
                ("Packet capture", new[] { "Wireshark", "Npcap", "WinPcap", "Fiddler", "tcpdump" }),
                ("Network scanner", new[] { "Nmap", "Angry IP", "Advanced IP Scanner", "SoftPerfect" }),
                ("Admin tool", new[] { "PsExec", "Sysinternals", "PuTTY", "WinSCP", "Bitvise", "Process Hacker" }),
                ("End-of-life", new[] { "Java 8", "Java 7", "Python 2", ".NET Framework 3", "Adobe Flash", "Internet Explorer" })
            };
            foreach (var (label, keys) in cats)
            {
                var hits = allApps.Keys.Where(n => keys.Any(k => n.Contains(k, StringComparison.OrdinalIgnoreCase))).ToList();
                if (hits.Count == 0) continue;
                Line($"**{label}:**");
                foreach (var h in hits) Line($"  - {h}");
            }
        });

        Section("Endpoint management detection");
        Module("Endpoint management", "Registry + services + dsregcmd", () =>
        {
            bool intune = RegKeyExists(@"SOFTWARE\Microsoft\Enrollments") &&
                          RunProc("dsregcmd.exe", "/status").Contains("MDMUrl", StringComparison.OrdinalIgnoreCase);
            bool sccm = QueryFirst("SELECT * FROM Win32_Service WHERE Name='CcmExec'") != null;
            bool intuneAgent = QueryFirst("SELECT * FROM Win32_Service WHERE Name='IntuneManagementExtension'") != null;
            string[] rmmSvc = { "NinjaRMMAgent", "AteraAgent", "CagService", "Kaseya", "Syncro", "screenconnect", "ltservice", "amp_mgr" };
            bool rmm = false;
            foreach (var s in Query("SELECT * FROM Win32_Service"))
            {
                string nm = s["Name"]?.ToString() ?? "";
                if (rmmSvc.Any(r => nm.Contains(r, StringComparison.OrdinalIgnoreCase))) { rmm = true; break; }
            }
            string dsreg = RunProc("dsregcmd.exe", "/status");
            bool aadJoined = dsreg.Contains("AzureAdJoined : YES", StringComparison.OrdinalIgnoreCase);
            bool domainJoined = dsreg.Contains("DomainJoined : YES", StringComparison.OrdinalIgnoreCase);

            KV("Intune / MDM enrolled", intune || intuneAgent);
            KV("SCCM / MECM client", sccm);
            KV("RMM agent detected", rmm);
            KV("Entra (Azure AD) joined", aadJoined);
            KV("Domain joined", domainJoined);
            bool managed = intune || intuneAgent || sccm || rmm || domainJoined || aadJoined;
            KV("Overall management", managed ? "Detected" : "None detected");
            Note("Presence is evidence of management, not proof the agent is healthy or checking in.");
            if (!managed)
                Flag("5.1", "Endpoint management", "Concern", "No management plane detected; the machine is unmanaged.");
        });

        // ==================== TIER 2: POLICY + RECOVERY + NETWORK DETAIL ====================
        Section("Backup and recovery posture");
        Module("Recovery posture", "reg + vssadmin + services", () =>
        {
            string sr = RunProc("reg.exe", @"query ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"" /v RPSessionInterval");
            KV("System Restore configured", sr.Contains("RPSessionInterval", StringComparison.OrdinalIgnoreCase));
            string wre = RunProc("reagentc.exe", "/info");
            bool wreEnabled = wre.Contains("Enabled", StringComparison.OrdinalIgnoreCase);
            KV("Windows Recovery Environment (WinRE)", wreEnabled ? "Enabled" : "Disabled/unknown");
            string[] backupSvc = { "Veeam", "Acronis", "Carbonite", "Datto", "Backblaze", "CrashPlan", "Cove", "MacriumService", "wbengine" };
            var found = new List<string>();
            foreach (var s in Query("SELECT * FROM Win32_Service"))
            {
                string nm = s["Name"]?.ToString() ?? "";
                string dp = s["DisplayName"]?.ToString() ?? "";
                if (backupSvc.Any(b => nm.Contains(b, StringComparison.OrdinalIgnoreCase) || dp.Contains(b, StringComparison.OrdinalIgnoreCase)))
                    found.Add($"  - {dp} [{nm}]  State: {s["State"]}");
            }
            if (found.Count > 0) { Line("Backup agents detected:"); foreach (var f in found) Line(f); }
            else { Note("No third-party backup agent detected."); Flag("11.2", "Backup agent", "Concern", "No backup software detected on this machine."); }
        }, requiresAdmin: true);

        Section("SMB and NTLM configuration");
        Module("SMB/NTLM", "Registry", () =>
        {
            object? reqSign = ReadReg(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature");
            KV("SMB server signing required", reqSign == null ? "Not set" : (ToInt(reqSign) == 1).ToString());
            object? cliSign = ReadReg(@"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "RequireSecuritySignature");
            KV("SMB client signing required", cliSign == null ? "Not set" : (ToInt(cliSign) == 1).ToString());
            object? ntlm = ReadReg(@"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "NtlmMinClientSec");
            KV("NTLM min client security", ntlm ?? "Not set");
        });

        Section("Proxy configuration");
        Module("Proxy", "Registry", () =>
        {
            object? enable = ReadRegHive(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyEnable");
            object? server = ReadRegHive(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyServer");
            KV("Proxy enabled (current user)", enable == null ? "Not set" : (ToInt(enable) == 1).ToString());
            KV("Proxy server", server ?? "None");
        });

        Section("Credential Manager (presence only)");
        Module("Credential Manager", "cmdkey list (counts only)", () =>
        {
            // COUNT ONLY. Never the secret contents. This module deliberately
            // parses only the number of stored targets, not their values.
            string ck = RunProc("cmdkey.exe", "/list");
            int stored = Regex.Matches(ck, @"Target:", RegexOptions.IgnoreCase).Count;
            KV("Stored credential entries (count only)", stored);
            Note("Only the number of stored entries is read. Their secret contents are never collected.");
        });

        Section("Effective policy summary");
        Module("Effective policy (gpresult)", "gpresult", () =>
        {
            string gp = RunProc("gpresult.exe", "/r /scope:computer");
            bool any = false;
            foreach (var raw in gp.Split('\n'))
            {
                var t = raw.Trim();
                if (t.StartsWith("Applied Group Policy Objects", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("The computer is a part of", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("Domain Name", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("Domain Type", StringComparison.OrdinalIgnoreCase))
                { Line("  " + t); any = true; }
            }
            if (gp.Contains("N/A", StringComparison.OrdinalIgnoreCase) || !any)
                Note("No applied domain Group Policy objects (standalone/workgroup machine).");
        }, requiresAdmin: true);

        // ==================== COLLECTION PROVENANCE ====================
        Section("Collection provenance");
        Line("| Module | Source | Status | ms | Reason |");
        Line("|--------|--------|--------|----|--------|");
        foreach (var p in prov)
            Line($"| {p.Name} | {p.Source} | {p.Status} | {p.Ms} | {p.Reason} |");
        Line("");
        Note("Success = ran and read data. Skipped = needs admin and the tool was not elevated. Failed = the module errored; the reason is recorded. A blank field inside a Success module means 'not detected'; a Skipped or Failed module means 'not collected'.");

        // ==================== FOOTER ====================
        var elapsed = DateTime.Now - start;
        Section("Collection summary");
        KV("Elapsed", $"{elapsed.TotalSeconds:N1} seconds");
        KV("Elevated", isAdmin);
        int okCount = prov.Count(p => p.Status == "Success");
        int failCount = prov.Count(p => p.Status == "Failed");
        int skipCount = prov.Count(p => p.Status == "Skipped");
        KV("Modules", $"{prov.Count} total — {okCount} success, {skipCount} skipped, {failCount} failed");
        Line("");
        Line("_Report generated by FieldDesk Collector v" + Version + ". Read-only. Open source (MIT)._");

        // ==================== ASSEMBLE FINAL (summary first) ====================
        var final = new StringBuilder();
        final.AppendLine("# FieldDesk Collection Report");
        final.AppendLine();
        final.AppendLine($"- **Hostname:** {host}");
        final.AppendLine($"- **Collected (local):** {start:yyyy-MM-dd HH:mm:ss zzz}");
        final.AppendLine($"- **Collected (UTC):** {start.ToUniversalTime():yyyy-MM-dd HH:mm:ss}");
        final.AppendLine($"- **Collector version:** {Version}");
        final.AppendLine($"- **Run as:** {Environment.UserName}");
        final.AppendLine($"- **Elevated (admin):** {isAdmin}");
        final.AppendLine();
        final.AppendLine("> Read-only. Only this one computer. Nothing changed or installed.");

        var concerns = findings.Where(f => f.Status == "Concern").ToList();
        final.AppendLine();
        final.AppendLine("## Executive summary");
        final.AppendLine();
        if (concerns.Count == 0)
            final.AppendLine("No machine-level concerns were flagged by automated checks. Interviews and documents still decide the process and training controls.");
        else
        {
            final.AppendLine($"Automated checks flagged **{concerns.Count}** machine-level concern(s) on **{host}**:");
            final.AppendLine();
            foreach (var c in concerns)
                final.AppendLine($"- **[CIS {c.Cis}] {c.Item}** — {c.Detail}");
        }
        final.AppendLine();
        final.AppendLine("_Machine evidence only. Process, training, and provider controls are assessed by interview and document review, not by this tool._");

        final.AppendLine();
        final.AppendLine("## CIS safeguard rollup (machine-checkable items)");
        final.AppendLine();
        final.AppendLine("| CIS | Item | Status | Notes |");
        final.AppendLine("|-----|------|--------|-------|");
        foreach (var f in findings.OrderBy(x => x.Cis))
            final.AppendLine($"| {f.Cis} | {f.Item} | {f.Status} | {f.Detail} |");
        final.AppendLine();

        // ----- Coverage summary + cross-framework evidence map -----
        int covered = CisLabels.Count;
        final.AppendLine("## Framework coverage summary");
        final.AppendLine();
        final.AppendLine($"This machine provides evidence toward **{covered}** CIS Controls v8 (IG1) safeguards that a Windows endpoint can answer directly. Each is mapped below to NIST CSF 2.0, NIST IR 7621, HIPAA, PCI DSS v4, and SOC 2.");
        final.AppendLine();
        final.AppendLine("Controls this endpoint cannot answer are assessed by other means: the Microsoft 365 / Entra tenant (the 6.x MFA and access family), the network edge (4.2, 9.2, 12.1), and interviews or documents (training, offboarding, provider inventory, incident response). This report is one evidence source of three.");
        final.AppendLine();
        final.AppendLine("## Cross-framework evidence map");
        final.AppendLine();
        final.AppendLine("Status is derived from this machine's evidence. A framework tag points to a **relevant** control; it is not a completed assessment of that control.");
        final.AppendLine();
        final.AppendLine("| CIS v8 | Safeguard | Status | NIST CSF 2.0 | NIST IR 7621 | HIPAA | PCI DSS v4 | SOC 2 |");
        final.AppendLine("|--------|-----------|--------|--------------|--------------|-------|-----------|-------|");
        foreach (var cis in CisLabels.Keys.OrderBy(CisSort))
        {
            string label = CisLabels[cis];
            string status = DeriveStatus(findings, cis);
            var m = FrameworkMap.TryGetValue(cis, out var arr) ? arr : new[] { "", "", "", "", "" };
            final.AppendLine($"| {cis} | {label} | {status} | {m[0]} | {m[1]} | {m[2]} | {m[3]} | {m[4]} |");
        }
        final.AppendLine();
        final.AppendLine("_Legend: Concern = evidence shows a gap; OK = evidence shows the control met; Info = context worth review; Reviewed = checked, see detail below. 'N/A' means the framework has no direct machine-level equivalent for that safeguard._");
        final.AppendLine();
        final.AppendLine("---");

        final.Append(body.ToString());

        // ==================== WRITE FILE ====================
        string dir = Path.GetDirectoryName(Environment.ProcessPath) ?? Directory.GetCurrentDirectory();
        string fileName = $"FieldDesk_{Sanitize(host)}_{start:yyyyMMdd-HHmmss}.md";
        string fullPath = Path.Combine(dir, fileName);
        try { File.WriteAllText(fullPath, final.ToString(), new UTF8Encoding(true)); }
        catch
        {
            fullPath = Path.Combine(Directory.GetCurrentDirectory(), fileName);
            File.WriteAllText(fullPath, final.ToString(), new UTF8Encoding(true));
        }
        return fullPath;
    }

    // ===================== helpers =====================

    private static IEnumerable<ManagementObject> Query(string wql, string ns = @"root\CIMV2")
    {
        var scope = new ManagementScope($@"\\.\{ns}");
        scope.Connect();
        using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(wql));
        foreach (ManagementObject mo in searcher.Get()) yield return mo;
    }

    private static ManagementObject? QueryFirst(string wql, string ns = @"root\CIMV2")
    {
        foreach (var mo in Query(wql, ns)) return mo;
        return null;
    }

    private static int CountEvents(string logName, string xpath, int cap = 50000)
    {
        try
        {
            var q = new EventLogQuery(logName, PathType.LogName, xpath);
            using var reader = new EventLogReader(q);
            int n = 0;
            for (EventRecord? e = reader.ReadEvent(); e != null && n < cap; e = reader.ReadEvent()) { n++; e.Dispose(); }
            return n;
        }
        catch { return -1; }
    }

    private static DateTime? NewestEventTime(string logName, string xpath)
    {
        try
        {
            var q = new EventLogQuery(logName, PathType.LogName, xpath) { ReverseDirection = true };
            using var reader = new EventLogReader(q);
            using var e = reader.ReadEvent();
            return e?.TimeCreated;
        }
        catch { return null; }
    }

    private static DateTime? OldestEventTime(string logName)
    {
        try
        {
            var q = new EventLogQuery(logName, PathType.LogName, "*") { ReverseDirection = false };
            using var reader = new EventLogReader(q);
            using var e = reader.ReadEvent();
            return e?.TimeCreated;
        }
        catch { return null; }
    }

    private static string CountText(int n) => n < 0 ? "Log unavailable" : n.ToString();

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
        catch { return ""; }
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
        try { if (int.TryParse(pid, out int id)) return Process.GetProcessById(id).ProcessName; }
        catch { }
        return "?";
    }

    private static void EmitArray(Action<string> line, string label, string[]? values)
    {
        if (values == null || values.Length == 0) return;
        foreach (var v in values) line($"  - {label}: {v}");
    }

    private static void EmitRun(Action<string> line, RegistryKey hive, string path, string label)
    {
        try
        {
            using var k = hive.OpenSubKey(path);
            if (k == null) return;
            foreach (var name in k.GetValueNames())
                line($"  - {label}: {name} = {k.GetValue(name)}");
        }
        catch { }
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
            "COMODO", "AAA Certificate", "D-TRUST", "DTRUST", "SSL.com", "HARICA"
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
        try { using var k = Registry.LocalMachine.OpenSubKey(path); return k?.GetValue(value); }
        catch { return null; }
    }

    private static bool RegKeyExists(string path)
    {
        try { using var k = Registry.LocalMachine.OpenSubKey(path); return k != null; }
        catch { return false; }
    }

    private static object? ReadRegAny(string path, string value)
        => ReadRegHive(Registry.CurrentUser, path, value)
        ?? ReadRegHive(Registry.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\" + path, value);

    private static object? ReadRegHive(RegistryKey hive, string path, string value)
    {
        try { using var k = hive.OpenSubKey(path); return k?.GetValue(value); }
        catch { return null; }
    }

    private static bool IsAdmin()
    {
        try
        {
            using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            return new System.Security.Principal.WindowsPrincipal(id)
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    private static string ToDate(object? wmiDate)
    {
        try
        {
            if (wmiDate == null) return "";
            return ManagementDateTimeConverter.ToDateTime(wmiDate.ToString()).ToString("yyyy-MM-dd HH:mm:ss");
        }
        catch { return wmiDate?.ToString() ?? ""; }
    }

    private static DateTime ParseDate(string? s) => DateTime.TryParse(s, out var d) ? d : DateTime.MinValue;

    private static bool ToBool(object? o)
    {
        if (o == null) return false;
        if (o is bool b) return b;
        return bool.TryParse(o.ToString(), out var r) && r;
    }

    private static int ToInt(object? o) => o != null && int.TryParse(o.ToString(), out var r) ? r : 0;
    private static long ToLong(object? o) => o != null && long.TryParse(o.ToString(), out var r) ? r : 0;
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
        0 => "Boot", 1 => "System", 2 => "Automatic", 3 => "Manual", 4 => "Disabled",
        _ => start.ToString() ?? "?"
    };

    private static string Sanitize(string s) => Regex.Replace(s, "[^A-Za-z0-9_-]", "_");

    // Derive a per-safeguard status from all findings tagged with that CIS id.
    private static string DeriveStatus(List<Finding> findings, string cis)
    {
        var hits = findings.Where(f => f.Cis == cis).ToList();
        if (hits.Any(h => h.Status == "Concern")) return "Concern";
        if (hits.Any(h => h.Status == "OK")) return "OK";
        if (hits.Any(h => h.Status == "Info")) return "Info";
        return "Reviewed";
    }

    // Sort CIS ids numerically (so 10.1 comes after 8.3, not after 1.x).
    private static double CisSort(string cis)
    {
        var parts = cis.Split('.');
        double major = parts.Length > 0 && double.TryParse(parts[0], out var mj) ? mj : 0;
        double minor = parts.Length > 1 && double.TryParse(parts[1], out var mn) ? mn : 0;
        return major * 100 + minor;
    }

    // ---- Batch 1B: services helpers ----
    private static string ExtractExePath(string pathName)
    {
        if (string.IsNullOrWhiteSpace(pathName)) return "";
        pathName = pathName.Trim();
        if (pathName.StartsWith("\""))
        {
            int end = pathName.IndexOf('"', 1);
            if (end > 1) return pathName.Substring(1, end - 1);
        }
        var m = Regex.Match(pathName, @"^(.*?\.exe)", RegexOptions.IgnoreCase);
        return m.Success ? m.Groups[1].Value : pathName;
    }

    private static bool IsStandardExeLocation(string exe)
    {
        if (string.IsNullOrWhiteSpace(exe)) return true; // don't flag unknown
        string e = exe.ToLowerInvariant();
        return e.Contains(@"\windows\") || e.Contains(@"\program files\") || e.Contains(@"\program files (x86)\");
    }

    private static bool HasUnquotedServicePath(string pathName)
    {
        if (string.IsNullOrWhiteSpace(pathName)) return false;
        string p = pathName.Trim();
        if (p.StartsWith("\"")) return false;                 // properly quoted
        var exe = Regex.Match(p, @"^(.*?\.exe)", RegexOptions.IgnoreCase);
        if (!exe.Success) return false;
        string exePath = exe.Groups[1].Value;
        return exePath.Contains(' ');                          // space + unquoted = risk
    }

    // ---- Batch 1C: Defender / ASR / Device Guard text maps ----
    private static string MapsText(object? v) => ToInt(v) switch { 0 => "Disabled", 1 => "Basic", 2 => "Advanced", _ => "Not set" };
    private static string SampleText(object? v) => ToInt(v) switch { 0 => "Always prompt", 1 => "Send safe samples", 2 => "Never send", 3 => "Send all samples", _ => "Not set" };
    private static string PuaText(object? v) => ToInt(v) switch { 0 => "Disabled", 1 => "Enabled", 2 => "Audit", _ => "Not set" };
    private static string NpText(object? v) => ToInt(v) switch { 0 => "Disabled", 1 => "Enabled (block)", 2 => "Audit", _ => "Not set" };
    private static string CfaText(object? v) => ToInt(v) switch { 0 => "Disabled", 1 => "Enabled (block)", 2 => "Audit", _ => "Not set" };
    private static string AsrActionText(string a) => a switch { "0" => "Not configured", "1" => "Enabled (block)", "2" => "Audit", "6" => "Warn", _ => "Unknown" };
    private static string VbsText(int v) => v switch { 0 => "Off", 1 => "Enabled but not running", 2 => "Enabled and running", _ => "Unknown" };
    private static string SecSvcText(int v) => v switch { 1 => "Credential Guard", 2 => "HVCI", 3 => "System Guard", 4 => "SMM", _ => $"Service {v}" };

    private static int[] ToIntArray(object? o)
    {
        if (o is int[] ia) return ia;
        if (o is System.Collections.IEnumerable en && o is not string)
        {
            var list = new List<int>();
            foreach (var item in en) if (int.TryParse(item?.ToString(), out int n)) list.Add(n);
            return list.ToArray();
        }
        return Array.Empty<int>();
    }

    private static string[] ToStringArray(object? o)
    {
        if (o is string[] sa) return sa;
        if (o is System.Collections.IEnumerable en && o is not string)
        {
            var list = new List<string>();
            foreach (var item in en) { var v = item?.ToString(); if (!string.IsNullOrEmpty(v)) list.Add(v); }
            return list.ToArray();
        }
        return Array.Empty<string>();
    }

    private static string AsrRuleName(string guid) => guid.ToLowerInvariant() switch
    {
        "56a863a9-875e-4185-98a7-b882c64b5ce5" => "Block abuse of exploited vulnerable signed drivers",
        "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" => "Block Adobe Reader from creating child processes",
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a" => "Block Office apps from creating child processes",
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" => "Block credential stealing from LSASS",
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" => "Block executable content from email/webmail",
        "01443614-cd74-433a-b99e-2ecdc07bfc25" => "Block executables unless prevalence/age/trusted",
        "5beb7efe-fd9a-4556-801d-275e5ffc04cc" => "Block execution of potentially obfuscated scripts",
        "d3e037e1-3eb8-44c8-a917-57927947596d" => "Block JS/VBScript from launching downloaded content",
        "3b576869-a4ec-4529-8536-b80a7769e899" => "Block Office apps from creating executable content",
        "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" => "Block Office apps from injecting into other processes",
        "26190899-1602-49e8-8b27-eb1d0a1ce869" => "Block Office comm apps from creating child processes",
        "e6db77e5-3df2-4cf1-b95a-636979351e5b" => "Block persistence through WMI event subscription",
        "d1e49aac-8f56-4280-b9ba-993a6d77406c" => "Block process creations from PsExec and WMI",
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" => "Block untrusted/unsigned processes from USB",
        "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" => "Block Win32 API calls from Office macros",
        "c1db55ab-c21a-4637-bb3f-a12568109d35" => "Use advanced ransomware protection",
        _ => "ASR rule"
    };
}
