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
    private const string Version = "1.3.0";

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
}
