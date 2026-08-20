# FieldDesk Collector

A standalone Windows desktop app for authorized security assessments. It reads
read-only posture from **the one computer it runs on**, then writes a plain-text
(Markdown) report. It changes nothing, installs nothing, and touches no other
computer on the network.

The app has a simple window: one button to run, a log that shows progress, and
buttons to open the finished report. It asks for administrator rights on launch,
so Windows shows the standard UAC prompt by itself.

## Download and run (for the person doing the assessment)

1. Go to the **Releases** page of this repository.
2. Download `FieldDeskCollector.exe`.
3. Copy it to a USB drive if you like.
4. On the target machine, double-click it. Click **Yes** at the UAC prompt.
5. Click **Run Collection**. Wait about 10 seconds.
6. The report file appears next to the app. Click **Open Report** to read it.

There is no install step and no build step for end users. It is one file.

## What it collects

Device identity and OS, patch history, BitLocker status, Windows Firewall
profiles, Microsoft Defender / registered antivirus, local users and
Administrators-group membership, management (domain / Intune) enrollment,
installed software, and this host's own network configuration.

## What it never touches

No documents, no passwords or secrets, no email, no browser history, no
keystrokes, no screen contents, and **no other computers**. It does not scan,
ping, or connect to anything else on the network. See `DISCLOSURE.md` — that is
the page to hand a client before running the app.

## How the .exe gets built (for the repository owner)

You do not build the app by hand. GitHub builds it for you.

1. Put these files in a GitHub repository.
2. GitHub Actions runs the workflow in `.github/workflows/build.yml`.
3. On every push to `main`, it builds the `.exe` and saves it as a downloadable
   artifact under the **Actions** tab.
4. To publish a real download, create a version tag. GitHub then makes a Release
   with the `.exe` attached:

   ```
   git tag v1.0.0
   git push origin v1.0.0
   ```

That is the only "command" involved, and it is a one-time publish step. Nobody
ever compiles the app on their own machine.

## Building locally (optional, only if you want to)

You need the .NET 8 SDK. Then:

```
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true
```

The `.exe` lands under `bin/Release/net8.0-windows/win-x64/publish/`.

## Code signing (before wide distribution)

An unsigned .exe trips Windows SmartScreen, because a portable binary that reads
accounts and security settings also describes recon tooling. Sign the published
`.exe` with an Authenticode code-signing certificate before handing it to a
client's IT team. Until then, the open source code is the trust anchor: anyone
can read exactly what it does.

## Authorization — not optional

Run this only on machines you are contracted and authorized in writing to
assess. Unauthorized use may violate the federal Computer Fraud and Abuse Act
and state computer-crime statutes.

## Project layout

| File | Purpose |
|------|---------|
| `Program.cs` | App entry point |
| `MainForm.cs` | The window and buttons |
| `Collector.cs` | The read-only collection logic |
| `app.manifest` | Requests administrator rights at launch |
| `FieldDeskCollector.csproj` | Build settings |
| `.github/workflows/build.yml` | Automatic GitHub build |
| `DISCLOSURE.md` | Plain-language sheet for the client |
| `LICENSE` | MIT |

## License

MIT. See `LICENSE`. Open source on purpose — the readability is the point.
