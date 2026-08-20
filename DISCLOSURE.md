# What the FieldDesk Collector does — plain language

Hand this to the client before you run anything. It exists so nobody has to
take "trust me" for an answer.

## In one sentence

It reads configuration and status from **this one computer**, writes a text
report, and changes nothing.

## It looks at

- The computer's name, make, model, and Windows version
- When Windows was last updated
- Whether the disk is encrypted (BitLocker)
- Whether the firewall and antivirus are on
- Which user accounts exist and who has administrator rights
- Whether the computer is managed (domain or Microsoft Intune)
- Which applications are installed
- This computer's own network address settings

## It does NOT look at

- Documents, spreadsheets, photos, or any personal files
- Passwords, PINs, or any saved credentials
- Email, messages, or their contents
- Web browsing history or anything typed into a browser
- Keystrokes or what's on the screen
- **Any other computer.** It does not scan the network or connect to other
  machines. It only ever describes the one it is run on.

## What happens to the report

It's a plain-text (Markdown) file you can open and read in Notepad. It is
written to the assessor's drive. It is not uploaded automatically and nothing
is sent to any outside service by the tool itself. Retention and handling are
covered in the engagement agreement.

## How to verify all of the above

The tool is open source under the MIT license. The full script is readable
text — anyone on your team can open `FieldDesk-Collector.ps1` and confirm
exactly what it reads before it is run.

## Authorization

This is run only with your written authorization, on the machines named in the
engagement, during the agreed window.
