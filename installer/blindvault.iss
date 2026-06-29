; BlindVault Windows installer (Inno Setup).
; Packages the GUI (BlindVault.exe) + the CLI (bv.exe), adds `bv` to PATH,
; creates a Start Menu entry, and provides a clean uninstaller.
; Built in CI — see .github/workflows/release.yml. Version is passed with
;   iscc /DMyAppVersion=X.Y.Z installer\blindvault.iss

#ifndef MyAppVersion
  #define MyAppVersion "0.0.0"
#endif
#define MyAppName "BlindVault"
#define MyAppPublisher "Loizos Kallinos"
#define MyAppURL "https://github.com/psypilot/blindvault"

[Setup]
; A stable AppId so upgrades replace the previous version in place.
AppId={{B1A7D3E2-9C4F-4A6B-8E1D-2F5C7A9B0D34}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/blob/main/TROUBLESHOOTING.md
DefaultDirName={autopf}\BlindVault
DefaultGroupName=BlindVault
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=BlindVault-Setup
SetupIconFile=..\assets\blindvault.ico
UninstallDisplayIcon={app}\BlindVault.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; Per-user install — no administrator rights required (friendlier for everyone).
PrivilegesRequired=lowest
ChangesEnvironment=yes

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked
Name: "addtopath";   Description: "Add the &bv command to my PATH"; GroupDescription: "Command line:"

[Files]
Source: "..\dist\BlindVault.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\bv.exe";         DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\BlindVault";           Filename: "{app}\BlindVault.exe"
Name: "{group}\Uninstall BlindVault"; Filename: "{uninstallexe}"
Name: "{autodesktop}\BlindVault";     Filename: "{app}\BlindVault.exe"; Tasks: desktopicon

[Registry]
; Append the install dir to the per-user PATH (so `bv` works in any terminal).
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; \
  ValueData: "{olddata};{app}"; Check: NeedsAddPath('{app}'); Tasks: addtopath

[Run]
Filename: "{app}\BlindVault.exe"; Description: "Launch BlindVault now"; \
  Flags: nowait postinstall skipifsilent

[Code]
function NeedsAddPath(Param: string): Boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', OrigPath) then
  begin
    Result := True;
    Exit;
  end;
  Result := Pos(';' + Param + ';', ';' + OrigPath + ';') = 0;
end;

procedure RemoveFromPath(Param: string);
var
  OrigPath, Padded: string;
  P: Integer;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', OrigPath) then
    Exit;
  Padded := ';' + OrigPath + ';';
  P := Pos(';' + Param + ';', Padded);
  if P = 0 then
    Exit;
  Delete(Padded, P, Length(Param) + 1);
  { trim the wrapping semicolons we added }
  if (Length(Padded) > 0) and (Padded[1] = ';') then Delete(Padded, 1, 1);
  if (Length(Padded) > 0) and (Padded[Length(Padded)] = ';') then Delete(Padded, Length(Padded), 1);
  RegWriteExpandStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', Padded);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveFromPath(ExpandConstant('{app}'));
end;
