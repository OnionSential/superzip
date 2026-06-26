#define MyAppName "SuperZip"
#define MyAppVersion "1.0"
#define MyAppPublisher "Самодельные архиваторы"
#define MyAppExeSZ "sz.exe"
#define MyAppExeMix "mix.exe"
#define MyAppExeGUI "SuperZip.exe"

[Setup]
AppId={{B4E3F2A0-7C1D-4E9A-9F2B-2D6C8A1E5F30}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeGUI}
OutputBaseFilename=SuperZip-Setup
Compression=lzma2/ultra64
SolidCompression=yes
SetupIconFile=assets\app_icon.ico
WizardStyle=modern
WizardImageFile=assets\wizard_banner.bmp
WizardSmallImageFile=assets\wizard_small.bmp
WizardImageStretch=no
DisableWelcomePage=no
PrivilegesRequired=lowest
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Создать значок на рабочем столе"; GroupDescription: "Дополнительно:"
Name: "contextmenu"; Description: "Добавить пункт ""Сжать в SuperZip"" в контекстное меню (файлы и папки)"; GroupDescription: "Дополнительно:"
Name: "fileassoc"; Description: "Связать файлы .sz с SuperZip (значок и открытие по двойному клику)"; GroupDescription: "Дополнительно:"

[Files]
Source: "{#MyAppExeGUI}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#MyAppExeSZ}";  DestDir: "{app}"; Flags: ignoreversion
Source: "{#MyAppExeMix}"; DestDir: "{app}"; Flags: ignoreversion
Source: "assets\app_icon.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "assets\archive_icon.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}";              Filename: "{app}\{#MyAppExeGUI}"; IconFilename: "{app}\app_icon.ico"
Name: "{group}\Удалить {#MyAppName}";       Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}";          Filename: "{app}\{#MyAppExeGUI}"; IconFilename: "{app}\app_icon.ico"; Tasks: desktopicon

[Registry]
; --- правый клик на ФАЙЛЕ -> Сжать в SuperZip (запускает SuperZip.exe с путём;
;     сама программа разберёт, сжимать или распаковывать, по расширению) ---
Root: HKCU; Subkey: "Software\Classes\*\shell\SuperZip"; ValueType: string; ValueName: ""; ValueData: "Сжать в SuperZip"; Tasks: contextmenu; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\*\shell\SuperZip"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\app_icon.ico"; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\*\shell\SuperZip\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeGUI}"" ""%1"""; Tasks: contextmenu

; --- правый клик на ПАПКЕ -> Сжать в SuperZip ---
Root: HKCU; Subkey: "Software\Classes\Directory\shell\SuperZip"; ValueType: string; ValueName: ""; ValueData: "Сжать в SuperZip"; Tasks: contextmenu; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\Directory\shell\SuperZip"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\app_icon.ico"; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\Directory\shell\SuperZip\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeGUI}"" ""%1"""; Tasks: contextmenu

; --- ассоциация .sz: свой значок (с замком) + открытие двойным кликом ---
Root: HKCU; Subkey: "Software\Classes\.sz"; ValueType: string; ValueName: ""; ValueData: "SuperZip.Archive"; Tasks: fileassoc; Flags: uninsdeletevalue
Root: HKCU; Subkey: "Software\Classes\SuperZip.Archive"; ValueType: string; ValueName: ""; ValueData: "Архив SuperZip"; Tasks: fileassoc; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\SuperZip.Archive\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\archive_icon.ico,0"; Tasks: fileassoc
Root: HKCU; Subkey: "Software\Classes\SuperZip.Archive\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeGUI}"" ""%1"""; Tasks: fileassoc

[Run]
Filename: "{app}\{#MyAppExeGUI}"; Description: "Запустить SuperZip"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: files; Name: "{app}\*.sz"
