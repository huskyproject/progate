{ $O+,F+,I-,S-,R-,V-}
Unit MKGlobT;

{$IfDef FPC}
 {$PackRecords 1}
{$EndIf}

Interface

Uses Dos;

type
  OldAddrType = record
    zone,
    net,
    node,
    point : word;
  end;

  PAddr = ^AddrType;
  AddrType = record                 {Used for Fido style addresses}
    zone,
    net,
    node,
    point : word;
    domain : string[20];
  end;
Type SecType = Record
  Level: Word;                         {Security level}
  Flags: LongInt;                      {32 bitmapped flags}
  End;

Type MKDateType = Record
  Year: Word;
  Month: Word;
  Day: Word;
  End;

Type MKDateTime = Record
  Year: Word;
  Month: Word;
  Day: Word;
  Hour: Word;
  Min: Word;
  Sec: Word;
  End;

Const
  uoNotAvail = 0;
  uoBrowse =  1;
  uoXfer   =  2;
  uoMsg    =  3;
  uoDoor   =  4;
  uoChat   =  5;
  uoQuest  =  6;
  uoReady  =  7;
  uoMail   =  8;
  uoWait   =  9;
  uoLogIn  = 10;

Function  AddrStr(Addr: AddrType): String;
procedure ParseAddr(AStr: String; Var DestAddr: AddrType);
Function  DomainlessAddrStr(Addr: AddrType): String;
Function  PointlessAddrStr(Var Addr: AddrType): String;
function  CompAddr(a1, a2: addrtype): byte;
Function  IsValidAddr(Addr: AddrType): Boolean;
Function  Access(USec: SecType; RSec: SecType): Boolean;
Function  EstimateXferTime(FS: LongInt; BaudRate: Word; Effic: Word): LongInt;
  {Result in seconds}
Function  NameCrcCode(Str: String): LongInt; {Get CRC code for name}
Function  Flag2Str(Number: Byte): String;
Function  Str2Flag(St: String): Byte;
Function  ValidMKDate(DT: MKDateTime): Boolean;
{$IFDEF WINDOWS}
Procedure DT2MKDT(Var DT: TDateTime; Var DT2: MKDateTime);
Procedure MKDT2DT(Var DT: MKDateTime; Var DT2: TDateTime);
{$ELSE}
Procedure DT2MKDT(Var DT: DateTime; Var DT2: MKDateTime);
Procedure MKDT2DT(Var DT: MKDateTime; Var DT2: DateTime);
{$ENDIF}
Procedure Str2MKD(St: String; Var MKD: MKDateType);
Function MKD2Str(MKD: MKDateType): String;
Function AddrEqual(Addr1: AddrType; Addr2: AddrType):Boolean;

Var
  StartUpPath: String[128];

Const
  UseEms: Boolean = True;
  LocalMode: Boolean = False;
  LogToPrinter: Boolean = False;
  ReLoad: Boolean = False;
  NodeNumber: Byte = 1;
  OverRidePort: Byte = 0;
  OverRideBaud: Word = 0;
  UserBaud: Word = 0;
  ExitErrorLevel: Byte = 0;
  TimeToEvent: LongInt = 0;
  ShellToMailer: Boolean = False;

Implementation

Uses MKString, Crc32, MKMisc;


Function Flag2Str(Number: Byte): String;
  Var
    Temp1: Byte;
    Temp2: Byte;
    i: Word;
    TempStr: String[8];

  Begin
  Temp1 := 0;
  Temp2 := $01;
  For i := 1 to 8 Do
    Begin
    If (Number and Temp2) <> 0 Then
      TempStr[i] := 'X'
    Else
      TempStr[i] := '-';
    Temp2 := Temp2 shl 1;
    End;
  TempStr[0] := #8;
  Flag2Str := TempStr;
  End;


Function Str2Flag(St: String): Byte;
  Var
    i: Word;
    Temp1: Byte;
    Temp2: Byte;

  Begin
  St := StripBoth(St,' ');
  St := PadLeft(St,'-',8);
  Temp1 := 0;
  Temp2 := $01;
  For i := 1 to 8 Do
    Begin
    If UpCase(St[i]) = 'X' Then
      Inc(Temp1,Temp2);
    Temp2 := Temp2 shl 1;
    End;
  Str2Flag := Temp1;
  End;



{ vergleich zweier adressen (wilcars "*" erlaubt!) -  (c)sl }
function CompAddr(a1, a2: addrtype): byte;
var
  e : byte;
begin
  e := 0;
  if a1.zone = 0 then
  begin
    a1.zone := a2.zone;
    inc(e);
  end;
  if a1.net = 0 then
  begin
    a1.net := a2.net;
    inc(e);
  end;
  if a1.node = 0 then
  begin
    a1.node := a2.node;
    inc(e);
  end;
  if a1.point = 0 then
  begin
    a1.point := a2.point;
    inc(e);
  end;
  if not ((a1.zone = a2.zone) and
      (a1.node = a2.node) and
      (a1.net = a2.net) and
      (a1.point = a2.point)) then e := 255;
  CompAddr := e;
end;

Function AddrStr(Addr: AddrType): String;
var
  temp : string[40];
begin
  if Addr.Point = 0 then
  begin
    temp := Long2Str(Addr.Zone) + ':' + Long2Str(Addr.Net) + '/' + Long2Str(Addr.Node)
  end
  else
  begin
    temp := Long2Str(Addr.Zone) + ':' + Long2Str(Addr.Net) + '/' + Long2Str(Addr.Node) + '.' + Long2Str(Addr.Point);
  end;
  if Addr.domain <> '' then temp := temp + '@' + Addr.domain;
  AddrStr := temp;
end;

Function DomainlessAddrStr(Addr: AddrType): String;
begin
  if Addr.Point = 0 then
  begin
    DomainlessAddrStr := Long2Str(Addr.Zone) + ':' + Long2Str(Addr.Net) + '/' + Long2Str(Addr.Node)
  end
  else
  begin
    DomainlessAddrStr :=
      Long2Str(Addr.Zone) + ':' + Long2Str(Addr.Net) + '/' + Long2Str(Addr.Node) + '.' + Long2Str(Addr.Point);
  end;
end;

Function PointlessAddrStr(Var Addr: AddrType): String;
begin
  PointlessAddrStr := Long2Str(Addr.Zone) + ':' + Long2Str(Addr.Net) + '/' + Long2Str(Addr.Node);
end;

Function Access(USec: SecType; RSec: SecType): Boolean;
  Begin
  If (USec.Level >=  RSec.Level) Then
    Access :=  ((RSec.Flags and Not(USec.Flags)) = 0)
  Else
    Access := False;
  End;


Function EstimateXferTime(FS: LongInt; BaudRate: Word; Effic: Word): LongInt;
  Begin
  If BaudRate > 0 Then
    EstimateXferTime := ((FS * 100) Div Effic) Div (BaudRate Div 10)
  Else
    EstimateXferTime := ((FS * 100) Div Effic) Div (960);
  End;


Function NameCrcCode(Str: String): LongInt;
  Var
    NCode: LongInt;
    i: WOrd;

  Begin
  NCode := UpdC32(Length(Str),$ffffffff);
  i := 1;
  While i < Length(Str) Do
    Begin
    NCode := Updc32(Ord(UpCase(Str[i])), NCode);
    Inc(i);
    End;
  NameCrcCode := NCode;
  End;


procedure ParseAddr(AStr: String; Var DestAddr: AddrType);
var
  p: byte;
begin
  fillchar(destaddr, sizeof(destaddr), 0);
  AStr := StripBoth(AStr, ' ');

  p := pos('@', AStr);
  if p > 0 then
  begin
    DestAddr.domain := copy(astr, p + 1, 255);
    astr := copy(astr, 1, p - 1);
  end;

  p := pos(':', astr);
  if p > 0 then
  begin
    destaddr.zone := str2long(copy(astr, 1, p - 1));
    astr := copy(astr, p + 1, 255)
  end;

  p := pos('/', astr);
  if p > 0 then
  begin
    destaddr.net := str2long(copy(astr, 1, p - 1));
    astr := copy(astr, p + 1, 255)
  end;

  p := pos('.', astr);

  if p = 0 then p := 255;
  destaddr.node := str2long(copy(astr, 1, p - 1));
  astr := copy(astr, p + 1, 255);

  if p <> 255 then
  begin
    destaddr.point := str2long(copy(astr, 1, 255));
  end;

end;


{$IFDEF WINDOWS}
Procedure DT2MKDT(Var DT: TDateTime; Var DT2: MKDateTime);
{$ELSE}
Procedure DT2MKDT(Var DT: DateTime; Var DT2: MKDateTime);
{$ENDIF}

  Begin
  DT2.Year := DT.Year;
  DT2.Month := DT.Month;
  DT2.Day := DT.Day;
  DT2.Hour := DT.Hour;
  DT2.Min := DT.Min;
  DT2.Sec := DT.Sec;
  End;


{$IFDEF WINDOWS}
Procedure MKDT2DT(Var DT: MKDateTime; Var DT2: TDateTime);
{$ELSE}
Procedure MKDT2DT(Var DT: MKDateTime; Var DT2: DateTime);
{$ENDIF}

  Begin
  DT2.Year := DT.Year;
  DT2.Month := DT.Month;
  DT2.Day := DT.Day;
  DT2.Hour := DT.Hour;
  DT2.Min := DT.Min;
  DT2.Sec := DT.Sec;
  End;


Function  ValidMKDate(DT: MKDateTime): Boolean;
  Var
    {$IFDEF WINDOWS}
    DT2: TDateTime;
    {$ELSE}
    DT2: DateTime;
    {$ENDIF}

  Begin
  MKDT2DT(DT, DT2);
  ValidMKDate := ValidDate(DT2);
  End;


Procedure Str2MKD(St: String; Var MKD: MKDateType);
  Begin
  FillChar(MKD, SizeOf(MKD), #0);
  MKD.Year := Str2Long(Copy(St, 7, 2));
  MKD.Month := Str2Long(Copy(St, 1, 2));
  MKD.Day := Str2Long(Copy(St, 4, 2));
  If MKD.Year < 80 Then
    Inc(MKD.Year, 2000)
  Else
    Inc(MKD.Year, 1900);
  End;


Function MKD2Str(MKD: MKDateType): String;
  Begin
  MKD2Str := PadLeft(Long2Str(MKD.Month),'0',2) + '-' +
             PadLeft(Long2Str(MKD.Day), '0',2) + '-' +
             PadLeft(Long2Str(MKD.Year Mod 100), '0', 2);
  End;


Function AddrEqual(Addr1: AddrType; Addr2: AddrType):Boolean;
  Begin
  AddrEqual := ((Addr1.Zone = Addr2.Zone) and (Addr1.Net = Addr2.Net)
    and (Addr1.Node = Addr2.Node) and (Addr1.Point = Addr2.Point));
  End;



Function  IsValidAddr(Addr: AddrType): Boolean;
  Begin
  IsValidAddr := ((Addr.Zone = 0) And (Addr.Net = 0));
    { We have to skip administrative '/0' addresses}
  End;


End.
