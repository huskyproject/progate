Program ProGate; {internet<->fido-gate}
{$I-}
{$IfDef SPEED}
{$Else}
 {$IfDef VIRTUALPASCAL}
  {$Define VP}
  {$M 65520}
 {$Else}
  {$M 65520, 0, 655360}
 {$EndIf}
{$EndIf}

Uses
{$IfDef UNIX}
 Linux,
{$EndIf}
 DOS,
 MKGlobT, MKMisc, MKMsgAbs, MKMsgFid, MKMsgEzy, MKMsgJam, MKMsgHud, MKMsgSqu,
 Types, GeneralP, IniFile, Log;
{$IfDef VP}
 {$IfDef VPDEMO}
  {$Dynamic VP11DEMO.LIB}
 {$EndIf}
{$EndIf}

Const
  ShortName = 'progate';
{$IfDef OS2}
  Version = '/2'
{$Else}
 {$IfDef UNIX}
 Version = '/Lx'
 {$Else}
  {$IfDef DPMI}
  Version = '/16'
  {$Else}
  Version = '/8'
  {$EndIf}
 {$EndIf}
{$EndIf}
  + ' 0.9beta6';

  {TCfg.PKT_Mailer}
  cCM_BT              = 1;

  {TCfg.SendMethod}
  cSM_Program         = 1;
  cSM_SendMailQueue   = 2;


Type
 PCfg = ^TCfg;
 PLink = ^TLink;
 PEnCoder = ^TEnCoder;
 PDeCoder = ^TDeCoder;

 TNetAddr = {21 Byte}
  Record
  Zone, Net, Node, Point: Word;
  Domain: String[12];
  end;

 TEnCoder = {523 Byte}
  Record
  Name: String[10];
  OutFile: String;
  Command: String;
  End;

 TDeCoder = {267 Byte}
  Record
  Name: String[10];
  Command: String;
  End;

 TCfg =
  Record
  LogFile: String;
  LogLevel, ScrLevel: Byte;
  GateAddr, ToAddr: TNetAddr;
  NetMail: String; {path of netmailarea}
  MailBox: String; {mailbox-file to gate}
  SendMethod: Byte; {how to send emails}
  SendProgram: String; {program used to send emails}
  MQueue: String; {path to sendmail queue}
  Tmp: String;
  Prio: LongInt; {initial priority for EMails}
  Host: String; {own hostname}
  Org: String; {organization for EMails}
  Domain: String; {domain to use for EMails if not specified in Netmail}
  PKT_EMail: String; {EMail-address used for PKTs}
  PKT_Inbound: String; {where incoming PKTs are put}
  PKT_Mailer: Byte;
  PKT_BT_Outbound: String;
  Links: PLink; {FTN<->RFC-Links}
  NumLinks: Word;
  PrioSem: String; {semaphore created when Crash flag was set on any outgoing
                    EMail}
  EnCoders: Array[1..20] of PEnCoder;
  NumEnCoder: Byte;
  DeCoders: Array[1..20] of PDeCoder;
  NumDeCoder: Byte;
  End;

 TLink =
  Record
  Prev, Next: PLink;
  Name: String40;
  EMail : String80;
  Subject: String80;
  Method: String[10];
  Addr: TNetAddr;
  End;

Var
 Debug: Boolean;
 NM: AbsMsgPtr;
 Cfg: PCfg;
 CfgName: String;
 lh: Byte; {loghandle}
 CurLink: PLink;

Procedure Syntax;
 Begin
 WriteLn('Syntax: '+ShortName+' [-d]');
 WriteLn('Example: '+ShortName);
 WriteLn('-d : debug');
 WriteLn;
 End;


Function Addr2Str(Addr: TNetAddr): String;
Var
  s: String;

  Begin
  With Addr do
    Begin
    s := IntToStr(Zone) + ':' + IntToStr(Net) + '/' + IntToStr(Node);
    If (Point <> 0) then s := s + '.' + IntToStr(Point);
    If (Domain <> '') then s := s + '@' + Domain;
    Addr2Str := s;
    End;
  End;

Procedure Str2Addr(s: String; var Addr: TNetAddr);
Var
{$IfDef VIRTUALPASCAL}
  i: LongInt;
{$Else}
  i: Integer;
{$EndIf}

  Begin
  If (Pos(':', s) = 0) then Addr.Zone := 0
  Else
    Begin
    Val(Copy(s, 1, Pos(':', s) - 1), Addr.Zone, i);
    Delete(s, 1, Pos(':', s));
    End;
  If (Pos('/', s) = 0) then Addr.Net := 0
  Else
    Begin
    Val(Copy(s, 1, Pos('/', s) - 1), Addr.Net, i);
    Delete(s, 1, Pos('/', s));
    End;
  If (Pos('.', s) = 0) or
   ((Pos('.', s) > Pos('@', s)) and (Pos('@', s) > 0)) then
    Begin
    Addr.Point := 0;
    If (Pos('@', s) = 0) then
      Begin
      Val(s, Addr.Node, i);
      Addr.Domain := '';
      End
    Else
      Begin
      Val(Copy(s, 1, Pos('@', s) - 1), Addr.Node, i);
      Delete(s, 1, Pos('@', s));
      Addr.Domain := UpStr(s);
      End;
    End
  Else
    Begin
    Val(Copy(s, 1, Pos('.', s) - 1), Addr.Node, i);
    Delete(s, 1, Pos('.', s));
    If (Pos('@', s) = 0) then
      Begin
      Val(s, Addr.Point, i);
      Addr.Domain := '';
      End
    Else
      Begin
      Val(Copy(s, 1, Pos('@', s) - 1), Addr.Point, i);
      Delete(s, 1, Pos('@', s));
      Addr.Domain := UpStr(s);
      End;
    End;
  End;

Function CompAddr(A1, A2: TNetAddr): Boolean;
Var
  C: Boolean;

  Begin
  c := ((A1.Zone = 0) or (A2.Zone = 0) or (A1.Zone = A2.Zone));
  c := c and ((A1.Net = 0) or (A2.Net = 0) or (A1.Net = A2.Net));
  c := c and (A1.Node = A2.Node);
  c := c and (A1.Point = A2.Point);
  c := c and ((A1.Domain = '') or (A2.Domain = '') or (UpStr(A1.Domain) = UpStr(A2.Domain)));
  CompAddr := c;
  End;

Procedure MKAddr2TNetAddr(MKAddr: AddrType; Var A1: TNetAddr);
  Begin
  A1.Zone := MKAddr.Zone;
  A1.Net := MKAddr.Net;
  A1.Node := MKAddr.Node;
  A1.Point := MKAddr.Point;
  A1.Domain := MKAddr.Domain;
  End;

Procedure TNetAddr2MKAddr(A1: TNetAddr; Var MKAddr: AddrType);
  Begin
  MKAddr.Zone := A1.Zone;
  MKAddr.Net := A1.Net;
  MKAddr.Node := A1.Node;
  MKAddr.Point := A1.Point;
  MKAddr.Domain := A1.Domain;
  End;

Function RandName8: String8;
  Begin
  RandName8 := WordToHex(Random($FFFF))+WordToHex(Random($FFFF));
  End;


Function GetMsgID : String;
Var
 MsgIDFile: Text;
 CurMsgID: ULong;
 Dir: String;
 s: String;
{$IfDef VP}
 Error: LongInt;
{$Else}
 Error: Integer;
{$EndIf}

 begin
 Dir := GetEnv('MSGID');
 If (Dir <> '') then Dir := AddDirSep(Dir);
 Assign(MsgIDFile, Dir + 'msgid.dat');
 {$I-} ReSet(MsgIDFile); {$I+}
 If (IOResult = 0) then
  begin
  ReadLn(MsgIDFile, s);
  While (s[Byte(s[0])] = #10) or (s[Byte(s[0])] = #13) do Dec(s[0]);
  Val(s, CurMsgID, Error);
  If (Error <> 0) or (CurMsgID = 0) then CurMsgID := 1;
  Close(MsgIDFile);
  end
 Else CurMsgID := 1; {Reset MsgID if no MSGID.DAT is found}
 GetMsgID := WordToHex(word(CurMsgID SHR 16)) + WordToHex(word(CurMsgID));
 Inc(CurMsgID);
 {$I-} ReWrite(MsgIDFile); {$I+}
 If (IOResult = 0) then
  Begin
  Write(MsgIDFile, CurMsgID, #13#10);
  Close(MsgIDFile);
{$IfDef UNIX}
  ChMod(Dir + 'msgid.dat', FilePerm);
{$EndIf}
  End;
 end;

Procedure DeCode(Method: String10; fname: String);
Var
 CurMethod: Byte;
 s: String;
 i: Byte;
 OldDir: String;

 Begin
 If (Cfg^.NumDeCoder = 0) then
  Begin
  LogSetCurLevel(lh, 2);
  LogWriteLn(lh, 'Could not find decoder "'+Method+'" to decode incoming EMail!');
  Exit;
  End;
 For CurMethod := 1 to Cfg^.NumDeCoder do
  If (Cfg^.DeCoders[CurMethod]^.Name = Method) then Break;

 If (Cfg^.DeCoders[CurMethod]^.Name <> Method) then
  Begin
  LogSetCurLevel(lh, 2);
  LogWriteLn(lh, 'Could not find decoder "'+Method+'" to decode incoming EMail!');
  End
 Else
  Begin
  s := Cfg^.DeCoders[CurMethod]^.Command;
  i := Pos('%F', UpStr(s));
  While (i <> 0) do
   Begin
   Delete(s, i, 2);
   Insert(fname, s, i);
   i := Pos('%F', UpStr(s));
   End;

  GetDir(0, OldDir);
  ChDir(Cfg^.PKT_Inbound);
{$IfDef UNIX}
  Shell(s);
{$Else}
  SwapVectors;
  Exec(GetEnv('COMSPEC'), '/c '+s);
  SwapVectors;
{$EndIf}
  ChDir(OldDir);
  End;
 End;

Procedure EnCode(Method: String10; in_fname: string; var out_fname: String);
Var
 CurMethod: Byte;
 s: String;
 i: Byte;
 OldDir: String;
 inDir: String;
 inFile: String;

 Begin
 If (Cfg^.NumEnCoder = 0) then
  Begin
  LogSetCurLevel(lh, 2);
  LogWriteLn(lh, 'Could not find encoder "'+Method+'" to encode outgoing EMail!');
  Exit;
  End;
 For CurMethod := 1 to Cfg^.NumEnCoder do
  If (Cfg^.EnCoders[CurMethod]^.Name = Method) then Break;

 If (Cfg^.EnCoders[CurMethod]^.Name <> Method) then
  Begin
  LogSetCurLevel(lh, 2);
  LogWriteLn(lh, 'Could not find encoder "'+Method+'" to encode outgoing EMail!');
  End
 Else
  Begin
  out_fname := Cfg^.EnCoders[CurMethod]^.OutFile;
  i := LastPos(DirSep, in_fname);
  inDir := Copy(in_fname, 1, i - 1);
  inFile := Copy(in_fname, i + 1, Length(in_fname) - i);

  s := Cfg^.EnCoders[CurMethod]^.Command;
  i := Pos('%I', UpStr(s));
  While (i <> 0) do
   Begin
   Delete(s, i, 2);
   Insert(inFile, s, i);
   i := Pos('%I', UpStr(s));
   End;
  i := Pos('%O', UpStr(s));
  While (i <> 0) do
   Begin
   Delete(s, i, 2);
   Insert(out_fname, s, i);
   i := Pos('%O', UpStr(s));
   End;

  GetDir(0, OldDir);
  ChDir(inDir);
{$IfDef UNIX}
  Shell(s);
{$Else}
  SwapVectors;
  Exec(GetEnv('COMSPEC'), '/c '+s);
  SwapVectors;
{$EndIf}
  ChDir(OldDir);
  End;
 End;


Procedure CreatePrioSem;
Var
 f: Text;

 Begin
 Assign(f, Cfg^.PrioSem);
 {$I-} ReWrite(f); {$I+}
 If (IOResult <> 0) then
  Begin
  LogSetCurLevel(lh, 1);
  LogWriteLn(lh, 'Could not create semaphore "'+Cfg^.PrioSem+'"!');
  End
 Else
  Begin
  WriteLn(f, ShortName);
  Close(f);
{$IfDef UNIX}
  ChMod(Cfg^.PrioSem, FilePerm);
{$EndIf}
  End;
 End;


Procedure ParseLinks(var Ini: IniObj);
Var
 i: Word;
 s: String255;

  Begin
  Cfg^.NumLinks := 0;
  With Ini do
    Begin
    If GetSecNum('LINKS') = 0 then Exit;
    SetSection('LINKS');
    I := 0;
    While UpStr(ReSecEnName) = 'LINK' do
      begin
      Inc(i);
      If (i > 1) then
        Begin
        New(CurLink^.Next);
        CurLink^.Next^.Prev := CurLink;
        CurLink := CurLink^.Next;
        CurLink^.Next := Nil;
        End
      Else
        Begin
        New(Cfg^.Links);
        CurLink := Cfg^.Links;
        CurLink^.Next := Nil;
        CurLink^.Prev := Nil;
        End;
      s := ReSecEnValue;
      CurLink^.Name := s;
      If Debug then WriteLn('Link "', CurLink^.Name, '"');
      With CurLink^ do
        Begin
        EMail := '';
        Subject := '';
        Method := '';
        With Addr do
          Begin
          Zone := 0;
          Net := 0;
          Node := 0;
          Point := 0;
          Domain := '';
          End;
        End;

      If not SetNextOpt then Break;
      While UpStr(ReSecEnName) <> 'LINK' do
        Begin
        s := UpStr(ReSecEnName);
        If  s = 'EMAIL' then
          Begin
          CurLink^.EMail := ReSecEnValue;
          If Debug then WriteLn('EMail: ', CurLink^.EMail);
          End
        Else If s = 'ADDR' then
          Begin
          Str2Addr(ReSecEnValue, CurLink^.Addr);
          If Debug then WriteLn('Addr: ', Addr2Str(CurLink^.Addr));
          End
        Else If s = 'SUBJECT' then
          Begin
          CurLink^.Subject := ReSecEnValue;
          If Debug then WriteLn('Subject: ', CurLink^.Subject);
          End
        Else If s = 'METHOD' then
          Begin
          CurLink^.Method := UpStr(ReSecEnValue);
          If Debug then WriteLn('Method: ', CurLink^.Method);
          End
        Else
          Begin
          LogWriteLn(lh, 'Unknown or out of sequence keyword: '+ ReSecEnName);
          End;
        If not SetNextOpt then Break;
        End;
      end;
    Cfg^.NumLinks := i;
    If Debug then
     Begin
     WriteLn('<Return>');
     ReadLn;
     End;
    End;
  End;

Procedure ParseEncoding(var Ini: IniObj);
Var
 i: Word;
 s: String255;

  Begin
  Cfg^.NumEnCoder := 0; Cfg^.NumDeCoder := 0;
  With Ini do
   Begin
   If GetSecNum('ENCODING') = 0 then Exit;
   SetSection('ENCODING');
    Repeat
    If (UpStr(ReSecEnName) = 'ENCODER') then
     Begin
     Inc(Cfg^.NumEnCoder);
     New(Cfg^.EnCoders[Cfg^.NumEnCoder]);
     With Cfg^.EnCoders[Cfg^.NumEnCoder]^ do
      Begin
      s := ReSecEnValue;
      Name := UpStr(Copy(s, 1, Pos(',', s)-1));
      Delete(s, 1, Pos(',', s));
      OutFile := Copy(s, 1, Pos(',', s)-1);
      Delete(s, 1, Pos(',', s));
      Command := s;
      End;
     End
    Else If (UpStr(ReSecEnName) = 'DECODER') then
     Begin
     Inc(Cfg^.NumDeCoder);
     New(Cfg^.DeCoders[Cfg^.NumDeCoder]);
     With Cfg^.DeCoders[Cfg^.NumDeCoder]^ do
      Begin
      s := ReSecEnValue;
      Name := UpStr(Copy(s, 1, Pos(',', s)-1));
      Delete(s, 1, Pos(',', s));
      Command := s;
      End;
     End
    Else
     Begin
     LogWriteLn(lh, 'Unknown or out of sequence keyword: '+ReSecEnName);
     End;
    Until not SetNextOpt;

   If Debug then
    Begin
    WriteLn('<Return>');
    ReadLn;
    End;
   End;
  End;


Function ParseCfg: Boolean;
Var
 Ini: IniObj;
 Dir: DirStr;
 s: String;

 Begin
 ParseCfg := False;
 If (CfgName = '') then CfgName := AddDirSep(GetEnv(UpStr(ShortName)))+
  ShortName+'.cfg';
 If not FileExist(CfgName) then Begin FSplit(ParamStr(0), Dir, s, s);
  CfgName := Dir+ShortName+'.cfg'; End;
 If not FileExist(CfgName) then CfgName := '.'+DirSep+ShortName+'.cfg';
 If not FileExist(CfgName) then WriteLn('Could not find '+ShortName+'.cfg!')
 Else
  Begin
  Ini.Init(CfgName);
  Cfg^.LogFile := Ini.ReadEntry('GENERAL', 'LOG');
  Cfg^.LogLevel := StrToInt(Ini.ReadEntry('GENERAL', 'LOGLEVEL'));
  Cfg^.ScrLevel := StrToInt(Ini.ReadEntry('GENERAL', 'SCRLEVEL'));
  Cfg^.MailBox := Ini.ReadEntry('GENERAL', 'MAILBOX');
  Str2Addr(Ini.ReadEntry('GENERAL', 'GATEADDR'), Cfg^.GateAddr);
  Str2Addr(Ini.ReadEntry('GENERAL', 'TOADDR'), Cfg^.ToAddr);
  Cfg^.NetMail := Ini.ReadEntry('GENERAL', 'NETMAIL');
  Cfg^.SendProgram := Ini.ReadEntry('GENERAL', 'SENDPROGRAM');
  Cfg^.MQueue := AddDirSep(Ini.ReadEntry('GENERAL', 'MQUEUE'));
  Cfg^.Tmp := AddDirSep(Ini.ReadEntry('GENERAL', 'TMPDIR'));
  Cfg^.Prio := StrToInt(Ini.ReadEntry('GENERAL', 'PRIORITY'));
  Cfg^.Host := Ini.ReadEntry('GENERAL', 'HOSTNAME');
  Cfg^.Org := Ini.ReadEntry('GENERAL', 'ORGANIZATION');
  Cfg^.Domain := Ini.ReadEntry('GENERAL', 'DOMAIN');
  Cfg^.PKT_EMail := Ini.ReadEntry('GENERAL', 'PKT_EMAIL');
  Cfg^.PKT_Inbound := Ini.ReadEntry('GENERAL', 'PKT_INBOUND');
  Cfg^.PrioSem := Ini.ReadEntry('GENERAL', 'PRIOSEM');
  s := UpStr(Ini.ReadEntry('GENERAL', 'PKT_MAILER'));
  If (s = 'BT') then Cfg^.PKT_Mailer := cCM_BT
  Else Cfg^.PKT_Mailer := 0;
  Cfg^.PKT_BT_Outbound := Ini.ReadEntry('GENERAL', 'PKT_BT_OUTBOUND');
  s := UpStr(Ini.ReadEntry('GENERAL', 'SENDMETHOD'));
  If (s = 'PROGRAM') then Cfg^.SendMethod := cSM_Program
  Else If (s = 'SENDMAILQUEUE') then Cfg^.SendMethod := cSM_SendMailQueue
  Else Cfg^.SendMethod := 0;
  ParseLinks(Ini);
  ParseEncoding(Ini);
  Ini.Done;
  If (Cfg^.LogLevel < 0) then Cfg^.LogLevel := Abs(Cfg^.LogLevel);
  If (Cfg^.ScrLevel < 0) then Cfg^.ScrLevel := Abs(Cfg^.ScrLevel);
  If (Cfg^.LogLevel > 5) then Cfg^.LogLevel := 5;
  If (Cfg^.ScrLevel > 5) then Cfg^.ScrLevel := 5;
  If (Cfg^.LogFile = '') then WriteLn('No logfile specified!')
  Else If (Cfg^.MailBox = '') then WriteLn('No mailbox specified!')
  Else If (Cfg^.NetMail = '') then WriteLn('No netmail area specified!')
  Else If (Cfg^.SendMethod = 0) then WriteLn('No sendmethod specified!')
  Else If (Cfg^.Tmp = '') then WriteLn('No path for temporary files specified!')
  Else If (Cfg^.Host = '') then WriteLn('No hostname specified!')
  Else If (Cfg^.Domain = '') then WriteLn('No domain specified!')
  Else ParseCfg := True;
  Case Cfg^.SendMethod of
   cSM_Program: If (Cfg^.SendProgram = '') then WriteLn('No send-program specified!');
   cSM_SendMailQueue: IF (Cfg^.MQueue = '') then WriteLn('No sendmail-queue specified!');
   End;
  End;
 End;

Procedure Init;
Var
 s, sU: String255;
 i: LongInt;

 Begin
 WriteLn(ShortName, Version);
 WriteLn;
 Debug := False;
 CfgName := '';
 If (ParamCount > 1) then
  Begin
  Syntax;
  Halt(1);
  End;
 If (ParamCount > 0) then
  Begin
  For i := 1 to ParamCount do
   Begin
   s := ParamStr(i);
   sU := UpStr(s);
   If (sU = '-D') then Debug := True
   Else If (Pos('-C', sU) = 1) then CfgName := KillSpcs(Copy(s, 3, Length(s)-2));
   End;
  End;
 Randomize;
 New(Cfg);
 If not ParseCfg then
  Begin
  Dispose(Cfg);
  Halt(2);
  End;
 s := ShortName; s := s + Version;
 lh := OpenLog(Binkley, Cfg^.LogFile, UpStr(ShortName), s);
 If (lh = 0) then
  Begin
  WriteLn('Could not open "'+Cfg^.LogFile+'"!');
  Dispose(Cfg);
  Halt(3);
  End;
 LogSetScrLevel(lh, Cfg^.ScrLevel);
 LogSetLogLevel(lh, Cfg^.LogLevel);
 LogSetCurLevel(lh, 1);
 Case UpCase(Cfg^.NetMail[1]) of
  'H': NM := New(HudsonMsgPtr, Init);
  'S': NM := New(SqMsgPtr, Init);
  'F': NM := New(FidoMsgPtr, Init);
  'E': NM := New(EzyMsgPtr, Init);
  Else
   Begin
   LogWriteLn(lh, 'Invalid type for netmail area!');
   CloseLog(lh);
   Dispose(Cfg);
   Halt(3);
   End;
  End;
 NM^.SetMsgPath(Copy(Cfg^.NetMail, 2, Length(Cfg^.NetMail) - 1));
 If (NM^.OpenMsgBase <> 0) then
  Begin
  LogWriteLn(lh, 'Couldn''t open netmail area!');
  CloseLog(lh);
  Dispose(NM, Done);
  Dispose(Cfg);
  Halt(4);
  End;
  If (UpCase(Cfg^.NetMail[1]) = 'F') then FidoMsgPtr(NM)^.SetDefaultZone(0);
  NM^.SetMailType(mmtNetMail);
 End;

Procedure Done;
 Begin
 If (NM^.CloseMsgBase <> 0) then
  Begin
  LogSetCurLevel(lh, 1);
  LogWriteLn(lh, 'Could not close netmail area!');
  End;
 CloseLog(lh);
 Dispose(NM, Done);
 Dispose(Cfg);
 End;


Procedure CreateFidoMail(Sender, _To, Subject, MsgID, DateWritten, DateRcvd: String);
Var
 DWritten, DRcvd: TimeTyp;
{$IfDef VP}
 i: LongInt;
{$Else}
 i: Integer;
{$EndIf}
 s: String;
 DT: TimeTyp;
 TodayDT: TimeTyp;
 TempF: Text;
 MKAddr: AddrType;

 Begin
 {handle addresses}
 If (Sender[1] = '<') then {strip "<" and ">" around address}
  Begin
  Delete(Sender, 1, 1);
  If (Sender[Length(Sender)] = '>') then Delete(Sender, Length(Sender), 1);
  End;
 If (_To[1] = '<') then {strip "<" and ">" around address}
  Begin
  Delete(_To, 1, 1);
  If (_To[Length(_To)] = '>') then Delete(_To, Length(_To), 1);
  End;

 {handle dates}
 {           123456789012345678901234 }
 {DateRcvd: "Tue Sep 29 17:41:20 1998"}
 Today(TodayDT);
 if (TodayDT.Year < 99) then TodayDT.Year := TodayDT.Year+2000
 Else If (TodayDT.Year < 1999) then TodayDT.Year := TodayDT.Year+1900;
 DateRcvd := KillLeadingSpcs(DateRcvd);
 s := Copy(DateRcvd, 5, 3); {copy month}
 DRcvd.Month := TodayDT.Month; {if month is invalid set it to current month}
 For i := 1 to 12 do If (Months3Eng[i] = s) then DRcvd.Month := i;
 Val(Copy(DateRcvd, 9, 2), DRcvd.Day, i); {get Day}
 If (i <> 0) or (DRcvd.Day < 1) or (DRcvd.Day > 31) then
  DRcvd.Day := TodayDT.Day; {set day to today if invalid (simple check)}
 Val(Copy(DateRcvd, 12, 2), DRcvd.Hour, i); {get hour}
 If (i <> 0) or (DRcvd.Hour < 0) or (DRcvd.Hour > 23) then
  DRcvd.Hour := 0; {set hour to 0 if invalid}
 Val(Copy(DateRcvd, 15, 2), DRcvd.Min, i); {get minute}
 If (i <> 0) or (DRcvd.Min < 0) or (DRcvd.Min > 59) then
  DRcvd.Min := 0; {set minute to 0 if invalid}
 Val(Copy(DateRcvd, 18, 2), DRcvd.Sec, i); {get second}
 If (i <> 0) or (DRcvd.Sec < 0) or (DRcvd.Sec > 59) then
  DRcvd.Sec := 0; {set second to 0 if invalid}
 Val(Copy(DateRcvd, 21, 4), DRcvd.Year, i); {get year}
 If (i <> 0) or (DRcvd.Year < 1999) then
  DRcvd.Year := TodayDT.Year; {set year to current year if invalid}

 {DateWritten: "Mon, 14 Sep 1998 17:15:46 +0200"}
 DateWritten := KillLeadingSpcs(DateWritten);

 {skip DOW}
 Delete(DateWritten, 1, Pos(' ', DateWritten));

 Val(Copy(DateWritten, 1, 2), DWritten.Day, i); {get Day}
 If (i <> 0) or (DWritten.Day < 1) or (DWritten.Day > 31) then
  DWritten.Day := DRcvd.Day; {set to receive day if invalid}
 Delete(DateWritten, 1, Pos(' ', DateWritten));

 DWritten.Month := DRcvd.Month;
 s := Copy(DateWritten, 1, 3); {copy month}
 For i := 1 to 12 do If (Months3Eng[i] = s) then DWritten.Month := i;
 Delete(DateWritten, 1, Pos(' ', DateWritten));

 Val(Copy(DateWritten, 1, Pos(' ', DateWritten)-1), DWritten.Year, i); {get year}
 If (i <> 0) then DWritten.Year := DRcvd.Year
 Else if (DWritten.Year < 1900) then
  Begin
  If (DWritten.Year < 98) then DWritten.Year := DWritten.Year + 2000
  Else DWritten.Year := DWritten.Year + 1900;
  End;
 Delete(DateWritten, 1, Pos(' ', DateWritten));

 Val(Copy(DateWritten, 1, pos(':', DateWritten)-1), DWritten.Hour, i); {get hour}
 If (i <> 0) or (DWritten.Hour < 0) or (DWritten.Hour > 23) then
  DWritten.Hour := DRcvd.Hour;
 Delete(DateWritten, 1, Pos(':', DateWritten));

 Val(Copy(DateWritten, 1, pos(':', DateWritten)-1), DWritten.Min, i); {get minute}
 If (i <> 0) or (DWritten.Min < 0) or (DWritten.Min > 59) then
  DWritten.Min := DRcvd.Min;
 Delete(DateWritten, 1, Pos(':', DateWritten));

 If (Pos(' ', DateWritten) > 0) then
  Val(Copy(DateWritten, 1, pos(' ', DateWritten)-1), DWritten.Sec, i) {get second}
 Else
  Val(DateWritten, DWritten.Sec, i); {get second}
 If (i <> 0) or (DWritten.Sec < 0) or (DWritten.Sec > 59) then
  DWritten.Sec := DRcvd.Sec;

 {process MsgID}
 MsgID := MsgID + ' ' + GetMsgID;

 {create mail}
 With NM^ do
  Begin
  StartNewMsg;
  SetFrom(Sender);
  SetKillSent(False);
  SetTo(_To);
  TNetAddr2MKAddr(Cfg^.ToAddr, MKAddr);
  SetDest(MKAddr);
  TNetAddr2MKAddr(Cfg^.GateAddr, MKAddr);
  SetOrig(MKAddr);
  SetLocal(False);
  SetPriv(True);
  SetSubj(Subject);
  DT := DWritten;
  If (DT.Year > 100) then DT.Year := DT.Year mod 100;
  Now(DT);
  If (DT.Month > 9) then s := IntToStr(DT.Month) + '-'
  Else s := '0' + IntToStr(DT.Month) + '-';
  If (DT.Day > 9) then s := s + IntToStr(DT.Day) + '-'
  Else s := s + '0' + IntToStr(DT.Day) + '-';
  If (DT.Year > 9) then s := s + IntToStr(DT.Year)
  Else s := s + '0' + IntToStr(DT.Year);
  SetDate(s);
  If (DT.Hour > 9) then s := IntToStr(DT.Hour) + ':'
  Else s := '0' + IntToStr(DT.Hour) + ':';
  If (DT.Min > 9) then s := s + IntToStr(DT.Min)
  Else s := s + '0' + IntToStr(DT.Min);
  SetTime(s);
  DoStringLn(#01'MSGID: '+MsgID);

  Assign(TempF, Cfg^.Tmp+ShortName+'.tmp');
  ReSet(TempF);
  While not EOF(TempF) do
   Begin
   ReadLn(TempF, s);
   DoStringLn(s);
   End;
  Close(TempF);
  DoStringLn('');
  DoStringLn('--- '+ShortName+Version);
  If (WriteMsg <> 0) then
   Begin
   LogSetCurLevel(lh, 1);
   LogWriteLn(lh, 'Couldn''t write netmail!');
   End;
  End;

 LogSetCurLevel(lh, 3);
 LogWriteLn(lh, 'From: "'+Sender+'"');
 LogWriteLn(lh, 'To:   "'+_To+'"');
 LogWriteLn(lh, 'Subj: "'+Subject+'"');
 LogSetCurLevel(lh, 4);
 LogWriteLn(lh, 'MsgID "'+MsgID+'", written "'+Date2Str(DWritten)+' '+Time2Str(DWritten)+
  '", rcvd "'+Date2Str(DRcvd)+' '+Time2Str(DRcvd)+'"');
 LogSetCurLevel(lh, 3);
 LogWriteLn(lh, '');
 Erase(TempF);
 End;


Procedure CreateEMail(Sender, Rcpt, Subject, BodyFile: String);
{creates EMail in sendmail queue or via program}
{for description of queue files see format.txt}
Var
 f: Text;
 s: String;
 DT: TimeTyp;
 i: LongInt;
 fname: String;
 SenderUser, SenderHost: String;

 Begin
 SenderUser := Copy(Sender, 1, Pos('@', Sender)-1);
 SenderHost := Copy(Sender, Pos('@', Sender)+1, Length(Sender)-Pos('@', Sender));
 Today(DT); Now(DT);
 If (DT.Year < 99) then DT.Year := DT.Year+2000 Else
  If (DT.Year < 1900) then DT.Year := DT.Year+1900;
 Case Cfg^.SendMethod of
  cSM_Program:
   Begin
   s := Cfg^.SendProgram;
   i := Pos('%u', s);
   While (i <> 0) do
    Begin
    Delete(s, i, 2);
    Insert(SenderUser, s, i);
    i := Pos('%u', s);
    End;
   i := Pos('%h', s);
   While (i <> 0) do
    Begin
    Delete(s, i, 2);
    Insert(SenderHost, s, i);
    i := Pos('%h', s);
    End;
   i := Pos('%s', s);
   While (i <> 0) do
    Begin
    Delete(s, i, 2);
    Insert(Subject, s, i);
    i := Pos('%s', s);
    End;
   i := Pos('%r', s);
   While (i <> 0) do
    Begin
    Delete(s, i, 2);
    Insert(Rcpt, s, i);
    i := Pos('%r', s);
    End;
   i := Pos('%f', s);
   While (i <> 0) do
    Begin
    Delete(s, i, 2);
    Insert(BodyFile, s, i);
    i := Pos('%f', s);
    End;
   i := Pos('%;', s);
   While (i <> 0) do
    Begin
    Delete(s, i, 1);
    i := Pos('%;', s);
    End;

{$IfDef OS2}
 {$IfDef VIRTUALPASCAL}
    Exec(GetEnv('COMSPEC'), '/C '+s);
    i := DOSExitCode;
 {$Else}
    i := DOSExitCode(Exec(GetEnv('COMSPEC'), '/C '+s));
 {$EndIF}
{$Else}
 {$IfDef UNIX}
    i := Shell(s);
 {$Else}
    SwapVectors;
    Exec(GetEnv('COMSPEC'), '/C '+s);
    i := DOSExitCode;
    SwapVectors;
 {$EndIf}
{$EndIf}
   If (i <> 0) then
    Begin
    LogSetCurLevel(lh, 1);
    LogWriteLn(lh, 'program "'+s+'" returned error #'+IntToStr(i)+'!');
    End;
   End;
  cSM_SendMailQueue:
   Begin
   i := 0;
    Repeat
    fname := Char(Byte('A')+DT.Hour) + Char(Byte('A')+Random(26)) + Char(Byte('A')+Random(26));
    fname := fname + Char(Byte('0')+Random(10)) + Char(Byte('0')+Random(10)) +
     Char(Byte('0')+Random(10))+'.'+Char(Byte('0')+Random(10)) +
     Char(Byte('0')+Random(10));
    Inc(i);
    Until (not (FileExist(Cfg^.MQueue+'qf'+fname) or
     FileExist(Cfg^.MQueue+'tf'+fname))) or (i > 1000);
   If FileExist(Cfg^.MQueue+'qf'+fname) then
    Begin
    LogSetCurLevel(lh, 1);
    LogWriteLn(lh, 'Not enough free places in sendmail queue (tried 1000 times)!')
    End
   Else
    Begin
    If not CopyFile(BodyFile, Cfg^.MQueue+'df'+fname) then
     Begin
     LogSetCurLevel(lh, 1);
     LogWriteLn(lh, 'Could not copy "'+BodyFile+'" to "'+Cfg^.MQueue+'df'+fname+'"!')
     End
    Else
     Begin
     Assign(f, Cfg^.MQueue+'tf'+fname);
     {$I-} ReWrite(f); {$i+}
     If (IOResult <> 0) then
      Begin
      LogSetCurLevel(lh, 1);
      LogWriteLn(lh, 'Could not create "'+Cfg^.MQueue+'tf'+fname+'"!')
      End
     Else
      Begin
      WriteLn(f, 'P'+IntToStr(Cfg^.Prio));
      WriteLn(f, 'T'+DTToUnixStr(DT));
      WriteLn(f, 'Ddf'+fname);
      WriteLn(f, 'Mplaced in queue by '+ShortName+Version);
      WriteLn(f, 'S<'+Sender+'>');
      WriteLn(f, 'HReturn-path: <'+Sender+'>');
      s := WkDays3Eng[DT.DayOfWeek]+' '+Months3Eng[DT.Month]+' '+
       IntToStr(DT.Day)+' '+Time2Str(DT)+' '+IntToStr(DT.Year);
      WriteLn(f, 'HReceived: by '+Cfg^.Host+' ('+ShortName+Version+') id '+
       fname+'; '+s);
      WriteLn(f, 'HFrom: '+Sender);
      WriteLn(f, 'HDate: '+s);
      WriteLn(f, 'HX-Mailer: '+ShortName+Version);
      WriteLn(f, 'HMessage-id: <'+DTToUnixStr(DT)+'.'+fname+'@'+Cfg^.Domain+'>');
      WriteLn(f, 'HOrganization: '+Cfg^.Org);
      WriteLn(f, 'HSubject: '+Subject);
      WriteLn(f, 'HTo: '+Rcpt);
      WriteLn(f, 'R<'+Rcpt+'>');
      Close(f);
  {$IfDef UNIX}
      ChMod(Cfg^.MQueue+'tf'+fname, FilePerm);
  {$EndIf}
      {$I-} Rename(f, Cfg^.MQueue+'qf'+fname); {$I+}
      If (IOResult <> 0) then
       Begin
       LogSetCurLevel(lh, 1);
       LogWriteLn(lh, 'Could not rename "'+Cfg^.MQueue+
        'tf'+fname+'" to "'+Cfg^.MQueue+'qf'+fname+'"!');
       End;
      End;
     End;
    End;
   End
  Else
   Begin
   LogSetCurLevel(lh, 1);
   LogWriteLn(lh, 'Invalid SendMethod!');
   End;
  End;
 End;


Procedure RFC2FTN_PKT;
Var
 MKAddr: AddrType;
 A1: TNetAddr;
 f: Text;
 s: String;

 Begin
 If (Cfg^.NumLinks > 0) then
  Begin
  LogSetCurLevel(lh, 4);
  LogWriteLn(lh, 'Scanning EMails for PKTs');
  Assign(f, Cfg^.Tmp+ShortName+'.tmp');
  With NM^ do
   Begin
   SeekFirst(1);
   While SeekFound do
    Begin
    InitMsgHdr;
    Write('                             '#13'Msg #', GetMsgDisplayNum);
    GetOrig(MKAddr);
    MKAddr2TNetAddr(MKAddr, A1);
    If CompAddr(A1, Cfg^.GateAddr) and (not IsRcvd) then
     Begin
     CurLink := Cfg^.Links;
     While (CurLink <> NIL) do
      Begin
      If (UpStr(Cfg^.PKT_EMail) = UpStr(GetTo)) then
       If (UpStr(CurLink^.EMail) = UpStr(GetFrom)) then
       If (UpStr(CurLink^.Subject) = UpStr(GetSubj)) then
       Begin
       WriteLn;
       LogSetCurLevel(lh, 3);
       LogWriteLn(lh, 'PKT-EMail from "'+CurLink^.EMail+'" ('+
        Addr2Str(CurLink^.Addr)+')');
       {$I-} ReWrite(f); {$I+}
       If (IOResult <> 0) then
        Begin
        LogSetCurLevel(lh, 1);
        LogWriteLn(lh, 'Could not create "'+Cfg^.Tmp+ShortName+'.tmp"!');
        End
       Else
        Begin
        SetRcvd(True);
        ReWriteHdr;
        MsgTxtStartUp;
        While not EOM do
         Begin
         s := GetString;
         If (s[1] <> #1) then WriteLn(f, s);
         End;
        Close(f);
{$IfDef UNIX}
        ChMod(Cfg^.Tmp+ShortName+'.tmp', FilePerm);
{$EndIf}
        Decode(CurLink^.Method, Cfg^.Tmp+ShortName+'.tmp');
        Erase(f);
        DeleteMsg;
        End; {If (IOResult <> 0)}
       End; {If (UpStr(Cfg^.PKT_EMail) = UpStr(GetTo)) and ...}
      CurLink := CurLink^.Next;
      End; {While (CurLink <> NIL)}
     End; {If CompAddr(A1, Cfg^.GateAddr) and (not IsRcvd)}
    SeekNext;
    End; {While SeekFound}
   WriteLn;
   End; {With NM^}
  End; {if (Cfg^.NumLinks > 0)}
 End;


Procedure ProcessMailBox(fname: String);
Var
 MailBoxF, TempF: Text;
 Line: String;
 Sender, _To, Subject, MsgID, DateWritten, DateRcvd: String;
 InHeader: Boolean;
 p: Byte;

{
first line (sender, sent on date/time):
"From kintscher@dupp.de  Tue Sep 29 17:41:20 1998"
To-Line: (Receiver)
"To: <members@ldknet.org>"
Subject-line:
"Subject: Passwort aendern beim Mailserver"
Message-ID:
"Message-ID: <117C5BF85862D111BE2B006097314EA303CF90@NTSERVER1>"
Date written:
"Date: Mon, 14 Sep 1998 17:15:46 +0200"
Delivered-To (receiver):
"Deliver-To: <something> Sascha.Silbe@ldknet.org"
}
 Begin
 LogSetCurLevel(lh, 4);
 LogWriteLn(lh, 'Scanning mailbox "'+fname+'"');
 Assign(MailBoxF, fname);
 Assign(TempF, Cfg^.Tmp+ShortName+'.tmp');
 {$I-} ReSet(MailBoxF); {$I+}
 If (IOResult <> 0) then Exit;
 If not EOF(MailBoxF) then
  Begin
  While not EOF(MailBoxF) do
   Begin
   ReadLn(MailBoxF, Line);
   While (Pos('From ', Line) = 1) do {begin of mail}
    Begin
    {process first line}
    Delete(Line, 1, 5); {remove "From "}
    p := Pos(' ', Line);
    Sender := Copy(Line, 1, p-1);
    Delete(Line, 1, p+1); {remove sender+"  "}
    DateRcvd := Line;

    {init optional parameters}
    _To := '';
    Subject := '';
    MsgID := '';
    DateWritten := '';

    ReWrite(TempF);
    WriteLn(TempF, #01'Sender: '+Sender);
    InHeader := True;

    If not EOF(MailBoxF) then
     Begin
      Repeat
      ReadLn(MailBoxF, Line);
      If ((Line = '') and InHeader) then
       Begin
       InHeader := False;
       If not EOF(MailBoxF) then ReadLn(MailBoxF, Line); {skip empty line between Header and Body}
       {add some infos to fido-mail}
       WriteLn(TempF, #1'REPLYADDR '+Sender);
       WriteLn(TempF, #1'REPLYTO '+Addr2Str(Cfg^.GateAddr)+' '+Sender);
       WriteLn(TempF, 'FROM: ', Sender);
       WriteLn(TempF, 'TO: ', _To);
       End;
      If InHeader then Line := KillLeadingSpcs(Line);
      If (Pos('From ', Line) <> 1) then {next mail?}
       Begin
       If InHeader then {check for known headerlines}
        Begin
        If ((Pos('To:', Line) = 1) and (_To = '')) then _To := KillSpcs(Copy(Line, 4, Length(Line)-3))
        Else If (Pos('From:', Line) = 1) then Sender := KillSpcs(Copy(Line, 6, Length(Line)-5))
        Else If ((Pos('Subject:', Line) = 1) and (Subject = '')) then Subject := KillSpcs(Copy(Line, 9, Length(Line)-8))
        Else If ((Pos('Message-ID:', Line) = 1) and (MsgID = '')) then MsgID := KillSpcs(Copy(Line, 12, Length(Line)-11))
        Else If ((Pos('Date:', Line) = 1) and (DateWritten = '')) then DateWritten := KillSpcs(Copy(Line, 6, Length(Line)-5));
        WriteLn(TempF, #01+Line);
        End
       Else
        Begin
        If (Pos('--- ', Line) = 1) then Line[2] := '+'; {invalidate fake tearline}
        WriteLn(TempF, Line);
        End;
       End;
      Until (Pos('From ', Line) = 1) or EOF(MailBoxF);
     End;

    Close(TempF);
{$IfDef UNIX}
    ChMod(Cfg^.Tmp+ShortName+'.tmp', FilePerm);
{$EndIf}
    If (_To = '') then _To := Copy(fname, LastPos(DirSep, fname)+1,
     Length(fname)-LastPos(DirSep, fname)-1)+'@'+Cfg^.Domain;

    {use sender as MsgID if none is given}
    If (MsgID = '') then MsgID := '<'+Sender+'>';
    {process mail}
    CreateFidoMail(Sender, _To, Subject, MsgID, DateWritten, DateRcvd);
    End;
   End;
  End;
 Close(MailBoxF);
 Erase(MailBoxF);
 End;

Procedure ScanNetMail;
Var
 MKAddr: AddrType;
 A1: TNetAddr;
 Sender, Rcpt: String;
 f: Text;
 s: String;
 Prio: Boolean;
 LineNr: Byte;

 Begin
 Prio := False;
 LogSetCurLevel(lh, 4);
 LogWriteLn(lh, 'Scanning netmail area "'+Cfg^.Netmail+'"');
 Assign(f, Cfg^.Tmp+ShortName+'.tmp');
 With NM^ do
  Begin
  SeekFirst(1);
  While SeekFound do
   Begin
   InitMsgHdr;
   Write('                             '#13'Msg #', GetMsgDisplayNum);
   GetDest(MKAddr);
   MKAddr2TNetAddr(MKAddr, A1);
   If CompAddr(A1, Cfg^.GateAddr) and (not IsRcvd) then
    Begin
    WriteLn;
    {$I-} ReWrite(f); {$I+}
    If (IOResult <> 0) then
     Begin
     LogSetCurLevel(lh, 1);
     LogWriteLn(lh, 'Could not create "'+Cfg^.Tmp+ShortName+'.tmp"!');
     End
    Else
     Begin
     SetSent(True);
     ReWriteHdr;
     MsgTxtStartUp;
     If (UpStr(GetTo) <> 'UUCP') then Rcpt := GetTo
     else Rcpt := 'unknown';
     Sender := Translate(GetFrom, ' ', '_');
     If (Pos('@', Sender) = 0) then Sender := Sender + '@'+Cfg^.Domain;
     LineNr := 0;
     While not EOM do
      Begin
      s := GetString;
      If (s[1] <> #1) then Inc(LineNr);
      If ((Pos('TO:', UpStr(s)) = 1) and (LineNr < 4)) then
       Begin
       Rcpt := KillSpcs(Copy(s, 4, Length(s)-3));
       End
      Else If ((Pos('FROM:', UpStr(s)) = 1) and (LineNr < 4)) then
       Begin
       Sender := KillSpcs(Copy(s, 6, Length(s)-5));
       End
      Else If (s[1] <> #1) then WriteLn(f, s);
      End;
     Close(f);
{$IfDef UNIX}
     ChMod(Cfg^.Tmp+ShortName+'.tmp', FilePerm);
{$EndIf}
     If IsCrash then
      Begin
      LogSetCurLevel(lh, 2);
      LogWriteLn(lh, 'From: "'+Sender+'"');
      LogWriteLn(lh, 'To:   "'+Rcpt+'"');
      LogWriteLn(lh, 'Subj: "'+GetSubj+'"');
      LogWriteLn(lh, '*** priority mail ***');
      End
     Else
      Begin
      LogSetCurLevel(lh, 3);
      LogWriteLn(lh, 'From: "'+Sender+'"');
      LogWriteLn(lh, 'To:   "'+Rcpt+'"');
      LogWriteLn(lh, 'Subj: "'+GetSubj+'"');
      End;
     Prio := Prio or IsCrash;
     CreateEMail(Sender, Rcpt, GetSubj, Cfg^.Tmp+ShortName+'.tmp');
     Erase(f);
     If IsFAttach then
      Begin
      LogSetCurLevel(lh, 3);
      LogWriteLn(lh, 'encoding attach as UUE');
      Encode('UUE', GetSubj, s);
      CreateEMail(Sender, Rcpt, GetSubj, s);
      End;
     LogWriteLn(lh, '');
     If IsKillSent then DeleteMsg;
     End;
    End;
   SeekNext;
   End;
  WriteLn;
  End;
 If (Prio and (Cfg^.PrioSem <> '')) then CreatePrioSem;
 End;


Procedure PKT2RFC(fn: String);
Var
 s: String;

 Begin
 LogSetCurLevel(lh, 3);
 LogWriteLn(lh, 'sending "'+fn+'" to "'+CurLink^.EMail+'" ('+
  Addr2Str(CurLink^.Addr)+')');
 s := '';
 Encode(CurLink^.Method, fn, s);
 CreateEMail(Cfg^.PKT_EMail, CurLink^.EMail, CurLink^.Subject, s);
 DelFile(s);
 End;

Procedure ScanBTFlo(fn: String);
Var
 f: Text;
 Line: String;
 s: String;

 Begin
 Assign(f, fn);
 {$I-} ReSet(f); {$I+}
 If (IOResult <> 0) then
  Begin
  LogSetCurLevel(lh, 1);
  LogWriteLn(lh, 'Could not open "'+fn+'"!');
  End
 Else
  Begin
  While not EOF(f) do
   Begin
   ReadLn(f, Line);
   Case UpCase(Line[1]) of
    '^':
     Begin
     s := Copy(Line, 2, Length(Line)-1);
     PKT2RFC(s);
     If not DelFile(s) then
      Begin
      LogSetCurLevel(lh, 1);
      LogWriteLn(lh, 'Could not delete file "'+s+'"!');
      End;
     End;
    '#':
     Begin
     s := Copy(Line, 2, Length(Line)-1);
     PKT2RFC(s);
     If not TruncFile(s) then
      Begin
      LogSetCurLevel(lh, 1);
      LogWriteLn(lh, 'Could not truncate file "'+s+'"!');
      End;
     End;
    Else
     Begin
     PKT2RFC(Line);
     End;
    End;
   End;
  {$I-} Close(f); {$I+}
  If (IOResult <> 0) then
   Begin
   LogSetCurLevel(lh, 1);
   LogWriteLn(lh, 'Could not close "'+fn+'"!');
   End;
  {$I-} Erase(f); {$I+}
  If (IOResult <> 0) then
   Begin
   LogSetCurLevel(lh, 1);
   LogWriteLn(lh, 'Could not delete "'+fn+'"!');
   End;
  End;
 End;

Procedure ScanBTMail(fn: String; Dir: String);
Var
 s: String;

 Begin
  Repeat
  s := Dir+DirSep+RandName8+'.pkt';
  Until not FileExist(s);
 If not MoveFile(fn, s) then
  Begin
  LogSetCurLevel(lh, 1);
  LogWriteLn(lh, 'Could not rename "'+fn+'" to "'+s+'"!');
  End
 Else
  Begin
  PKT2RFC(s);
  DelFile(s);
  End;
 End;

Procedure ScanBTOut(Link: PLink);
Var
 FlowName: String;
 Dir: String;
 s: String;

 Begin
 If ((Link^.Addr.Domain = Cfg^.GateAddr.Domain) or
  (Link^.Addr.Domain = '') or (Cfg^.GateAddr.Domain = '')) then
  Begin
  If (Link^.Addr.Zone <> Cfg^.GateAddr.Zone) then
   FlowName := Cfg^.PKT_BT_OutBound + '.'+
   Copy(WordToHex(Link^.Addr.Zone), 2, 3)+DirSep
  Else FlowName := Cfg^.PKT_BT_OutBound + DirSep;
  End
 Else
  Begin
  s := Cfg^.PKT_BT_OutBound;
  While (s[Length(s)] <> DirSep) do Delete(s, Length(s), 1);
  FlowName := s + Link^.Addr.Domain + '.'+
   Copy(WordToHex(Link^.Addr.Zone), 2, 3)+DirSep;
  End;
 Dir := Copy(FlowName, 1, Length(FlowName) - 1);
 FlowName := FlowName + WordToHex(Link^.Addr.Net) +
  WordToHex(Link^.Addr.Node);
 If (Link^.Addr.Point <> 0) then
  Begin
  Dir := FlowName + '.pnt';
  FlowName := FlowName + '.pnt'+DirSep+'0000' +
   WordToHex(Link^.Addr.Point);
  End;
 If FileExist(FlowName+'.flo') then ScanBTFLO(FlowName+'.flo');
 If FileExist(FlowName+'.dlo') then ScanBTFLO(FlowName+'.dlo');
 If FileExist(FlowName+'.hlo') then ScanBTFLO(FlowName+'.hlo');
 If FileExist(FlowName+'.clo') then ScanBTFLO(FlowName+'.clo');
 If FileExist(FlowName+'.out') then ScanBTMail(FlowName+'.out', Dir);
 If FileExist(FlowName+'.dut') then ScanBTMail(FlowName+'.dut', Dir);
 If FileExist(FlowName+'.hut') then ScanBTMail(FlowName+'.hut', Dir);
 If FileExist(FlowName+'.cut') then ScanBTMail(FlowName+'.cut', Dir);
 End;

Procedure ScanOutbound;
 Begin
 LogSetCurLevel(lh, 4);
 LogWriteLn(lh, 'Scanning outbound');

 CurLink := Cfg^.Links;
 While (CurLink <> NIL) do
  Begin
  Case Cfg^.PKT_Mailer of
   cCM_BT: ScanBTOut(CurLink);
   End;
  CurLink := CurLink^.Next;
  End;
 End;


Begin
Init;
ProcessMailBox(Cfg^.MailBox);
RFC2FTN_PKT;
ScanNetMail;
ScanOutbound;
Done;
End.


