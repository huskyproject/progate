{ $O+,F+,I-,S-,R-,V-}
Unit MKMsgHud;        {Hudson/QuickBbs-style Message Base}

{$IfDef FPC}
 {$PackRecords 1}
{$EndIf}

Interface


Uses MKMsgAbs, MKGlobT, GeneralP;

Type MsgTxtType = String[255];         {MsgTxt.Bbs file}

Type MsgToIdxType = String[35];          {MsgToIdx.Bbs file}

Type MsgInfoType = Record              {MsgInfo.Bbs file}
  LowMsg: Word;                        {Low message number in file}
  HighMsg: Word;                       {High message number in file}
  Active: Word;                        {Number of active messages}
  AreaActive: Array[1..200] of Word;   {Number active in each area}
  End;

Type MsgIdxType = Record               {MsgIdx.Bbs file}
  MsgNum: Word;                        {Message number}
  Area: Byte;                          {Message area}
  End;

Type MsgHdrType = Record               {MsgHdr.Bbs file}
  MsgNum: Word;                        {Message number}
  ReplyTo: Word;                       {Message is reply to this number}
  SeeAlso: Word;                       {Message has replies}
  Extra: Word;                         {No longer used}
  StartRec: Word;                      {starting seek offset in MsgTxt.Bbs}
  NumRecs: Word;                       {number of MsgTxt.Bbs records}
  DestNet: Integer;                    {NetMail Destination Net}
  DestNode: Integer;                   {NetMail Destination Node}
  OrigNet: Integer;                    {NetMail Originating Net}
  OrigNode: Integer;                   {NetMail Originating Node}
  DestZone: Byte;                      {NetMail Destination Zone}
  OrigZone: Byte;                      {NetMail Originating Zone}
  Cost: Word;                          {NetMail Cost}
  MsgAttr: Byte;                       {Message attribute - see constants}
  NetAttr: Byte;                       {Netmail attribute - see constants}
  Area: Byte;                          {Message area}
  Time: String[5];                     {Message time in HH:MM}
  Date: String[8];                     {Message date in MM-DD-YY}
  MsgTo: String[35];                   {Message is intended for}
  MsgFrom: String[35];                 {Message was written by}
  Subj: String[72];                    {Message subject}
  End;


Type LastReadType = Array[1..200] Of Word; {LASTREAD.BBS file}


Const                                  {MsgHdr.MsgAttr}
  maDeleted =       1;                 {Message is deleted}
  maUnmovedNet =    2;                 {Unexported Netmail message}
  maNetMail =       4;                 {Message is netmail message}
  maPriv =          8;                 {Message is private}
  maRcvd =         16;                 {Message is received}
  maUnmovedEcho =  32;                 {Unexported Echomail message}
  maLocal =        64;                 {"Locally" entered message}


Const                                  {MsgHdr.NetAttr}
  naKillSent =      1;                 {Delete after exporting}
  naSent =          2;                 {Msg has been sent}
  naFAttach =       4;                 {Msg has file attached}
  naCrash =         8;                 {Msg is crash}
  naReqRcpt =      16;                 {Msg requests receipt}
  naReqAudit =     32;                 {Msg requests audit}
  naRetRcpt =      64;                 {Msg is a return receipt}
  naFileReq =     128;                 {Msg is a file request}



{$IfDef SPEED}
Uses
  BseDOS;

Const
  fmReadOnly = Open_Access_ReadOnly;
  fmReadWrite = Open_Access_ReadWrite;
  fmDenyNone = Open_Share_DenyNone;

{$Else}

Const
  fmReadOnly = 0;          {FileMode constants}
  fmWriteOnly = 1;
  fmReadWrite = 2;
  fmDenyAll = 16;
  fmDenyWrite = 32;
  fmDenyRead = 48;
  fmDenyNone = 64;
  fmNoInherit = 128;

{$EndIf}

Const
  TxtSize = 64;
  SeekSize = 1000;

  HudsonFlushing: Boolean = True;

  HudsonLastRead : String[12] = 'LASTREAD.BBS';

Type
 TxtRecsType = Array[1..TxtSize] of MsgTxtType;
 SeekArrayType = Array[1..SeekSize] of MsgIdxType;

Type HudsonMsgType = Record
  MsgPath: String[50];                 {Message base directory}
  MsgInfoFile: File;
  MsgTxtFile: File;
  MsgHdrFile: File;
  MsgToIdxFile: File;
  MsgIdxFile: File;
  Opened: Boolean;
  Locked: Boolean;
  Error: Word; {0=no error}
  RealMsgNum: Word;
  MsgHdr: MsgHdrType;                  {Current message header}
  MsgInfo: MsgInfoType;                {MsgInfo record}
  MsgPos: Word;                        {MsgHdr seek position of current rec}
  {$IFDEF VirtualPascal}
  SeekNumRead: LongInt;
  {$ELSE}
  SeekNumRead: Word;                   {Number of records in the array}
  {$ENDIF}
  SeekPos: Integer;                    {Current position in array}
  SeekStart: Word;                     {File Pos of 1st record in Idx Array}
  SeekOver: Boolean;                   {More idx records?}
  CurrMsgNum: Word;                    {Current Seek Msg number}
  CurrTxtRec: Word;                    {Current txtrec in current msg}
  CurrTxtPos: Word;                    {Current position in current txtrec}
  OrigPoint: Word;                     {Point Addr orig}
  DestPoint: Word;                     {Point Addr destination}
  Echo: Boolean;                       {Should message be exported}
  CRLast: Boolean;                     {Last char was CR #13}
  Area: Word;
  MT: MsgMailType;
  End;


Type HudsonMsgObj = Object(AbsMsgObj)  {Message Export Object}
  MsgRec: ^HudsonMsgType;
  MsgChars: ^TxtRecsType;
  SeekArray: ^SeekArrayType;
  Constructor Init; {Initialize}
  Destructor Done; Virtual; {Done}
  Procedure InitMsgHdr; Virtual; {Setup message/read header}
  Procedure MsgTxtStartUp; Virtual; {Setup message text}
  Function  GetChar: Char; Virtual; {Get msg text character}
  Function  NextChar(Var Rec: Word; Var PPos: Word): Boolean;{internal to position for char}
  Function  GetString: String; Virtual; {Get wordwrapped string}
  Procedure SeekFirst(MsgNum: LongInt); Virtual; {Seek msg number}
  Procedure SeekNext; Virtual; {Find next matching msg}
  Procedure SeekPrior; Virtual; {Find prior matching msg}
  Procedure SeekRead(NumToRead: Word); {Refill seek array}
  Function  SetRead(RS: Boolean): boolean; Virtual; {Set read status}
  Function  IsRead: Boolean; Virtual; {Is current msg received}
  Function  GetFrom: String; Virtual; {Get from name on current msg}
  Function  GetTo: String;Virtual; {Get to name on current msg}
  Function  GetSubj: String; Virtual; {Get subject on current msg}
  Function  GetCost: Word; Virtual; {Get cost of current msg}
  Function  GetDate: String; Virtual; {Get date of current msg}
  Function  GetTime: String; Virtual; {Get time of current msg}
  Function  GetRefer: LongInt; Virtual; {Get reply to of current msg}
  Function  GetSeeAlso: LongInt; Virtual; {Get see also of current msg}
  Function  GetMsgNum: LongInt; Virtual; {Get message number}
  Procedure GetOrig(Var Addr: AddrType); Virtual; {Get origin address}
  Procedure GetDest(Var Addr: AddrType); Virtual; {Get destination address}
  Function  IsLocal: Boolean; Virtual; {Is current msg local}
  Function  IsCrash: Boolean; Virtual; {Is current msg crash}
  Function  IsKillSent: Boolean; Virtual; {Is current msg kill sent}
  Function  IsSent: Boolean; Virtual; {Is current msg sent}
  Function  IsFAttach: Boolean; Virtual; {Is current msg file attach}
  Function  IsReqRct: Boolean; Virtual; {Is current msg request receipt}
  Function  IsReqAud: Boolean; Virtual; {Is current msg request audit}
  Function  IsRetRct: Boolean; Virtual; {Is current msg a return receipt}
  Function  IsFileReq: Boolean; Virtual; {Is current msg a file request}
  Function  IsRcvd: Boolean; Virtual; {Is current msg received}
  Function  IsPriv: Boolean; Virtual; {Is current msg priviledged/private}
  Function  IsDeleted: Boolean; Virtual; {Is current msg deleted}
  Function  IsEchoed: Boolean; Virtual; {Is current msg unmoved echomail msg}
  Procedure SetDest(Var Addr: AddrType); Virtual; {Set Zone/Net/Node/Point for Dest}
  Procedure SetOrig(Var Addr: AddrType); Virtual; {Set Zone/Net/Node/Point for Orig}
  Procedure SetFrom(Name: String); Virtual; {Set message from}
  Procedure SetTo(Name: String); Virtual; {Set message to}
  Procedure SetSubj(Str: String); Virtual; {Set message subject}
  Procedure SetCost(SCost: Word); Virtual; {Set message cost}
  Procedure SetRefer(SRefer: LongInt); Virtual; {Set message reference}
  Procedure SetSeeAlso(SAlso: LongInt); Virtual; {Set message see also}
  Procedure SetDate(SDate: String); Virtual; {Set message date}
  Procedure SetTime(STime: String); Virtual; {Set message time}
  Procedure SetEcho(ES: Boolean); Virtual; {Set echo status}
  Procedure SetMsgAttr(Setting: Boolean; Mask: Word);
  Procedure SetNetAttr(Setting: Boolean; Mask: Word);
  Procedure SetLocal(LS: Boolean); Virtual; {Set local status}
  Procedure SetRcvd(RS: Boolean); Virtual; {Set received status}
  Procedure SetPriv(PS: Boolean); Virtual; {Set priveledge vs public status}
  Procedure SetCrash(SS: Boolean); Virtual; {Set crash netmail status}
  Procedure SetKillSent(SS: Boolean); Virtual; {Set kill/sent netmail status}
  Procedure SetSent(SS: Boolean); Virtual; {Set sent netmail status}
  Procedure SetFAttach(SS: Boolean); Virtual; {Set file attach status}
  Procedure SetReqRct(SS: Boolean); Virtual; {Set request receipt status}
  Procedure SetReqAud(SS: Boolean); Virtual; {Set request audit status}
  Procedure SetRetRct(SS: Boolean); Virtual; {Set return receipt status}
  Procedure SetFileReq(SS: Boolean); Virtual; {Set file request status}
  Procedure DoString(Str: String); Virtual; {Add string to message text}
  Procedure DoChar(Ch: Char); Virtual; {Add character to message text}
  Procedure DoStringLn(Str: String); Virtual; {Add string and newline to msg text}
  Function  WriteMsg: Word; Virtual; {Write msg to message base}
  Function  OpenMsgBase: Word; Virtual; {Individual msg open}
  Function  CloseMsgBase: Word; Virtual; {Individual msg close}
  Function  SeekEnd: Word; Virtual; {Seek to eof for msg base files}
  Function  SeekMsgBasePos(Position: Word): Word; Virtual; {Seek to pos of Msg Base File}
  Function  Check: Word; Virtual; {Check if msg base is ok}
  Function  CreateMsgBase(MaxMsg: Word; MaxDays: Word): Word; Virtual;{Create initial msg base files}
  Function  LockMsgBase: Boolean; Virtual; {Lock msg base for updating}
  Function  UnlockMsgBase: Boolean; Virtual; {Unlock msg base after updating}
(*  Function  WriteMailIdx(FN: String; MsgPos: Word): Word; Virtual;
    {Write Netmail or EchoMail.Bbs} *)
  Function  MsgBaseSize: Word; Virtual; {Number of msg base index records}
  Function  GetNumActive: Word; Virtual; {Get number of active messages}
  Function  GetHighMsgNum: LongInt; Virtual; {Get highest msg number}
  Function  GetLowMsgNum: LongInt; Virtual; {Get lowest msg number}
  Procedure StartNewMsg; Virtual; {Initialize message}
  Procedure SetMsgPath(MP: String); Virtual;
  Function  SeekFound:Boolean; Virtual; {Seek msg found}
  Procedure SetMailType(MT: MsgMailType); Virtual; {Set message base type}
  Function  GetSubArea: Word; Virtual; {Get sub area number}
  Procedure ReWriteHdr; Virtual; {Rewrite msg header after changes}
  Procedure DeleteMsg; Virtual; {Delete current message}
  Function  GetMsgLoc: LongInt; Virtual; {To allow reseeking to message}
  Procedure SetMsgLoc(ML: LongInt); Virtual; {Reseek to message}
  Function  NumberOfMsgs: LongInt; Virtual; {Number of messages}
  Function  GetLastRead: LongInt; Virtual; {Get last read for user num}
  Procedure SetLastRead(LR: LongInt); Virtual; {Set last read}
  Procedure GetHighest(Var LR: LastReadType); Virtual; {Get highest all areas}
  Function  GetTxtPos: LongInt; Virtual;
  Procedure SetTxtPos(TP: LongInt); Virtual;
  Function  MsgBaseExists: Boolean; Virtual;
  Function  GetRealMsgNum: LongInt; Virtual;
  function  GetID: Byte; virtual;
  End;

Type HudsonMsgPtr = ^HudsonMsgObj;

Implementation

Uses
  MKFile, MKString {, Global};


function  HudsonMsgObj.GetID: Byte;
begin
  GetID:=msgHudson;
end;

Constructor HudsonMsgObj.Init;
  Begin
  New(MsgRec);
  New(MsgChars);
  New(SeekArray);
  If ((MsgRec = Nil) Or (MsgChars = Nil) or (SeekArray = Nil)) Then
    Begin
    If MsgRec <> Nil Then
      Dispose(MsgRec);
    If MsgChars <> Nil Then
      Dispose(MsgChars);
    If SeekArray <> Nil Then
      Dispose(SeekArray);
    Fail;
    Exit;
    End;
  MsgRec^.MsgPath := '';
  MsgRec^.Opened := False;
  MsgRec^.Locked := False;
  MsgRec^.Error := 0;
  End;


Destructor HudsonMsgObj.Done;
  Begin
  Dispose(MsgRec);
  Dispose(MsgChars);
  Dispose(SeekArray);
  End;


procedure HudsonMsgObj.InitMsgHdr;
begin
  Seek(MsgRec^.MsgHdrFile, MsgRec^.MsgPos);
  MsgRec^.OrigPoint := 0;
  MsgRec^.DestPoint := 0;
  BlockRead(MsgRec^.MsgHdrFile, MsgRec^.MsgHdr, 1);
  MsgRec^.Error := IOResult;
end;


Procedure HudsonMsgObj.SetMsgAttr(Setting: Boolean; Mask: Word);
  Begin
  If Setting Then
    MsgRec^.MsgHdr.MsgAttr := MsgRec^.MsgHdr.MsgAttr or Mask
  Else
    MsgRec^.MsgHdr.MsgAttr := MsgRec^.MsgHdr.MsgAttr and (Not Mask);
  End;



Procedure HudsonMsgObj.SetRcvd(RS: Boolean);
  Begin
  SetMsgAttr(RS, maRcvd);
  End;


Procedure HudsonMsgObj.SetPriv(PS: Boolean);
  Begin
  SetMsgAttr(PS, maPriv);
  End;


Procedure HudsonMsgObj.SetNetAttr(Setting: Boolean; Mask: Word);
  Begin
  If Setting Then
    MsgRec^.MsgHdr.NetAttr := MsgRec^.MsgHdr.NetAttr Or Mask
  Else
    MsgRec^.MsgHdr.NetAttr := MsgRec^.MsgHdr.NetAttr And (Not Mask);
  End;


Procedure HudsonMsgObj.SetSeeAlso(SAlso: LongInt);
  Begin
  MsgRec^.MsgHdr.SeeAlso := SAlso;
  End;


Procedure HudsonMsgObj.SetFrom(Name: String); {Set msg from}
  Begin
  MsgRec^.MsgHdr.MsgFrom := Name;
  End;


Procedure HudsonMsgObj.SetTo(Name: String); {Set msg to}
  Begin
  MsgRec^.MsgHdr.MsgTo := Name;
  End;


Procedure HudsonMsgObj.SetSubj(Str: String); {Set msg subject}
  Begin
  MsgRec^.MsgHdr.Subj := Str;
  End;


Function HudsonMsgObj.GetFrom: String;
  Begin
  GetFrom := MsgRec^.MsgHdr.MsgFrom;
  End;


Function HudsonMsgObj.GetTo: String;
  Begin
  GetTo := MsgRec^.MsgHdr.MsgTo;
  End;


Function HudsonMsgObj.GetSubj: String;
  Begin
  GetSubj := MsgRec^.MsgHdr.Subj;
  End;


Function HudsonMsgObj.GetCost: Word;
  Begin
  GetCost := MsgRec^.MsgHdr.Cost;
  End;


Function HudsonMsgObj.GetDate: String;            {Get date of current msg}
  Begin
  GetDate := MsgRec^.MsgHdr.Date;
  End;


Function HudsonMsgObj.GetTime: String;            {Get time of current msg}
  Begin
  GetTime := MsgRec^.MsgHdr.Time;
  End;


Function HudsonMsgObj.GetRefer: LongInt;
  Begin
  GetRefer := MsgRec^.MsgHdr.ReplyTo;
  End;


Function HudsonMsgObj.GetSeeAlso: LongInt;
  Begin
  GetSeeAlso := MsgRec^.MsgHdr.SeeAlso;
  End;


Function HudsonMsgObj.GetMsgNum: LongInt;
Begin
  InitMsgHdr;
  GetMsgNum := MsgRec^.MsgHdr.MsgNum;
End;


Procedure HudsonMsgObj.GetOrig(Var Addr: AddrType);
  Begin
  Addr.Zone := MsgRec^.MsgHdr.OrigZone;
  Addr.Net := MsgRec^.MsgHdr.OrigNet;
  Addr.Node := MsgRec^.MsgHdr.OrigNode;
  Addr.Point := MsgRec^.OrigPoint;
  Addr.Domain := '';
  End;


Procedure HudsonMsgObj.GetDest(Var Addr: AddrType);
  Begin
  Addr.Zone := MsgRec^.MsgHdr.DestZone;
  Addr.Net := MsgRec^.MsgHdr.DestNet;
  Addr.Node := MsgRec^.MsgHdr.DestNode;
  Addr.Point := MsgRec^.DestPoint;
  Addr.Domain := '';
  End;


Function HudsonMsgObj.IsLocal: Boolean;
  Begin
  IsLocal := ((MsgRec^.MsgHdr.MsgAttr and maLocal) <> 0);
  End;


Function HudsonMsgObj.IsCrash: Boolean;
  Begin
  IsCrash := ((MsgRec^.MsgHdr.NetAttr and naCrash) <> 0);
  End;


Function HudsonMsgObj.IsKillSent: Boolean;
  Begin
  IsKillSent := ((MsgRec^.MsgHdr.NetAttr and naKillSent) <> 0);
  End;


Function HudsonMsgObj.IsSent: Boolean;
  Begin
  IsSent := ((MsgRec^.MsgHdr.NetAttr and naSent) <> 0);
  End;


Function HudsonMsgObj.IsFAttach: Boolean;
  Begin
  IsFAttach := ((MsgRec^.MsgHdr.NetAttr and naFAttach) <> 0);
  End;


Function HudsonMsgObj.IsReqRct: Boolean;
  Begin
  IsReqRct := ((MsgRec^.MsgHdr.NetAttr and naReqRcpt) <> 0);
  End;


Function HudsonMsgObj.IsReqAud: Boolean;
  Begin
  IsReqAud := ((MsgRec^.MsgHdr.NetAttr and naReqAudit) <> 0);
  End;


Function HudsonMsgObj.IsRetRct: Boolean;
  Begin
  IsRetRct := ((MsgRec^.MsgHdr.NetAttr and naRetRcpt) <> 0);
  End;


Function HudsonMsgObj.IsFileReq: Boolean;
  Begin
  IsFileReq := ((MsgRec^.MsgHdr.NetAttr and naFileReq) <> 0);
  End;


Function HudsonMsgObj.IsRcvd: Boolean;
  Begin
  IsRcvd := ((MsgRec^.MsgHdr.MsgAttr and maRcvd) <> 0);
  End;


Function HudsonMsgObj.IsPriv: Boolean;
  Begin
  IsPriv := ((MsgRec^.MsgHdr.MsgAttr and maPriv) <> 0);
  End;


Function HudsonMsgObj.IsDeleted: Boolean;
  Begin
  IsDeleted := ((MsgRec^.MsgHdr.MsgAttr and maDeleted) <> 0);
  End;


Function HudsonMsgObj.IsEchoed: Boolean;
  Begin
  IsEchoed := MsgRec^.Echo;
{  IsEchoed := ((MsgRec^.MsgHdr.MsgAttr and maUnmovedEcho) <> 0); }
{  IsUnmovedNet := ((MsgRec^.MsgHdr.MsgAttr and maUnmovedNet) <> 0);}
  End;


Procedure HudsonMsgObj.MsgTxtStartUp;
  Var
    {$IFDEF VirtualPascal}
    NumRead: LongInt;
    {$ELSE}
    NumRead: Word;
    {$ENDIF}
    MaxTxt: Word;

  Begin
  Wrapped := False;
  If MsgRec^.MsgHdr.NumRecs > TxtSize Then
    MaxTxt := TxtSize
  Else
    MaxTxt := MsgRec^.MsgHdr.NumRecs;
  Seek(MsgRec^.MsgTxtFile, MsgRec^.MsgHdr.StartRec);
  If IoResult <> 0 Then
    MsgRec^.Error := 2222;
  If not shRead(MsgRec^.MsgTxtFile, MsgChars^, MaxTxt, NumRead) Then
    MsgRec^.Error := MKFileError;
  If NumRead <> MaxTxt Then
    MsgRec^.Error := 1111;
  MsgRec^.CurrTxtRec := 1;
  MsgRec^.CurrTxtPos := 1;
  EOM := False;
  End;


Function HudsonMsgObj.NextChar(Var Rec: Word; Var PPos: Word): Boolean;
  Var
    MoreNext: Boolean;

  Begin
  MoreNext := True;
  NextChar := True;
  While MoreNext Do
    Begin
    If ((Rec > MsgRec^.MsgHdr.NumRecs) or (Rec > TxtSize)) Then
      MoreNext := False
    Else
      Begin
      If (PPos > Length(MsgChars^[Rec])) Then
        Begin
        Inc(Rec);
        PPos := 1;
        End
      Else
        MoreNext := False;
      End;
    End;
  If ((Rec > MsgRec^.MsgHdr.NumRecs) or (Rec > TxtSize)) Then
    NextChar := False;
  End;


Function HudsonMsgObj.GetChar: Char;
  Var
    MoreNext: Boolean;

  Begin
  MoreNext := True;
  If ((MsgRec^.CurrTxtRec <= MsgRec^.MsgHdr.NumRecs) and
  (MsgRec^.CurrTxtRec <= TxtSize)) Then
    Begin
    While MoreNext Do
      Begin
      If ((MsgRec^.CurrTxtRec > MsgRec^.MsgHdr.NumRecs) Or
      (MsgRec^.CurrTxtRec > TxtSize)) Then
        MoreNext := False
      Else
        Begin
        If (MsgRec^.CurrTxtPos > Length(MsgChars^[MsgRec^.CurrTxtRec])) Then
          Begin
          Inc(MsgRec^.CurrTxtRec);
          MsgRec^.CurrTxtPos := 1;
          End
        Else
          MoreNext := False;
        End;
      End;
    If ((MsgRec^.CurrTxtRec > MsgRec^.MsgHdr.NumRecs) Or
    (MsgRec^.CurrTxtRec > TxtSize)) Then
      EOM := True;
    End
  Else
    EOM := True;
  If EOM Then
    Begin
    GetChar := #0;
    End
  Else
    GetChar := MsgChars^[MsgRec^.CurrTxtRec][MsgRec^.CurrTxtPos];
  Inc(MsgRec^.CurrTxtPos);
  End;


Procedure HudsonMsgObj.StartNewMsg;  {Initialize message}
  Const
    Blank = '* Blank *';

  Begin
  MsgRec^.CurrTxtRec := 1;
  MsgRec^.CurrTxtPos := 0;
  FillChar(MsgRec^.MsgHdr, SizeOf(MsgRec^.MsgHdr), #0);
  MsgRec^.Echo := False;
  MsgRec^.MsgHdr.Time := '00:00';
  MsgRec^.MsgHdr.Date := '00-00-00';
  MsgRec^.MsgHdr.MsgTo := Blank;
  MsgRec^.MsgHdr.MsgFrom := Blank;
  MsgRec^.MsgHdr.Subj := Blank;
  MsgRec^.CRLast := True;
  End;


Procedure HudsonMsgObj.SetEcho(ES: Boolean); {Set echo status}
  Begin
  MsgRec^.Echo := ES;
  End;


Procedure HudsonMsgObj.SetLocal(LS: Boolean); {Set local status}
  Begin
  If LS Then
    MsgRec^.MsgHdr.MsgAttr := MsgRec^.MsgHdr.MsgAttr or maLocal
  Else
    MsgRec^.MsgHdr.MsgAttr := MsgRec^.MsgHdr.Msgattr and (Not maLocal);
  End;


Procedure HudsonMsgObj.SetCrash(SS: Boolean); {Set crash netmail status}
  Begin
  If SS Then
    MsgRec^.MsgHdr.NetAttr := MsgRec^.MsgHdr.NetAttr or naCrash
  Else
    MsgRec^.MsgHdr.NetAttr := MsgRec^.MsgHdr.NetAttr and (Not naCrash);
  End;


Procedure HudsonMsgObj.SetKillSent(SS: Boolean); {Set kill/sent netmail status}
  Begin
  If SS Then
    MsgRec^.MsgHdr.NetAttr := MsgRec^.MsgHdr.NetAttr or naKillSent
  Else
    MsgRec^.MsgHdr.NetAttr := MsgRec^.MsgHdr.NetAttr and (Not naKillSent);
  End;



Procedure HudsonMsgObj.SetSent(SS: Boolean); {Set sent netmail status}
  Begin
  If SS Then
    MsgRec^.MsgHdr.NetAttr := MsgRec^.MsgHdr.NetAttr or naSent
  Else
    MsgRec^.MsgHdr.NetAttr := MsgRec^.MsgHdr.NetAttr and (Not naSent);
  End;



Procedure HudsonMsgObj.SetFAttach(SS: Boolean); {Set file attach status}
  Begin
  If SS Then
    MsgRec^.MsgHdr.NetAttr := MsgRec^.MsgHdr.NetAttr or naFAttach
  Else
    MsgRec^.MsgHdr.NetAttr := MsgRec^.MsgHdr.NetAttr and (Not naFAttach);
  End;



Procedure HudsonMsgObj.SetReqRct(SS: Boolean); {Set request receipt status}
  Begin
  If SS Then
    MsgRec^.MsgHdr.NetAttr := MsgRec^.MsgHdr.NetAttr or naReqRcpt
  Else
    MsgRec^.MsgHdr.NetAttr := MsgRec^.MsgHdr.NetAttr and (Not naReqRcpt);
  End;



Procedure HudsonMsgObj.SetReqAud(SS: Boolean); {Set request audit status}
  Begin
  If SS Then
    MsgRec^.MsgHdr.NetAttr := MsgRec^.MsgHdr.NetAttr or naReqAudit
  Else
    MsgRec^.MsgHdr.NetAttr := MsgRec^.MsgHdr.NetAttr and (Not naReqAudit);
  End;



Procedure HudsonMsgObj.SetRetRct(SS: Boolean); {Set return receipt status}
  Begin
  If SS Then
    MsgRec^.MsgHdr.NetAttr := MsgRec^.MsgHdr.NetAttr or naRetRcpt
  Else
    MsgRec^.MsgHdr.NetAttr := MsgRec^.MsgHdr.NetAttr and (Not naRetRcpt);
  End;



Procedure HudsonMsgObj.SetFileReq(SS: Boolean); {Set file request status}
  Begin
  If SS Then
    MsgRec^.MsgHdr.NetAttr := MsgRec^.MsgHdr.NetAttr or naFileReq
  Else
    MsgRec^.MsgHdr.NetAttr := MsgRec^.MsgHdr.NetAttr and (Not naFileReq);
  End;


Procedure HudsonMsgObj.SetCost(SCost: Word);      {Set message cost}
  Begin
  MsgRec^.MsgHdr.Cost := SCost;
  End;


Procedure HudsonMsgObj.SetRefer(SRefer: LongInt);    {Set message reference}
  Begin
  MsgRec^.MsgHdr.ReplyTo := SRefer;
  End;


Procedure HudsonMsgObj.SetDate(SDate: String);    {Set message date}
  Begin
  MsgRec^.MsgHdr.Date := Copy(PadLeft(SDate,'0',8),1,8);
  MsgRec^.MsgHdr.Date[3] := '-';
  MsgRec^.MsgHdr.Date[6] := '-';
  End;


Procedure HudsonMsgObj.SetTime(STime: String);    {Set message time}
  Begin
  MsgRec^.MsgHdr.Time := Copy(PadLeft(STime,'0',5),1,5);
  MsgRec^.MsgHdr.Time[3] := ':';
  End;



Procedure HudsonMsgObj.DoString(Str: String);     {Add string to message text}
  Var
    i: Word;

  Begin
  i := 1;
  While i <= Length(Str) Do
    Begin
    DoChar(Str[i]);
    Inc(i);
    End;
  End;


Procedure HudsonMsgObj.DoChar(Ch: Char);          {Add character to message text}
  Begin
  If (MsgRec^.CurrTxtRec < TxtSize) or (MsgRec^.CurrTxtPos < 255) Then
    Begin
    If MsgRec^.CurrTxtPos = 255 Then
      Begin
      MsgChars^[MsgRec^.CurrTxtRec][0] := Chr(255);
      Inc(MsgRec^.CurrTxtRec);
      MsgRec^.CurrTxtPos := 0;
      End;
    Case CH of
      #$0D: MsgRec^.CRLast := True;
      #$0A:;
      #$8D:;
      Else
        MsgRec^.CRLast := False;
      End;
    Inc(MsgRec^.CurrTxtPos);
    MsgChars^[MsgRec^.CurrTxtRec][MsgRec^.CurrTxtPos] := Ch;
    End;
  End;



Procedure HudsonMsgObj.DoStringLn(Str: String);   {Add string and newline to msg text}
  Begin
  DoString(Str);
  DoChar(#13);
  End;


Function HudsonMsgObj.WriteMsg: Word;
  Var
    WriteError: Word;
    MsgPos: Word;
    MsgIdx: MsgIdxType;
    FN: String[13];
    AlreadyLocked: Boolean;

  Begin
  If FileSize(MsgRec^.MsgTxtFile) > $ff00 Then
    WriteError := 99
  Else
    WriteError := 0;
  If Not MsgRec^.CRLast Then
    DoChar(#$0D);
  MsgRec^.MsgHdr.NumRecs := MsgRec^.CurrTxtRec;
  MsgChars^[MsgRec^.CurrTxtRec][0] := Chr(MsgRec^.CurrTxtPos);
  Case MsgRec^.MT of
    mmtNormal:  Begin
             MsgRec^.MsgHdr.MsgAttr := MsgRec^.MsgHdr.MsgAttr and
               Not(maNetMail + maUnmovedNet + maUnmovedEcho);
             End;
    mmtEchoMail: Begin
             MsgRec^.MsgHdr.MsgAttr := MsgRec^.MsgHdr.MsgAttr and
               Not(maNetMail + maUnmovedNet);
             If MsgRec^.Echo Then
               MsgRec^.MsgHdr.MsgAttr := MsgRec^.MsgHdr.MsgAttr or maUnmovedEcho;
             End;
    mmtNetMail: Begin
             MsgRec^.MsgHdr.MsgAttr := MsgRec^.MsgHdr.MsgAttr and Not(maUnmovedEcho);
             MsgRec^.MsgHdr.MsgAttr := MsgRec^.MsgHdr.MsgAttr or maNetMail;
             If MsgRec^.Echo Then
               MsgRec^.MsgHdr.MsgAttr := MsgRec^.MsgHdr.MsgAttr or maUnmovedNet;
             End;
    End;
  MsgRec^.MsgHdr.Area := MsgRec^.Area;
  AlreadyLocked := MsgRec^.Locked;
  If Not AlreadyLocked Then
    If Not LockMsgBase Then
      WriteError := 5;
  If WriteError = 0 Then
    WriteError := SeekEnd;
  If WriteError = 0 Then               {Write MsgHdr}
    Begin
    MsgRec^.MsgHdr.StartRec := FileSize(MsgRec^.MsgTxtFile);
    MsgPos := FileSize(MsgRec^.MsgHdrFile);
    Inc(MsgRec^.MsgInfo.HighMsg);
    MsgRec^.MsgHdr.MsgNum := MsgRec^.MsgInfo.HighMsg;
    Inc(MsgRec^.MsgInfo.Active);
    Inc(MsgRec^.MsgInfo.AreaActive[MsgRec^.MsgHdr.Area]);
    If Not shWrite(MsgRec^.MsgHdrFile, MsgRec^.MsgHdr, 1)
      Then WriteError := MKFileError;
    End;
  If WriteError = 0 Then
    If Not shWrite(MsgRec^.MsgToIdxFile, MsgRec^.MsgHdr.MsgTo, 1) Then
      WriteError := MKFileError;
  If WriteError = 0 Then               {Write MsgIdx}
    Begin
    MsgIdx.MsgNum := MsgRec^.MsgHdr.MsgNum;
    MsgIdx.Area := MsgRec^.MsgHdr.Area;
    If Not shWrite(MsgRec^.MsgIdxFile, MsgIdx, 1) Then
      WriteError := MKFileError;
    End;
  If WriteError = 0 Then               {Write MsgTxt}
    Begin
    If Not shWrite(MsgRec^.MsgTxtFile, MsgChars^, MsgRec^.MsgHdr.NumRecs) Then
      WriteError := MKFileError;
    End;
  If WriteError = 0 Then
    Begin
    Case MsgRec^.MT of
      mmtEchoMail: FN := 'ECHOMAIL.BBS';
      mmtNetMail: FN := 'NETMAIL.BBS';
      Else
        FN := '';
      End; {Case MsgType}
(*    If ((Length(FN) > 0) and MsgRec^.Echo) Then
      WriteError := WriteMailIdx(Cfg.JAMPath+FN, MsgPos); *)
    End;
  If WriteError = 0 Then
    If Not AlreadyLocked Then
      If Not UnlockMsgBase Then
        WriteError := 5;
  If ((WriteError = 0) and (HudsonFlushing)) Then
    Begin
    FlushFile(MsgRec^.MsgInfoFile);
    FlushFile(MsgRec^.MsgTxtFile);
    FlushFile(MsgRec^.MsgHdrFile);
    FlushFile(MsgRec^.MsgInfoFile);
    FlushFile(MsgRec^.MsgToIdxFile);
    FlushFile(MsgRec^.MsgIdxFile);
    End;
  MsgRec^.MsgPos := MsgPos;;
  WriteMsg := WriteError;
  End;


Procedure HudsonMsgObj.SetDest(Var Addr: AddrType);   {Set Zone/Net/Node/Point for Dest}
  Begin
  MsgRec^.MsgHdr.DestZone := Lo(Addr.Zone);
  MsgRec^.MsgHdr.DestNet := Addr.Net;
  MsgRec^.MsgHdr.DestNode := Addr.Node;
  MsgRec^.DestPoint := Addr.Point;
  If ((MsgRec^.DestPoint <> 0) and (MsgRec^.Mt = mmtNetMail)) Then
    DoStringLn(#1 + 'TOPT ' + Long2Str(MsgRec^.DestPoint));
  End;


Procedure HudsonMsgObj.SetOrig(Var Addr: AddrType);   {Set Zone/Net/Node/Point for Orig}
  Begin
  MsgRec^.MsgHdr.OrigZone := Lo(Addr.Zone);
  MsgRec^.MsgHdr.OrigNet := Addr.Net;
  MsgRec^.MsgHdr.OrigNode := Addr.Node;
  MsgRec^.OrigPoint := Addr.Point;
  If ((MsgRec^.OrigPoint <> 0) and (MsgRec^.Mt = mmtNetmail)) Then
    DoStringLn(#1 + 'FMPT ' + Long2Str(MsgRec^.OrigPoint));
  End;



Procedure HudsonMsgObj.SetMsgPath(MP: String);
Var
 s: String;

  Begin
  MsgRec^.Area := Str2Long(Copy(MP,1,3));
  s := Copy(MP,4,60);
  s := AddDirSep(s);
  MsgRec^.MsgPath := s;
  shAssign(MsgRec^.MsgIdxFile, MsgRec^.MsgPath + 'MSGIDX.BBS');
  shAssign(MsgRec^.MsgToIdxFile, MsgRec^.MsgPath + 'MSGTOIDX.BBS');
  shAssign(MsgRec^.MsgHdrFile, MsgRec^.MsgPath + 'MSGHDR.BBS');
  shAssign(MsgRec^.MsgTxtFile, MsgRec^.MsgPath + 'MSGTXT.BBS');
  shAssign(MsgRec^.MsgInfoFile, MsgRec^.MsgPath + 'MSGINFO.BBS');
  End;


Function HudsonMsgObj.LockMsgBase: Boolean; {Lock msg base prior to adding message}
  Var
    LockError: Word;
    {$IFDEF VirtualPascal}
    NumRead: LongInt;
    {$ELSE}
    NumRead: Word;
    {$ENDIF}

  Begin
  LockError := 0;
  If Not MsgRec^.Locked Then
    Begin
    LockError := shLock(MsgRec^.MsgInfoFile,406,1);
    If LockError = 1 Then
      LockError := 0;                    {No Locking if share not loaded}
    If LockError = 0 Then
      Begin
      Seek(MsgRec^.MsgInfoFile,0);
      LockError := IoResult;
      End;
    If LockError = 0 Then
      Begin
      If Not shRead(MsgRec^.MsgInfoFile, MsgRec^.MsgInfo,1,NumRead) Then
        LockError := MKFileError;
      End;
    End;
  MsgRec^.Locked := (LockError = 0);
  LockMsgBase := LockError = 0;
  End;


Function HudsonMsgObj.UnlockMsgBase: Boolean; {Unlock msg base after adding message}
  Var
    LockError: Word;

  Begin
  LockError := 0;
  If MsgRec^.Locked Then
    Begin
    Seek(MsgRec^.MsgInfoFile,0);
    LockError := IoResult;
    shWrite(MsgRec^.MsgInfoFile, MsgRec^.MsgInfo,1);
    If LockError = 0 Then
      LockError := IoResult;
    LockError := UnLockFile(MsgRec^.MsgInfoFile,406,1);
    If LockError = 1 Then
      LockError := 0;                    {No locking if share not loaded}
    End;
  MsgRec^.Locked := False;
  UnlockMsgBase := LockError = 0;
  End;


Function HudsonMsgObj.GetNumActive: Word;
  Begin
  GetNumActive := MsgRec^.MsgInfo.Active;
  End;


Function HudsonMsgObj.GetHighMsgNum: LongInt;
  Begin
  GetHighMsgNum := MsgRec^.MsgInfo.HighMsg;
  End;


Function HudsonMsgObj.GetLowMsgNum: LongInt;
  Begin
  GetLowMsgNum := MsgRec^.MsgInfo.LowMsg;
  End;


Function HudsonMsgObj.CreateMsgBase(MaxMsg: Word; MaxDays: Word): Word;
  Var
    CreateError: Word;
    i: Word;

  Begin
  CreateError := 0;
  If Not MakePath(MsgRec^.MsgPath) Then
    CreateError := 1;
  ReWrite(MsgRec^.MsgIdxFile, SizeOf(MsgIdxType));
  If CreateError = 0 Then
    CreateError := IoResult;
  ReWrite(MsgRec^.MsgToIdxFile, SizeOf(MsgToIdxType));
  If CreateError = 0 Then
    CreateError := IoResult;
  ReWrite(MsgRec^.MsgHdrFile, SizeOf(MsgHdrType));
  If CreateError = 0 Then
    CreateError := IoResult;
  ReWrite(MsgRec^.MsgTxtFile, SizeOf(MsgTxtType));
  If CreateError = 0 Then
    CreateError := IoResult;
  ReWrite(MsgRec^.MsgInfoFile, SizeOf(MsgInfoType));
  If CreateError = 0 Then
    CreateError := IoResult;
  MsgRec^.MsgInfo.LowMsg := 1;
  MsgRec^.MsgInfo.HighMsg := 0;
  MsgRec^.MsgInfo.Active := 0;
  For i := 1 to 200 Do
    MsgRec^.MsgInfo.AreaActive[i] := 0;
  If Not shWrite(MsgRec^.MsgInfoFile, MsgRec^.MsgInfo, 1) Then
    CreateError := MKFileError;
  Close(MsgRec^.MsgInfoFile);
  If CreateError = 0 Then
    CreateError := IoResult;
  Close(MsgRec^.MsgIdxFile);
  If CreateError = 0 Then
    CreateError := IoResult;
  Close(MsgRec^.MsgToIdxFile);
  If CreateError = 0 Then
    CreateError := IoResult;
  Close(MsgRec^.MsgTxtFile);
  If CreateError = 0 Then
    CreateError := IoResult;
  Close(MsgRec^.MsgHdrFile);
  If CreateError = 0 Then
    CreateError := IoResult;
  CreateMsgBase := CreateError;
  End;


Function  HudsonMsgObj.MsgBaseExists: Boolean;
  Begin
  MsgBaseExists := (Check <> 1);
  End;



Function HudsonMsgObj.Check: Word;          {Check if msg base is Ok}
  { 0 = ok, 1 = not there (create), 2 = corrupted}
  Var
    BaseSize: LongInt;
    Status: Word;

  Begin
  Status := 0;
  If (Not FileExist(MsgRec^.MsgPath + 'MSGINFO.BBS'))  Then
    Status := 1;
  If (Not FileExist(MsgRec^.MsgPath + 'MSGHDR.BBS'))  Then
    Begin
    If Status = 0 Then
      Status := 2;
    End
  Else
    Begin
    If Status = 1 Then
      Status := 2;
    End;
  If (Not FileExist(MsgRec^.MsgPath + 'MSGTXT.BBS'))  Then
    Begin
    If Status = 0 Then
      Status := 2;
    End
  Else
    Begin
    If Status = 1 Then
      Status := 2;
    End;
  If (Not FileExist(MsgRec^.MsgPath + 'MSGIDX.BBS')) Then
    Begin
    If Status = 0 Then
      Status := 2;
    End
  Else
    Begin
    If Status = 1 Then
      Status := 2;
    End;
  If (Not FileExist(MsgRec^.MsgPath + 'MSGTOIDX.BBS'))  Then
    Begin
    If Status = 0 Then
      Status := 2;
    End
  Else
    Begin
    If Status = 1 Then
      Status := 2;
    End;
  If Status = 0 Then
    Begin
    If SizeFile(MsgRec^.MsgPath + 'MSGINFO.BBS') <> SizeOf(MsgInfoType) Then
      Status := 2;
    End;
  If Status = 0 Then
    Begin
    BaseSize := SizeFile(MsgRec^.MsgPath + 'MSGHDR.BBS') Div SizeOf(MsgHdrType);
    If BaseSize <> (SizeFile(MsgRec^.MsgPath + 'MSGIDX.BBS') Div SizeOf(MsgIdxType)) Then
      Status := 2;
    If BaseSize <> (SizeFile(MsgRec^.MsgPath + 'MSGTOIDX.BBS') Div SizeOf(MsgToIdxType)) Then
      Status := 2;
    End;
  Check := Status;
  End;



Function HudsonMsgObj.MsgBaseSize:Word;
  Begin
  If Length(MsgRec^.MsgPath) > 0 Then
    Begin
    MsgBaseSize := FileSize(MsgRec^.MsgIdxFile);
    End
  Else
    MsgBaseSize := 0;
  End;


Function HudsonMsgObj.SeekEnd: Word;        {Seek to end of Msg Base Files}
  Var
    SeekError: Word;

  Begin
  SeekError := 0;
  Seek(MsgRec^.MsgIdxFile, FileSize(MsgRec^.MsgIdxFile));
  If SeekError = 0 Then
    SeekError := IoResult;
  Seek(MsgRec^.MsgToIdxFile, FileSize(MsgRec^.MsgToIdxFile));
  If SeekError = 0 Then
    SeekError := IoResult;
  Seek(MsgRec^.MsgTxtFile, FileSize(MsgRec^.MsgTxtFile));
  If SeekError = 0 Then
    SeekError := IoResult;
  Seek(MsgRec^.MsgHdrFile, FileSize(MsgRec^.MsgHdrFile));
  If SeekError = 0 Then
    SeekError := IoResult;
  SeekEnd := SeekError;
  End;


Function HudsonMsgObj.SeekMsgBasePos(Position: Word): Word; {Seek to pos of Msg Base File}
  Var
    SeekError: Word;
  Begin
  Seek(MsgRec^.MsgIdxFile, Position);
  SeekError := IoResult;
  Seek(MsgRec^.MsgToIdxFile, Position);
  If SeekError = 0 Then
    SeekError := IoResult;
  Seek(MsgRec^.MsgHdrFile, Position);
  If SeekError = 0 Then
    SeekError := IoResult;
  SeekMsgBasePos := SeekError;
  End;


(* Function HudsonMsgObj.WriteMailIdx(FN: String; MsgPos: Word): Word; {Write Netmail or EchoMail.Bbs}
Var
  IdxFile: File;
  WriteError: Word;
Begin
  WriteError := 0;
  shAssign(IdxFile, FN);
  FileMode := fmReadWrite + fmDenyNone;
  If FileExist(FN) Then Begin
    If Not shReset(IdxFile, SizeOf(MsgPos)) Then
      WriteError := MKFileError;
  End Else Begin
    ReWrite(IdxFile, SizeOf(MsgPos));
    WriteError := IoResult;
  End;
  If WriteError = 0 Then Begin
    Seek(IdxFile, FileSize(IdxFile));
    WriteError := IoResult;
  End;
  If WriteError = 0 Then Begin
    BlockWrite(IdxFile, MsgPos, 1);
    WriteError := IoResult;
  End;
  If WriteError = 0 Then Begin
    Close(IdxFile);
    WriteError := IoResult;
  End;
  WriteMailIdx := WriteError;
End; *)

Function HudsonMsgObj.OpenMsgBase: Word; {Set path and initialize}
  Var
    OpenError: Word;
    CheckMode: Word;
    {$IFDEF VirtualPascal}
    NumRead: LongInt;
    {$ELSE}
    NumRead: Word;
    {$ENDIF}

  Begin
  OpenError := 0;
  If Not MsgRec^.Opened Then
    Begin
    CheckMode := Check;
    If CheckMode = 1 Then
      Begin
      OpenError := CreateMsgBase(100,100);
      If OpenError = 0 Then
        CheckMode := 0;
      End;
    If CheckMode = 2 Then
      OpenError := 5000;
    If CheckMode = 0 Then
      Begin
      FileMode := fmReadWrite + fmDenyNone;
      If Not ShReset(MsgRec^.MsgIdxFile, SizeOf(MsgIdxType)) Then
        OpenError := MKFileError;
      FileMode := fmReadWrite + fmDenyNone;
      If Not shReset(MsgRec^.MsgToIdxFile, SizeOf(MsgToIdxType)) Then
        OpenError := MKFileError;
      FileMode := fmReadWrite + fmDenyNone;
      If Not shReset(MsgRec^.MsgTxtFile, SizeOf(MsgTxtType)) Then
        OpenError := MKFileError;
      FileMode := fmReadWrite + fmDenyNone;
      If Not shReset(MsgRec^.MsgHdrFile, SizeOf(MsgHdrType)) Then
        OpenError := MKFileError;
      FileMode := fmReadWrite + fmDenyNone;
      If Not shReset(MsgRec^.MsgInfoFile, SizeOf(MsgInfoType)) Then
        OpenError := MKFileError;
      End;
    End;
  If OpenError = 0 Then
    Begin
    If Not shRead(MsgRec^.MsgInfoFile, MsgRec^.MsgInfo,1,NumRead) Then
      OpenError := 1;
    End;
  MsgRec^.Opened := (OpenError = 0);
  OpenMsgBase := OpenError;
  End;


Function HudsonMsgObj.CloseMsgBase: Word;         {Close Msg Base Files}
  Var
    w, CloseError: Word;

  Begin
  CloseError := 0;
  If MsgRec^.Opened Then
    Begin
    Close(MsgRec^.MsgIdxFile);
    If CloseError = 0 Then
      CloseError := IoResult;
    Close(MsgRec^.MsgToIdxFile);
    If CloseError = 0 Then
      CloseError := IoResult;
    Close(MsgRec^.MsgTxtFile);
    If CloseError = 0 Then
      CloseError := IoResult;
    Close(MsgRec^.MsgHdrFile);
    If CloseError = 0 Then
      CloseError := IoResult;
    Close(MsgRec^.MsgInfoFile);
    If CloseError = 0 Then
      CloseError := IoResult;
    End;
  w := IoResult;
  CloseMsgBase := CloseError;
  End;


Procedure HudsonMsgObj.SeekRead(NumToRead: Word);
Begin
  If NumToRead > SeekSize Then
    NumToRead := SeekSize;
  Seek(MsgRec^.MsgIdxFile, MsgRec^.SeekStart);
  If IoResult <> 0 Then;
  If Not shRead(MsgRec^.MsgIdxFile, SeekArray^, NumToRead , MsgRec^.SeekNumRead) Then
    MsgRec^.Error := 1000;
End;


Procedure HudsonMsgObj.SeekNext;
begin
  repeat
    Inc(MsgRec^.SeekPos);
    if (MsgRec^.SeekPos > MsgRec^.SeekNumRead) then begin
      Inc(MsgRec^.SeekStart, MsgRec^.SeekNumRead);
      SeekRead(SeekSize);
      MsgRec^.SeekPos := 1;
    end;
    if MsgRec^.SeekNumRead = 0 then begin
      MsgRec^.SeekOver := True;
      break;
    end else begin
      if (MsgRec^.SeekPos > 0) And (MsgRec^.SeekPos <= MsgRec^.SeekNumRead) and
         (SeekArray^[MsgRec^.SeekPos].MsgNum <> $ffff) and
         (SeekArray^[MsgRec^.SeekPos].Area = MsgRec^.Area) then Inc(MsgRec^.RealMsgNum);
      if ((MsgRec^.SeekPos > 0) And (MsgRec^.SeekPos <= MsgRec^.SeekNumRead)) and
          (SeekArray^[MsgRec^.SeekPos].MsgNum > MsgRec^.CurrMsgNum) and
          (SeekArray^[MsgRec^.SeekPos].MsgNum <> $ffff) and
          (SeekArray^[MsgRec^.SeekPos].Area = MsgRec^.Area) then
      begin
        MsgRec^.CurrMsgNum := SeekArray^[MsgRec^.SeekPos].MsgNum;
        break;
      end;
    end;
  until false;
  MsgRec^.MsgPos := Word(MsgRec^.SeekStart + MsgRec^.SeekPos - 1);
end;


procedure HudsonMsgObj.SeekPrior;
var
  SeekDec: Word;
begin
  MsgRec^.SeekOver := False;
  repeat
    Dec(MsgRec^.SeekPos);
    if (MsgRec^.SeekPos < 1) then begin
      if MsgRec^.SeekStart = 0 then begin
        MsgRec^.SeekOver := True;
        break;
      end;
      if (MsgRec^.SeekStart < SeekSize) then
        SeekDec := MsgRec^.SeekStart
      else
        SeekDec := SeekSize;
      Dec(MsgRec^.SeekStart, SeekDec);
      if MsgRec^.SeekStart < 0 then MsgRec^.SeekStart := 0;
      SeekRead(SeekDec);
      MsgRec^.SeekPos := MsgRec^.SeekNumRead;
    end;
    if not MsgRec^.SeekOver then begin
      if (MsgRec^.SeekPos > 0) And (MsgRec^.SeekPos <= MsgRec^.SeekNumRead) and
         (SeekArray^[MsgRec^.SeekPos].MsgNum <> $ffff) and
         (SeekArray^[MsgRec^.SeekPos].Area = MsgRec^.Area) then Dec(MsgRec^.RealMsgNum);
      if ((SeekArray^[MsgRec^.SeekPos].MsgNum < MsgRec^.CurrMsgNum) and
          (SeekArray^[MsgRec^.SeekPos].MsgNum <> $ffff) and
          (SeekArray^[MsgRec^.SeekPos].Area = MsgRec^.Area) and
          (MsgRec^.SeekPos > 0) and (MsgRec^.SeekPos <= MsgRec^.SeekNumRead)) then begin
        MsgRec^.CurrMsgNum := SeekArray^[MsgRec^.SeekPos].MsgNum;
        break;
      end;
    end;
  until false;
  MsgRec^.MsgPos := Word(MsgRec^.SeekStart + MsgRec^.SeekPos);
  if MsgRec^.MsgPos>0 then dec(MsgRec^.MsgPos);
end;


Function HudsonMsgObj.SeekFound:Boolean;   {Seek has been completed}
Begin
  SeekFound := Not MsgRec^.SeekOver;
End;


Procedure HudsonMsgObj.SeekFirst(MsgNum: LongInt);
  Begin
  MsgRec^.SeekStart := 0;
  MsgRec^.SeekNumRead := 0;
  MsgRec^.SeekPos := 0;
  MsgRec^.SeekOver := False;
  MsgRec^.RealMsgNum := 0;
  SeekRead(SeekSize);
  if msgnum=0 then
    MsgRec^.CurrMsgNum := 0
  else
    MsgRec^.CurrMsgNum := MsgNum - 1;
  SeekNext;
  End;


Procedure HudsonMsgObj.SetMailType(MT: MsgMailType);
  Begin
  MsgRec^.MT := MT;
  End;


Function HudsonMsgObj.GetSubArea: Word;
  Begin
  GetSubArea := MsgRec^.MsgHdr.Area;
  End;


Procedure HudsonMsgObj.ReWriteHdr;
  Var
    NumRead: Word;
    RcvdName: String[35];
    MsgError: Word;
    MsgIdx: MsgIdxType;

  Begin
  MsgError := SeekMsgBasePos(MsgRec^.MsgPos);
  If IsRcvd Then
    RcvdName := '* Received *'
  Else
    RcvdName := MsgRec^.MsgHdr.MsgTo;
  If IsDeleted Then
    Begin
    RcvdName := '* Deleted *';
    MsgIdx.MsgNum := $ffff;
    End
  Else
    MsgIdx.MsgNum := MsgRec^.MsgHdr.MsgNum;
  If MsgError = 0 Then
    Begin
    If not shWrite(MsgRec^.MsgHdrFile, MsgRec^.MsgHdr,1) Then
      MsgError := MKFileError;
    End;
  If MsgError = 0 Then
    Begin
    If Not shWrite(MsgRec^.MsgToIdxFile, RcvdName, 1) Then
      MsgError := MKFileError;
    End;
  MsgIdx.Area := MsgRec^.MsgHdr.Area;
  If MsgError = 0 Then
    Begin
    If not shWrite(MsgRec^.MsgIdxFile, MsgIdx,1) Then
      MsgError := MKFileError;
    End;
  End;


Procedure HudsonMsgObj.DeleteMsg;
  Var
    {$IFDEF VirtualPascal}
    NumRead: LongInt;
    {$ELSE}
    NumRead: Word;
    {$ENDIF}
    RcvdName: String[35];
    MsgIdx: MsgIdxType;
    MsgError: Word;

  Begin
  MsgIdx.Area := MsgRec^.MsgHdr.Area;
  If LockMsgBase Then
    MsgError := 0
  Else
    MsgError := 5;
  If MsgError = 0 Then
    MsgError := SeekMsgBasePos(MsgRec^.MsgPos);
  If MsgError = 0 Then
    Begin
    If not shRead(MsgRec^.MsgHdrFile, MsgRec^.MsgHdr,1, NumRead) Then
      MsgError := MKFileError;
    End;
  If ((MsgRec^.MsgHdr.MsgAttr and maDeleted) = 0) Then
    Begin
    Dec(MsgRec^.MsgInfo.Active);
    Dec(MsgRec^.MsgInfo.AreaActive[MsgRec^.MsgHdr.Area]);
    End;
  MsgRec^.MsgHdr.MsgAttr := MsgRec^.MsgHdr.MsgAttr Or maDeleted;
  RcvdName := '* Deleted *';
  MsgIdx.MsgNum := $ffff;
  If MsgError = 0 Then
    MsgError := SeekMsgBasePos(MsgRec^.MsgPos);
  If MsgError = 0 Then
    Begin
    If not shWrite(MsgRec^.MsgHdrFile, MsgRec^.MsgHdr,1) Then
      MsgError := MKFileError;
    End;
  If MsgError = 0 Then
    If Not shWrite(MsgRec^.MsgToIdxFile, RcvdName, 1) Then
      MsgError := MKFileError;
  If MsgError = 0 Then
    If Not shWrite(MsgRec^.MsgIdxFile, MsgIdx, 1) Then
      MsgError := MKFileError;
  If MsgError = 0 Then
    If Not UnLockMsgBase Then
      MsgError := 5;
  End;


Function HudsonMsgObj.GetMsgLoc: LongInt;
  Begin
  GetMsgLoc := MsgRec^.MsgPos;
  End;


Procedure HudsonMsgObj.SetMsgLoc(ML: LongInt);
  Begin
  MsgRec^.MsgPos := ML;
  End;


Function HudsonMsgObj.NumberOfMsgs: LongInt;
Var
  TmpInfo : Word;
  f: file;

Begin
  if ioresult<>0 then;
  assign(f,MsgRec^.MsgPath+'MsgInfo.Bbs');
  FileMode := fmReadOnly + fmDenyNone;
  reset(f,1);
  FileMode:=fmReadWrite;
  seek(f,6+pred(MsgRec^.Area)*sizeof(TmpInfo));
  blockread(f,TmpInfo,Sizeof(TmpInfo));
  close(f);
  if ioresult<>0 then NumberOfMsgs:=0 else NumberOfMsgs:=TmpInfo;
End;


function HudsonMsgObj.GetLastRead: LongInt;
var
  LRec     : Word;
  f        : file;
begin
  if ioresult <> 0 then;
  FileMode := fmReadOnly or fmDenyNone;
  Assign(f, MsgRec^.MsgPath + HudsonLastRead);
  Reset(f, 1);
  Seek(f, ((MsgRec^.Area - 1) * Sizeof(LRec)));
  Blockread(f, LRec, Sizeof(LRec));
  close(f);
  if ioresult <> 0 then
    GetLastRead := 0
  else
    GetLastRead := LRec;
end;

procedure HudsonMsgObj.SetLastRead(LR: LongInt);
type
  TBuf = array[1..4000] of byte;
var
  LRec   : Word;
  Num    : Word;
  Buf    : ^TBuf;
  f      : file;
begin
  if ioresult <> 0 then;
  New(Buf);
  fillchar(Buf^, sizeof(Buf^), 0);
  LRec := LR;
  FileMode := fmReadWrite or fmDenyNone;
  Assign(f, MsgRec^.MsgPath + HudsonLastRead);
  Reset(f, 1);
  if ioresult <> 0 then Rewrite(f, 1);
  if 1 * Sizeof(LastReadType) > FileSize(f) then
  begin
    Seek(f, Filesize(f));
    while (Sizeof(LastReadType) > FileSize(f)) and (ioresult = 0) do
    begin
      Num := (Sizeof(LastReadType)) - FileSize(f);
      if Num > 4000 then Num := 4000;
      Blockwrite(f, Buf^, Num);
    end;
  end;
  Seek(f, ((MsgRec^.Area - 1) * Sizeof(LRec)));
  Blockwrite(f, LRec, Sizeof(LRec));
  Close(f);
  if ioresult <> 0 then;
  Dispose(Buf);
end;

Procedure HudsonMsgObj.GetHighest(Var LR: LastReadType);
  Var
    i: Word;
    IdxFile: File;
    MIdx: ^SeekArrayType;
    {$IFDEF VirtualPascal}
    NumRead: LongInt;
    {$ELSE}
    NumRead: Word;
    {$ENDIF}

  Begin
  New(MIdx);
  For i := 1 to 200 Do
    LR[i] := 0;
  Assign(IdxFile, MsgRec^.MsgPath + 'MsgIdx.Bbs');
  FileMode := fmReadOnly + fmDenyNone;
  If shReset(IdxFile, SizeOf(MsgIdxType)) Then;
  While Not(Eof(IdxFile)) Do
    Begin
    If shRead(IdxFile, MIdx^, SeekSize, NumRead) Then;
    i := 1;
    While i <= NumRead Do
      Begin
      If MIdx^[i].MsgNum <> $ffff Then
        Begin
        If MIdx^[i].MsgNum > LR[MIdx^[i].Area] Then
          LR[MIdx^[i].Area] := MIdx^[i].MsgNum;
        End;
      Inc(i);
      End;
    End;
  Close(IdxFile);
  If IoResult <> 0 Then;
  Dispose(MIdx);
  End;


Function HudsonMsgObj.GetTxtPos: LongInt;
  Var
    Tmp: LongInt;

  Begin
  Tmp := MsgRec^.CurrTxtRec;
  GetTxtPos := MsgRec^.CurrTxtPos +  Tmp shl 16;
  End;


Procedure HudsonMsgObj.SetTxtPos(TP: LongInt);
  Begin
  MsgRec^.CurrTxtRec := TP shr 16;
  MsgRec^.CurrTxtPos := TP and $ffff;
  End;


Function HudsonMsgObj.GetString: String;
  Var
    Rec: Word;
    PPos: Word;
    CurrLen: Byte;
    WRec: Word;
    WPos: Word;
    WLen: Byte;
    StrDone: Boolean;
    TxtOver: Boolean;
    StartSoft: Boolean;

  Begin
  StrDone := False;
  CurrLen := 0;
  Rec := MsgRec^.CurrTxtRec;
  PPos := MsgRec^.CurrTxtPos;
  TxtOver := Not NextChar(Rec, PPos);
  If TxtOver Then
    EOM := True;
  WLen := 0;
  WRec := Rec;
  WPos := PPos;
  StartSoft := Wrapped;
  Wrapped := True;
  While ((Not StrDone) And (CurrLen < MaxLen) And (Not TxtOver)) Do
    Begin
    Case MsgChars^[Rec][PPos] of
      #$0d: Begin
            StrDone := True;
            Wrapped := False;
            End;
      #$8d:;
      #$0a:;
      #$20: Begin
            If ((CurrLen <> 0) or (Not StartSoft)) Then
              Begin
              Inc(CurrLen);
              GetString[CurrLen] := MsgChars^[Rec][PPos];
              WLen := CurrLen;
              WRec := Rec;
              WPos := PPos;
              End
            Else
              StartSoft := False;
            End;
      Else
        Begin
        Inc(CurrLen);
        GetString[CurrLen] := MsgChars^[Rec][PPos];
        End;
      End;
    Inc(PPos);
    TxtOver := Not NextChar(Rec, PPos);
    End;
  If StrDone Then
    Begin
    GetString[0] := Chr(CurrLen);
    MsgRec^.CurrTxtRec := Rec;
    MsgRec^.CurrTxtPos := PPos;
    End
  Else
    If TxtOver Then
      Begin
      GetString[0] := Chr(CurrLen);
      MsgRec^.CurrTxtRec := Rec;
      MsgRec^.CurrTxtPos := PPos;
      If CurrLen = 0 Then EOM := True;
      End
    Else
      Begin
      If WLen = 0 Then
        Begin
        GetString[0] := Chr(CurrLen);
        MsgRec^.CurrTxtRec := Rec;
        MsgRec^.CurrTxtPos := PPos;
        End
      Else
        Begin
        GetString[0] := Chr(WLen);
        Inc(WPos);
        NextChar(WRec, WPos);
        MsgRec^.CurrTxtPos := WPos;
        MsgRec^.CurrTxtRec := WRec;
        End;
      End;
  End;

Function HudsonMsgObj.GetRealMsgNum: LongInt;
begin
  GetRealMsgNum:=MsgRec^.RealMsgNum;
end;

function HudsonMsgObj.SetRead(RS: Boolean): boolean;
begin
(*  if IsRead=false then begin
    if RS then
      inc(MsgRec^.MsgHdr.TimesRead)
    else
      MsgRec^.MsgHdr.TimesRead:=0;
    SetRead:=true;
  end else
    SetRead:=false; *)
   SetRead := True;
end;

function HudsonMsgObj.IsRead: Boolean;
begin
{  IsRead:=(MsgRec^.MsgHdr.TimesRead>0);}
  IsRead := False;
end;

end.
