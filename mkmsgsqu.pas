{ $O+,F+,I-,S-,R-,V-,X+}
Unit MKMsgSqu;

{$IfDef FPC}
 {$PackRecords 1}
{$EndIf}

Interface

Uses MKGlobT, MKMsgAbs, GeneralP;

{ $I FILEMODE.INC}
{--- begin FILEMODE.INC ---}
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
{--- end FILEMODE.INC ---}

Const
  SqHdrId = $AFAE4453;
  SqLinkNext = 0;
  SqLinkPrev = 1;
  SqNullFrame = 0;
  SqFrameMsg = 0;
  SqFrameFree = 1;
  SqFrameRLE = 2;
  SqFrameLZW = 3;
  SqFromSize = 36;
  SqToSize = 36;
  SqSubjSize = 72;
  SqMaxReply = 10;


Type SqBaseType = Record
  Len: Word; {Length of this record}
  Rsvd1: Word; {Future use}
  NumMsg: LongInt; {Number of messages}
  HighMsg: LongInt; {Highest msg}
  SkipMsg: LongInt; {# of msgs to keep in beginning of area}
  HighWater: LongInt; {High water UMsgId}
  Uid: LongInt; {Next UMsgId}
  Base: String[79]; {Base name of Squish file}
  BeginFrame: LongInt; {Offset of first frame in file}
  LastFrame: LongInt; {Offset of last frame in file}
  FirstFree: LongInt; {Offset of first free frame in file}
  LastFree: LongInt; {Offset of last free frame in file}
  EndFrame: LongInt; {Pointer to end of file}
  MaxMsg: LongInt; {Maximum number of messages}
  KeepDays: Word; {Maximum age of messages}
  SqHdrSize: Word; {Size of frame header}
  Rsvd2: Array[1..124] of Byte; {Future use}
  End;


Type SqFrameHdrType = Record
  Id: LongInt; {Must equal SqHdrId}
  NextFrame: LongInt; {Next msg frame}
  PrevFrame: LongInt; {Prior msg frame}
  FrameLength: LongInt; {Length of this frame not counting header}
  MsgLength: LongInt; {Length of message}
  ControlLength: LongInt; {Length of control information}
  FrameType: Word; {Type of message frame}
  Rsvd: Word; {Future use}
  End;


Type SqMsgHdrType = Record
  Attr: LongInt; {Msg attribute}
  MsgFrom: String[SqFromSize - 1]; {Nul Term from name}
  MsgTo: String[SqToSize - 1]; {Nul term to name}
  Subj: String[SqSubjSize - 1]; {Nul term subject}
  Orig: OldAddrType; {Origin address}
  Dest: OldAddrType; {Destination address}
  DateWritten: LongInt; {Date/Time msg written}
  DateArrived: LongInt; {Date/Time msg arrived here}
  UtcOffset: Word; {Minutes offset from UTC}
  ReplyTo: LongInt; {Original msg}
  Replies: Array[1..SqMaxReply] of LongInt; {Replies}
  AzDate: String[19]; {AsciiZ "Fido" style date}
  End;


Type SqIdxType = Record
  Ofs: LongInt; {Offset of frame header}
  UMsgId: LongInt; {Unique message id}
  Hash: LongInt; {Hash of MsgTo name}
  End;


Const
{$IFDEF OS2}
  SqIdxArraySize = 16384;
{$ELSE}
  SqIdxArraySize = 5400;  {5200}
{$ENDIF}

Type SqIdxArrayType = Array[1..SqIdxArraySize] of SqIdxType;

Type SqIdxPtrType = ^SqIdxArrayType;

Type FreeListType = Record
  FreePos: LongInt;
  FreeSize: LongInt;
  End;

Const MaxFree = 500;

Type FreeArrayType = Array[1..MaxFree] of FreeListType;

Const
  SqBSize: Word = SizeOf(SqBaseType);
  SqFSize: Word = SizeOf(SqFrameHdrType);
  SqMSize: Word = SizeOf(SqMsgHdrType);
  SqISize: Word = SizeOf(SqIdxType);


Const
  SqTxtBufferSize = 34000;  {34000}

Type SqInfoType = Record
  FN: String[80];
  MsgChars: Array[1..SqTxtBufferSize] of Char;
  Error: Word;
  FreeLoaded: Boolean;
  SqdFile: File;
  SqIFile: File;
  SqBase: SqBaseType;
  SqBaseExtra: Array[1..100] of Char;
  SqdOpened: Boolean;
  SqiOpened: Boolean;
  SqiAlloc: Word;
  Locked: Boolean;
  HighestFree: Word;
  Frame: SqFrameHdrType;
  MsgHdr: SqMsgHdrType;
  Extra: Array[1..100] of Char;
  TxtCtr: Word;
  CurrIdx: Word;
  StrDate: String[8];
  StrTime: String[8];
  CurrentFramePos: LongInt;
  CurrentUID: LongInt;
  SName: String[35];
  SHandle: String[35];
  HName: LongInt;
  HHandle: LongInt;
  End;


Type SqMsgObj = Object(AbsMsgObj)
  SqInfo: ^SqInfoType;
  SqIdx: ^SqIdxArrayType;
  IndexRead: Boolean;
  FreeArray: ^FreeArrayType;
  Constructor Init; {Initialize}
  Destructor Done; Virtual; {Done cleanup and dispose}
  function  GetID: Byte; Virtual;
  Function  OpenMsgBase: Word; Virtual; {Open message base}
  Function  CloseMsgBase: Word; Virtual; {Close message base}
  Function  CreateMsgBase(MaxMsg: Word; MaxDays: Word): Word; Virtual;
  Function  MsgBaseExists: Boolean; Virtual;
  Procedure SetMsgPath(FN: String); Virtual; {Set filepath and name - no extension}
  Function  SqdOpen: Word; Virtual; {Open squish data file}
  Function  SqiOpen: Word; Virtual; {Open squish index file}
  Procedure SqdClose; Virtual; {Close squish data file}
  Procedure SqiClose; Virtual; {Close squish index file}
  Function  LockMsgBase: Boolean; Virtual; {Lock msg base}
  Function  UnLockMsgBase: Boolean; Virtual; {Unlock msg base}
  Procedure ReadBase; Virtual; {Read base data record}
  Procedure WriteBase; Virtual; {Write base data record}
  Function  GetBeginFrame: LongInt; Virtual; {Get beginning frame pos}
  Function  GetHighWater: LongInt; Virtual; {Get high water umsgid}
  Function  GetHighMsgNum: LongInt; Virtual; {Get highest msg number}
  Procedure ReadFrame(FPos: LongInt); Virtual; {Read frame at FPos}
  Procedure ReadVarFrame(Var Frame: SqFrameHdrType; FPos: LongInt); Virtual; {Read frame at FPos into Frame}
  Procedure WriteFrame(FPos: LongInt); Virtual; {Write frame at FPos}
  Procedure WriteVarFrame(Var Frame: SqFrameHdrType; FPos: LongInt); Virtual;
  Procedure UnlinkFrame(Var Frame: SqFrameHdrType); Virtual; {Unlink frame from linked list}
  Procedure LinkFrameNext(Var Frame: SqFrameHdrType; OtherFrame: LongInt;
    FramePos: LongInt); Virtual; {Link frame after other frame}
  Procedure KillMsg(MsgNum: LongInt); {Kill msg msgnum}
  Procedure KillExcess; {Kill msg in excess of limit}
  Procedure FindFrame(Var FL: LongInt; Var FramePos: LongInt); Virtual;
  Function  GetNextFrame: LongInt; Virtual; {Get next frame pos}
  Procedure ReadMsgHdr(FPos: LongInt); Virtual; {Read msg hdr for frame at FPos}
  Procedure WriteMsgHdr(FPos: LongInt); Virtual; {Read msg hdr for frame at FPos}
  Procedure WriteText(FPos: LongInt); Virtual; {Write text buffer for frame at Fpos}
  Function  SqHashName(Name: String): LongInt; Virtual; {Convert name to hash value}
  Procedure StartNewMsg; Virtual; {Initialize msg header}
  Function  GetFrom: String; Virtual; {Get message from}
  Function  GetTo: String; Virtual; {Get message to}
  Function  GetSubj: String; Virtual; {Get message subject}
  Procedure SetFrom(Str: String); Virtual; {Set message from}
  Procedure SetTo(Str: String); Virtual; {Set message to}
  Procedure SetSubj(Str: String); Virtual; {Set message subject}
  Procedure SetDate(Str: String); Virtual; {Set message date}
  Procedure SetTime(Str: String); Virtual; {Set message time}
  function  SetRead(RS: Boolean): boolean; virtual;
  Function  IsRead: Boolean; Virtual; {Is current msg received}
  Function  GetDate: String; Virtual; {Get message date mm-dd-yy}
  Function  GetTime: String; Virtual; {Get message time hh:mm}
  Function  GetRefer: LongInt; Virtual; {Get reply to of current msg}
  Procedure SetRefer(Num: LongInt); Virtual; {Set reply to of current msg}
  Function  GetSeeAlso: LongInt; Virtual; {Get see also msg}
  Procedure SetSeeAlso(Num: LongInt); Virtual; {Set see also msg}
  Procedure ReadText(FPos: LongInt); Virtual;
  Function  GetChar: Char; Virtual;
  Function  GetString: String; Virtual;
  Procedure GetOrig(Var Addr: AddrType); Virtual;
  Procedure SetOrig(Var Addr: AddrType); Virtual;
  Procedure GetDest(Var Addr: AddrType); Virtual;
  Procedure SetDest(Var Addr: AddrType); Virtual;
  Procedure InitText; Virtual;
  Procedure DoString(Str: String); Virtual; {Add string to message text}
  Procedure DoChar(Ch: Char); Virtual; {Add character to message text}
  Procedure DoStringLn(Str: String); Virtual; {Add string and newline to msg text}
  Function  WriteMsg: Word; Virtual; {Write msg to msg base}
  Procedure ReadIdx; Virtual;
  Procedure WriteIdx; Virtual;
  Procedure SeekFirst(MsgNum: LongInt); Virtual; {Seeks to 1st msg >= MsgNum}
  Function  GetMsgNum: LongInt; Virtual;
  Procedure SeekNext; Virtual;
  Procedure SeekPrior; Virtual;
  Function  SeekFound: Boolean; Virtual;
  Function  GetIdxFramePos: LongInt; Virtual;
  Function  GetIdxHash: LongInt; Virtual;
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
  Function  IsHold: Boolean; Virtual; {Is current msg hold}
  Function  IsDeleted: Boolean; Virtual; {Is current msg deleted}
  Procedure SetAttr(St: Boolean; Mask: LongInt); Virtual; {Set attribute}
  Procedure SetLocal(St: Boolean); Virtual; {Set local status}
  Procedure SetRcvd(St: Boolean); Virtual; {Set received status}
  Procedure SetPriv(St: Boolean); Virtual; {Set priveledge vs public status}
  Procedure SetCrash(St: Boolean); Virtual; {Set crash netmail status}
  Procedure SetKillSent(St: Boolean); Virtual; {Set kill/sent netmail status}
  Procedure SetSent(St: Boolean); Virtual; {Set sent netmail status}
  Procedure SetFAttach(St: Boolean); Virtual; {Set file attach status}
  Procedure SetReqRct(St: Boolean); Virtual; {Set request receipt status}
  Procedure SetReqAud(St: Boolean); Virtual; {Set request audit status}
  Procedure SetRetRct(St: Boolean); Virtual; {Set return receipt status}
  Procedure SetFileReq(St: Boolean); Virtual; {Set file request status}
  procedure setHold(sh : Boolean); virtual; {set hold status}
  Procedure InitMsgHdr; Virtual; {Set up message}
  Procedure MsgTxtStartUp; Virtual;
  Procedure SetMailType(MT: MsgMailType); Virtual; {Set message base type}
  Function  GetSubArea: Word; Virtual; {Get sub area number}
  Procedure ReWriteHdr; Virtual; {Rewrite msg header after changes}
  Procedure DeleteMsg; Virtual; {Delete current message}
  Procedure LoadFree; Virtual; {Load freelist into memory}
  Function  NumberOfMsgs: LongInt; Virtual; {Number of messages}
  Procedure SetEcho(ES: Boolean); Virtual; {Set echo status}
  Function  IsEchoed: Boolean; Virtual; {Is current msg unmoved echomail msg}
  Function  GetLastRead: LongInt; Virtual; {Get last read for user num}
  Procedure SetLastRead(LR: LongInt); Virtual; {Set last read}
  Function  GetMsgLoc: LongInt; Virtual; {To allow reseeking to message}
  Procedure SetMsgLoc(ML: LongInt); Virtual; {Reseek to message}
  Function  IdxHighest: LongInt; Virtual; { *** }
  Function  GetMsgDisplayNum: LongInt; Virtual; {Get msg number to display}
  Function  GetTxtPos: LongInt; Virtual; {Get indicator of msg text position}
  Procedure SetTxtPos(TP: LongInt); Virtual; {Set text position}
  Function  GetRealMsgNum: LongInt; Virtual;
  End;

Type SqMsgPtr = ^SqMsgObj;

procedure GetSquishInfo(fn: string; var cur, msgs: longint);

Implementation

Uses MKFile, MKString, MKDos, Dos {, Global};

Const
  SqMsgPriv =   $00001;
  SqMsgCrash =  $00002;
  SqMsgRcvd =   $00004;
  SqMsgSent =   $00008;
  SqMsgFile =   $00010;
  SqMsgFwd =    $00020;
  SqMsgOrphan = $00040;
  SqMsgKill =   $00080;
  SqMsgLocal =  $00100;
  SqMsgHold =   $00200;
  SqMsgXX2 =    $00400;
  SqMsgFreq =   $00800;
  SqMsgRrq =    $01000;
  SqMsgCpt =    $02000;
  SqMsgArq =    $04000;
  SqMsgUrg =    $08000;
  SqMsgScanned= $10000;
  SqMsgRead   = $80000000;


Constructor SqMsgObj.Init;
begin
  New(SqInfo);
  New(FreeArray);
  if (SqInfo = nil) or (FreeArray=nil) then begin
    if SqInfo <> Nil then Dispose(SqInfo);
    if FreeArray <> Nil then Dispose(FreeArray);
    Fail;
    Exit;
  end;
  with SqInfo^ do begin
    SqdOpened := False;
    SqiOpened := False;
    FN := '';
    Error := 0;
    Locked := False;
    FreeLoaded:=false;
    SqiAlloc := 0;
  end;
  End;


Destructor SqMsgObj.Done;
  Begin
  If SqInfo^.SqdOpened Then SqdClose;
  If SqInfo^.SqiOpened Then SqiClose;
  If SqInfo^.SqIAlloc > 0 Then
    If SqIdx <> Nil Then
      FreeMem(SqIdx, SqInfo^.SqiAlloc * SizeOf(SqIdxType));
  Dispose(FreeArray);
  Dispose(SqInfo);
  End;


function  SqMsgObj.GetID: Byte;
begin
  GetID:=msgSquish;
end;


Procedure SqMsgObj.SetMsgPath(FN: String);
  Begin
  SqInfo^.FN := FExpand(FN);
  If Pos('.SQD', UpStr(SqInfo^.FN)) > 0 Then
    SqInfo^.FN := Copy(SqInfo^.FN,1,Pos('.SQD', UpStr(SqInfo^.FN)) - 1);
  End;


Function SqMsgObj.OpenMsgBase: Word;
Var
 Error: Word;

  Begin
  Error := SqiOpen;
  If Error = 0 Then
    Begin
    Error := SqdOpen;
    If (Error = 0) then
     Begin
     ReadIdx;
     OpenMsgBase := 0;
     End
    Else
     Begin
     SqiClose;
     OpenMsgBase := Error;
     End;
    End
  Else
    OpenMsgBase := Error;
  End;


Function SqMsgObj.SqdOpen: Word;
  Var
    {$IFDEF VirtualPascal}
    NumRead: LongInt;
    {$ELSE}
    NumRead: Word;
    {$ENDIF}

  Begin
  If Not SqInfo^.SqdOpened Then
    Begin
    Assign(SqInfo^.SqdFile, SqInfo^.FN + '.sqd');
    FileMode := fmReadWrite + fmDenyNone;
    If Not shReset(SqInfo^.SqdFile, 1) Then
      SqdOpen := MKFileError
    Else
      Begin
      SqInfo^.SqdOpened := True;
      SqdOpen := 0;
      If Not shRead(SqInfo^.SqdFile, SqInfo^.SqBase, 2, NumRead) Then
        SqdOpen := MKFileError
      Else
        Begin
        If SqInfo^.SqBase.Len = 0 Then
          SqInfo^.SqBase.Len := SqBSize;
        If SqInfo^.SqBase.Len > (SizeOf(SqBaseType) + 100) Then
          SqdOpen := 1001
        Else
          Begin
          SqBSize := SqInfo^.SqBase.Len;
          ReadBase;
          End;
        End;
      End;
    End
  Else
    SqdOpen := 0;
  End;


Function SqMsgObj.SqiOpen: Word;
  Begin
  If Not SqInfo^.SqiOpened Then
    Begin
    Assign(SqInfo^.SqiFile, SqInfo^.FN + '.sqi');
    FileMode := fmReadWrite + fmDenyNone;
    If Not shReset(SqInfo^.SqiFile, SizeOf(SqIdxType)) Then
      SqiOpen := MKFileError
    Else
      Begin
      SqInfo^.SqiOpened := True;
      SqiOpen := 0;
      End;
    End
  Else
    SqiOpen := 0;
  End;


Function SqMsgObj.CloseMsgBase: Word;
  Begin
  SqdClose;
  SqiClose;
  CloseMsgBase := 0;
  End;


Function SqMsgObj.CreateMsgBase(MaxMsg: Word; MaxDays: Word): Word;
  Var
    i: Word;

  Begin
  If Not SqInfo^.SqdOpened Then
    Begin
    i := PosLastChar(DirSep, SqInfo^.FN);
    If i > 0 Then
      Begin
      If MakePath(Copy(SqInfo^.FN, 1, i)) Then;
      End;
    FillChar(SqInfo^.SqBase, SizeOf(SqInfo^.SqBase), 0);
    SqInfo^.SqBase.Len := 256;
    SqInfo^.SqBase.SqHdrSize := SqFSize;
    SqInfo^.SqBase.UID := 1;
    SqInfo^.SqBase.NumMsg := 0;
    SqInfo^.SqBase.Base := SqInfo^.FN;
    Str2Az(SqInfo^.FN, 78, SqInfo^.SqBase.Base);
    SqInfo^.SqBase.MaxMsg := MaxMsg;
    SqInfo^.SqBase.KeepDays := MaxDays;
    SqInfo^.SqBase.EndFrame := SqInfo^.SqBase.Len;
    CreateMsgBase := SaveFile(SqInfo^.FN + '.sqd', SqInfo^.SqBase, SqInfo^.SqBase.Len);
    If SaveFile(SqInfo^.FN + '.sqi', SqInfo^.SqBase, 0) = 0 Then;
    If SaveFile(SqInfo^.FN + '.sql', SqInfo^.SqBase, 0) = 0 Then;
    End
  Else
    CreateMsgBase := 176;
  End;


Function SqMsgObj.MsgBaseExists: Boolean;
  Begin
  MsgBaseExists :=  FileExist(SqInfo^.FN + '.sqd');
  End;


Procedure SqMsgObj.SqdClose;
  Begin
  If SqInfo^.SqdOpened Then
    Close(SqInfo^.SqdFile);
  If IOResult <> 0 Then;
  SqInfo^.SqdOpened := False;
  End;


Function SqMsgObj.LockMsgBase: Boolean; {Lock msg base}
Begin
  If Not SqInfo^.Locked Then Begin
    SqInfo^.Locked := shLock(SqInfo^.SqdFile, 0, 1) = 0;
    LockMsgBase := SqInfo^.Locked;
    ReadBase;
    ReadIdx;
    SqInfo^.FreeLoaded:=false;
  end;
end;


Function SqMsgObj.UnLockMsgBase: Boolean; {Unlock msg base}
  Begin
  If SqInfo^.Locked Then
    Begin
    WriteBase;
    WriteIdx;
    SqInfo^.Locked := Not UnLockFile(SqInfo^.SqdFile, 0, 1) < 2;
    UnLockMsgBase := Not SqInfo^.Locked;
    End;
  End;


Procedure SqMsgObj.SqiClose;
  Begin
  If SqInfo^.SqiOpened Then
    Close(SqInfo^.SqiFile);
  If IoResult <> 0 Then;
  SqInfo^.SqiOpened := False;
  End;


Procedure SqMsgObj.ReadBase;
  Var
    {$IFDEF VirtualPascal}
    NumRead: LongInt;
    {$ELSE}
    NumRead: Word;
    {$ENDIF}

  Begin
  Seek(SqInfo^.SqdFile, 0);
  If Not shRead(SqInfo^.SqdFile, SqInfo^.SqBase, SqBSize, NumRead) Then
    SqInfo^.Error := MKFileError;
  If SqInfo^.SqBase.SqHdrSize = 0 Then
    SQInfo^.SqBase.SqHdrSize := SqFSize;
  SqFSize := SqInfo^.SqBase.SqHdrSize;
  End;


Procedure SqMsgObj.WriteBase;
  Begin
  Seek(SqInfo^.SqdFile, 0);
  If Not shWrite(SqInfo^.SqdFile, SqInfo^.SqBase, SQBSize) Then
    SqInfo^.Error := MKFileError;
  End;


Procedure SqMsgObj.StartNewMsg; {Initialize msg header}
  Begin
  FillChar(SqInfo^.MsgHdr, SizeOf(SqInfo^.MsgHdr), 0);
  FillChar(SqInfo^.Frame, SizeOf(SqInfo^.Frame), 0);
  SqInfo^.TxtCtr := 0;
  SqInfo^.StrDate := '';
  SqInfo^.StrTime := '';
  End;


Function SqMsgObj.GetFrom: String; {Get message from}
Var
 s: String;

  Begin
  Move(SqInfo^.MsgHdr.MsgFrom, s, SqFromSize);
{  s := SqInfo^.MsgHdr.MsgFrom;}
  GetFrom := Az2Str(s, SqFromSize);
  End;


Function SqMsgObj.GetTo: String; {Get message to}
Var
 s: String;

  Begin
  Move(SqInfo^.MsgHdr.MsgTo, s, SqToSize);
{  s := SqInfo^.MsgHdr.MsgTo;}
  GetTo := Az2Str(s, SqToSize);
  End;


Function SqMsgObj.GetSubj: String; {Get message subject}
Var
 s: String;

  Begin
  Move(SqInfo^.MsgHdr.Subj, s, SqSubjSize);
{  SqInfo^.MsgHdr.Subj := s;}
  GetSubj := Az2Str(s, SqSubjSize);
  End;


Procedure SqMsgObj.SetFrom(Str: String); {Set message from}
  Begin
  Str2Az(Str, 35, SqInfo^.MsgHdr.MsgFrom);
  End;


Procedure SqMsgObj.SetTo(Str: String); {Set message to}
  Begin
  Str2Az(Str,35, SqInfo^.MsgHdr.MsgTo);
  End;


Procedure SqMsgObj.SetSubj(Str: String); {Set message subject}
  Begin
  Str2Az(Str,72, SqInfo^.MSgHdr.Subj);
  End;


Function SqMsgObj.GetDate: String; {Get message date mm-dd-yy}
  Var
    TmpDate: LongInt;

  Begin
  TmpDate := (SqInfo^.MsgHdr.DateWritten shr 16) +
   ((SqInfo^.MsgHdr.DateWritten and $ffff) shl 16);
  GetDate := DateStr(TmpDate);
  End;


Function SqMsgObj.GetTime: String; {Get message time hh:mm}
  Var
    TmpDate: LongInt;

  Begin
  TmpDate := (SqInfo^.MsgHdr.DateWritten shr 16) +
   ((SqInfo^.MsgHdr.DateWritten and $ffff) shl 16);
  GetTime := TimeStr(TmpDate);
  End;


Procedure SqMsgObj.SetDate(Str: String);
  Begin
  SqInfo^.StrDate := Copy(Str,1,8);
  End;


Procedure SqMsgObj.SetTime(Str: String);
  Begin
  SqInfo^.StrTime := Copy(Str,1,8);
  End;


Procedure SqMsgObj.GetOrig(Var Addr: AddrType);
begin
  move(SqInfo^.MsgHdr.Orig, Addr, sizeof(SqInfo^.MsgHdr.Orig));
  Addr.domain := '';
end;


Procedure SqMsgObj.SetOrig(Var Addr: AddrType);
  Begin
  move(Addr, SqInfo^.MsgHdr.Orig, sizeof(SqInfo^.MsgHdr.Orig));
  End;


Procedure SqMsgObj.GetDest(Var Addr: AddrType);
  Begin
  move(SqInfo^.MsgHdr.Dest, Addr, sizeof(SqInfo^.MsgHdr.Dest));
  addr.domain := '';
  End;


Procedure SqMsgObj.SetDest(Var Addr: AddrType);
  Begin
  move(Addr, SqInfo^.MsgHdr.Dest, sizeof(SqInfo^.MsgHdr.Dest));
  End;


Function SqMsgObj.SqHashName(Name: String): LongInt;
  Var
    Hash: LongInt;
    Tmp: LongInt;
    Counter: Word;

  Begin
  Hash := 0;
  Counter := 1;
  While Counter <= Length(Name) Do
    Begin
    Hash := (Hash shl 4) + Ord(LoCase(Name[Counter]));
    Tmp := Hash and $F0000000;
    If (Tmp <> 0) Then
      Hash := (Hash or (Tmp shr 24)) or Tmp;
    Inc(Counter);
    End;
  SqHashName := Hash and $7fffffff;
  End;


Procedure SqMsgObj.ReadFrame(FPos: LongInt); {Read frame at FPos}
  Begin
  ReadVarFrame(SqInfo^.Frame, FPos);
  End;


Procedure SqMsgObj.ReadVarFrame(Var Frame: SqFrameHdrType; FPos: LongInt); {Read frame at FPos}
  Var
    {$IFDEF VirtualPascal}
    NumRead: LongInt;
    {$ELSE}
    NumRead: Word;
    {$ENDIF}

  Begin
  Seek(SqInfo^.SqdFile, FPos);
  SqInfo^.Error := IoResult;
  If SqInfo^.Error = 0 Then
    Begin
    If Not shRead(SqInfo^.SqdFile, Frame, SizeOf(SqFrameHdrType), NumRead) Then
      SqInfo^.Error := MKFileError;
    End;
  End;


Procedure SqMsgObj.WriteFrame(FPos: LongInt); {Read frame at FPos}
  Begin
  WriteVarFrame(SqInfo^.Frame, FPos);
  End;


Procedure SqMsgObj.WriteVarFrame(Var Frame: SqFrameHdrType; FPos: LongInt); {Write frame at FPos}
  Begin
  Seek(SqInfo^.SqdFile, FPos);
  SqInfo^.Error := IoResult;
  If SqInfo^.Error = 0 Then
    Begin
    If Not shWrite(SqInfo^.SqdFile, Frame, SizeOf(SqFrameHdrType)) Then
      SqInfo^.Error := MKFileError;
    End;
  End;



Procedure SqMsgObj.UnlinkFrame(Var Frame: SqFrameHdrType);
  Var
    TmpFrame: SqFrameHdrType;

  Begin
  If Frame.PrevFrame <> 0 Then
    Begin
    ReadVarFrame(TmpFrame, Frame.PrevFrame);
    TmpFrame.NextFrame := Frame.NextFrame;
    WriteVarFrame(TmpFrame, Frame.PrevFrame);
    End;
  If Frame.NextFrame <> 0 Then
    Begin
    ReadVarFrame(TmpFrame, Frame.NextFrame);
    TmpFrame.PrevFrame := Frame.PrevFrame;
    WriteVarFrame(TmpFrame, Frame.NextFrame);
    End;
  End;


Procedure SqMsgObj.LoadFree;
  Var
    i: Word;
    TmpFrame: SqFrameHdrType;
    TmpPos: LongInt;

  Begin
  SqInfo^.FreeLoaded:=true;
  FillChar(FreeArray^,Sizeof(FreeArray^),0);
  i := 0;
  TmpPos := SqInfo^.SqBase.FirstFree;
  While ((TmpPos <> 0) and (i < MaxFree)) Do
    Begin
    ReadVarFrame(TmpFrame, TmpPos);
    Inc(i);
    FreeArray^[i].FreeSize := TmpFrame.FrameLength;
    FreeArray^[i].FreePos := TmpPos;
    TmpPos := TmpFrame.NextFrame;
    End;
  SqInfo^.HighestFree := i;
  End;


Procedure SqMsgObj.FindFrame(Var FL: LongInt; Var FramePos: LongInt);
  Var
    TmpFrame: SqFrameHdrType;
    BestFoundPos: LongInt;
    BestFoundSize: LongInt;
    BestIdx: Word;
    i: Word;

  Begin
  If SqInfo^.FreeLoaded=false Then LoadFree;
  BestFoundPos := 0;
  BestFoundSize := 0;
  For i := 1 to SqInfo^.HighestFree Do
    Begin
    If (FreeArray^[i].FreeSize > FL) Then
      Begin
      If ((BestFoundSize = 0) or (FreeArray^[i].FreeSize < BestFoundSize)) Then
        Begin
        BestFoundSize := FreeArray^[i].FreeSize;
        BestFoundPos := FreeArray^[i].FreePos;
        BestIdx := i;
        End;
      End
    End;
  FramePos := BestFoundPos;
  If FramePos <> 0 Then
    Begin
    ReadVarFrame(TmpFrame, FramePos);
    FreeArray^[BestIdx].FreePos := 0;
    FreeArray^[BestIdx].FreeSize := 0;
    End;
  If FramePos = 0 Then
    Begin
    FL := 0;
    FramePos := SqInfo^.SqBase.EndFrame;
    End
  Else
    Begin
    UnLinkFrame(TmpFrame);
    If TmpFrame.PrevFrame = 0 Then
      SqInfo^.SqBase.FirstFree := TmpFrame.NextFrame;
    If TmpFrame.NextFrame = 0 Then
      SqInfo^.SqBase.LastFree := TmpFrame.PrevFrame;
    FL := TmpFrame.FrameLength;
    End;
  End;


Procedure SqMsgObj.LinkFrameNext(Var Frame: SqFrameHdrType; OtherFrame: LongInt;
  FramePos: LongInt);

  Var
    TmpFrame: SqFrameHdrType;

  Begin
  If OtherFrame <> 0 Then
    Begin
    ReadVarFrame(TmpFrame, OtherFrame);
    TmpFrame.NextFrame := FramePos;
    Frame.PrevFrame := OtherFrame;
    WriteVarFrame(TmpFrame, OtherFrame);
    End;
  End;


Procedure SqMsgObj.KillMsg(MsgNum: LongInt);
  Var
    i: Word;
    KillPos: LongInt;
    IndexPos: LongInt;
    KillFrame: SqFrameHdrType;
    TmpFrame: SqFrameHdrType;
    CurrMove: LongInt;
    AlreadyLocked: Boolean;
    FreeCtr: Word;

  Begin
  AlreadyLocked := SqInfo^.Locked;
  If Not AlreadyLocked Then
    If LockMsgBase Then;
  If SqIdx = Nil Then
    SqInfo^.Error := 999
  Else
    Begin
    i := 1;
    While ((i <= SqInfo^.SqBase.NumMsg) and (MsgNum <> SqIdx^[i].UMsgId)) Do
      Inc(i);
    If MsgNum = SqIdx^[i].UMsgId Then
      Begin
      IndexPos := i;
      KillPos := SqIdx^[i].Ofs;
      ReadVarFrame(KillFrame, KillPos);
      If KillFrame.PrevFrame = 0 Then
        SqInfo^.SqBase.BeginFrame := KillFrame.NextFrame;
      If KillFrame.NextFrame = 0 Then
        SqInfo^.SqBase.LastFrame := KillFrame.PrevFrame;
      KillFrame.FrameType := sqFrameFree;
      UnLinkFrame(KillFrame);
      If ((SqInfo^.SqBase.FirstFree = 0) or (SqInfo^.SqBase.LastFree = 0)) Then
        Begin
        SqInfo^.SqBase.FirstFree := KillPos;
        SqInfo^.SqBase.LastFree := KillPos;
        KillFrame.PrevFrame := 0;
        KillFrame.NextFrame := 0;
        End
      Else
        Begin
        KillFrame.NextFrame := 0;
        KillFrame.PrevFrame := SqInfo^.SqBase.LastFree;
        ReadVarFrame(TmpFrame, SqInfo^.SqBase.LastFree);
        TmpFrame.NextFrame := KillPos;
        WriteVarFrame(TmpFrame, SqInfo^.SqBase.LastFree);
        SqInfo^.SqBase.LastFree := KillPos;
        End;
      WriteVarFrame(KillFrame, KillPos);
      FreeCtr := 1;
      While ((FreeCtr < MaxFree) and (FreeArray^[FreeCtr].FreePos <> 0)) Do
        Inc(FreeCtr);
      If FreeArray^[FreeCtr].FreePos = 0 Then
        Begin
        FreeArray^[FreeCtr].FreePos := KillPos;
        FreeArray^[FreeCtr].FreeSize := KillFrame.FrameLength;
        End;
      If FreeCtr > SqInfo^.HighestFree Then
        SqInfo^.HighestFree := FreeCtr;
      Dec(SqInfo^.SqBase.NumMsg);
      Dec(SqInfo^.SqBase.HighMsg);
      CurrMove := IndexPos;
      While CurrMove <= SqInfo^.SqBase.NumMsg Do
        Begin
        SqIdx^[CurrMove] := SqIdx^[CurrMove + 1];
        Inc(CurrMove);
        End;
  {    NumMove := SqInfo^.SqBase.NumMsg + 1 - IndexPos;
      NumMove := NumMove * SizeOf(SqIdxType);
      Move(SqIdx^[IndexPos + 1], SqIdx^[IndexPos], NumMove);  }
      End;
    End;
  If Not AlreadyLocked Then
    If UnlockMsgBase Then;
  End;


Procedure SqMsgObj.ReadMsgHdr(FPos: LongInt); {Read msg hdr for frame at FPos}
  Var
    {$IFDEF VirtualPascal}
    NumRead: LongInt;
    {$ELSE}
    NumRead: Word;
    {$ENDIF}

  Begin
  Seek(SqInfo^.SqdFile, FPos + SqFSize);
  SqInfo^.Error := IoResult;
  If SqInfo^.Error = 0 Then
    Begin
    If Not shRead(SqInfo^.SqdFile, SqInfo^.MsgHdr, SizeOf(SqMsgHdrType), NumRead) Then
      SqInfo^.Error := MKFileError;
    End;
  End;


Procedure SqMsgObj.WriteMsgHdr(FPos: LongInt); {Read msg hdr for frame at FPos}
  Var
    NumRead: Word;

  Begin
  Seek(SqInfo^.SqdFile, FPos + SqFSize);
  SqInfo^.Error := IoResult;
  If SqInfo^.Error = 0 Then
    Begin
    If Not shWrite(SqInfo^.SqdFile, SqInfo^.MsgHdr, SizeOf(SqMsgHdrType)) Then
      SqInfo^.Error := MKFileError;
    End;
  End;


Procedure SqMsgObj.WriteText(FPos: LongInt); {Write text buffer for frame at Fpos}
  Begin
  Seek(SqInfo^.SqdFile, FPos + SqFSize + SqMSize);
  SqInfo^.Error := IoResult;
  If SqInfo^.Error = 0 Then
    Begin
    If Not shWrite(SqInfo^.SqdFile, SqInfo^.MsgChars, SqInfo^.TxtCtr) Then
      SqInfo^.Error := MKFileError;
    End;
  End;


Function SqMsgObj.GetBeginFrame: LongInt; {Get beginning frame pos}
  Begin
  GetBeginFrame := SqInfo^.SqBase.BeginFrame;
  End;


Function SqMsgObj.GetNextFrame: LongInt; {Get next frame pos}
  Begin
  GetNextFrame := SqInfo^.Frame.NextFrame;
  End;


Procedure SqMsgObj.ReadText(FPos: LongInt);
  Begin
  Seek(SqInfo^.SqdFile, FPos + SqFSize + SqMSize);
  SqInfo^.Error := IoResult;
  if SqInfo^.Error = 0 then begin
    If SqInfo^.Frame.MsgLength > SqTxtBufferSize Then
      BlockRead(SqInfo^.SqdFile, SqInfo^.MsgChars, SqTxtBufferSize)
    Else
      BlockRead(SqInfo^.SqdFile, SqInfo^.MsgChars,
       SqInfo^.Frame.MsgLength-SizeOf(SqMsgHdrType));
    SqInfo^.Error := IoResult;
    End;
  SqInfo^.TxtCtr := 1;{ + SqInfo^.Frame.ControlLength};
  EOM := False;
  Wrapped := False;
  End;



Procedure SqMsgObj.InitText;
  Begin
  SqInfo^.TxtCtr := 0;
  End;


Procedure SqMsgObj.DoString(Str: String); {Add string to message text}
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


Procedure SqMsgObj.DoChar(Ch: Char); {Add character to message text}
  Begin
  If SqInfo^.TxtCtr < SqTxtBufferSize Then
    Begin
    Inc(SqInfo^.TxtCtr);
    SqInfo^.MsgChars[SqInfo^.TxtCtr] := ch;
    End;
  End;


Procedure SqMsgObj.DoStringLn(Str: String); {Add string and newline to msg text}
  Begin
  DoString(Str);
  DoChar(#13);
  End;



Procedure SqMsgObj.KillExcess;
  Var
    AlreadyLocked: Boolean;

  Begin
  AlreadyLocked := SqInfo^.Locked;
  If Not AlreadyLocked Then
    If LockMsgBase Then;
  If SqIdx = Nil Then
    SqInfo^.error := 999
  Else
    Begin
    If ((SqInfo^.SqBase.MaxMsg > 0) and
    (SqInfo^.SqBase.MaxMsg > SqInfo^.SqBase.SkipMsg)) Then
      Begin
      While (SqInfo^.SqBase.NumMsg > SqInfo^.SqBase.MaxMsg) Do
        KillMsg(SqIdx^[SqInfo^.SqBase.SkipMsg + 1].UMsgId);
      End;
    End;
  If Not AlreadyLocked Then
    If UnlockMsgBase Then;
  End;


Function SqMsgObj.WriteMsg: Word; {Write msg to msg base}
  Var
    MsgSize: LongInt;
    FrameSize: LongInt;
    FramePos: LongInt;
    TmpFrame: SqFrameHdrType;
    TmpDate: LongInt;
    {$IFDEF WINDOWS}
    TmpDT: TDateTime;
    {$ELSE}
    TmpDT: DateTime;
    {$ENDIF}
    TmpStr: String;
    AlreadyLocked: Boolean;
    s : String;

  Begin
  DoChar(#0);
  TmpDT.Year := Str2Long(Copy(SqInfo^.StrDate,7,2));
  If TmpDT.Year > 79 Then
    Inc(TmpDT.Year, 1900)
  Else
    Inc(TmpDT.Year, 2000);
  TmpDT.Month := Str2Long(Copy(SqInfo^.StrDate,1,2));
  TmpDT.Day := Str2Long(Copy(SqInfo^.StrDate,4,2));
  TmpDt.Hour := Str2Long(Copy(SqInfo^.StrTime,1,2));
  TmpDt.Min := Str2Long(Copy(SqInfo^.StrTime, 4,2));
  TmpDt.Sec := 0;
  TmpStr := FormattedDate(TmpDT, 'DD NNN YY  ') + Copy(SqInfo^.StrTime,1,5) + ':00';
  PackTime(TmpDT, TmpDate);
  SqInfo^.MsgHdr.DateWritten :=  (TmpDate shr 16) + ((TmpDate and $ffff) shl 16);
  TmpDate := GetDosDate;
  SqInfo^.MsgHdr.DateArrived := (TmpDate shr 16) + ((TmpDate and $ffff) shl 16);
  Str2AZ(TmpStr, 20, SqInfo^.MsgHdr.AZDate);
  AlreadyLocked := SqInfo^.Locked;
  If Not AlreadyLocked Then
    If LockMsgBase Then;
  If SqInfo^.Locked Then
    Begin
    MsgSize := SqInfo^.TxtCtr + SqMSize;
    FrameSize := MsgSize;
    FindFrame(FrameSize, FramePos);
    If SqInfo^.SqBase.LastFrame <> 0 Then
      Begin
      ReadVarFrame(TmpFrame, SqInfo^.SqBase.LastFrame);
      TmpFrame.NextFrame := FramePos;
      WriteVarFrame(TmpFrame, SqInfo^.SqBase.LastFrame);
      TmpFrame.PrevFrame := SqInfo^.SqBase.LastFrame;
      End
    Else
      Begin
      SqInfo^.SqBase.BeginFrame := FramePos;
      TmpFrame.PrevFrame := 0;
      End;
    TmpFrame.Id := SqHdrId;
    TmpFrame.FrameType := SqFrameMsg;
    SqInfo^.SqBase.LastFrame := FramePos;
    TmpFrame.NextFrame := 0;
    TmpFrame.FrameLength := FrameSize;
    TmpFrame.MsgLength := MsgSize;
    TmpFrame.ControlLength := 0;
    If TmpFrame.FrameLength = 0 Then
      Begin
      TmpFrame.FrameLength := TmpFrame.MsgLength + 0; {slack to minimize free frames}
      SqInfo^.SqBase.EndFrame := FramePos + SqFSize + TmpFrame.FrameLength;
      End;
    If SqInfo^.SqBase.NumMsg >= SqInfo^.SqiAlloc Then
      Begin
      WriteIdx;
      ReadIdx;
      End;
    If SqIdx = Nil Then
      Begin
      SqInfo^.Error := 999;
      WriteMsg := 999;
      End
    Else
      Begin
      WriteVarFrame(TmpFrame, FramePos);
      WriteMsgHdr(FramePos);
      WriteText(FramePos);
      Inc(SqInfo^.SqBase.NumMsg);
      SqIdx^[SqInfo^.SqBase.NumMsg].Ofs := FramePos;
      SqIdx^[SqInfo^.SqBase.NumMsg].UMsgId := SqInfo^.SqBase.UID;
      Move(SqInfo^.MsgHdr.MsgTo, s, SqToSize);
{      s := SqInfo^.MsgHdr.MsgTo;}
      SqIdx^[SqInfo^.SqBase.NumMsg].Hash := SqHashName(Az2Str(s, 35));
      Inc(SqInfo^.SqBase.UId);
      SqInfo^.SqBase.HighMsg := SqInfo^.SqBase.NumMsg;
      KillExcess;
      SqInfo^.CurrIdx := SqInfo^.SqBase.NumMsg;
      WriteMsg := 0;
      End;
    If Not AlreadyLocked Then
      If UnLockMsgBase Then;
    End
  Else
    WriteMsg := 5;
  End;



Function SqMsgObj.GetString: String;
  Var
    WPos: Word;
    WLen: Byte;
    StrDone: Boolean;
    TxtOver: Boolean;
    StartSoft: Boolean;
    CurrLen: Word;
    PPos: Word;
    TmpCh: Char;
    Kludge: Boolean;

  Begin
  Kludge := false;
  StrDone := False;
  CurrLen := 0;
  PPos := SqInfo^.TxtCtr;
  WPos := 0;
  WLen := 0;
  StartSoft := Wrapped;
  Wrapped := True;
  TmpCh := GetChar;
  While ((Not StrDone) And (CurrLen < MaxLen) And (Not EOM)) Do
    Begin
    Case TmpCh of
      #$00: ;
      #$0d: Begin
            StrDone := True;
            Wrapped := False;
          End;
      #$8d:;
      #$0a:;
      #$01: begin
        if Kludge then begin
          dec(SqInfo^.TxtCtr);
          StrDone := True;
          Wrapped := False;
        end else begin
          kludge:=true;
          Inc(CurrLen);
          GetString[CurrLen] := #1;
        end;
      end;
      #$20: Begin
            If ((CurrLen <> 0) or (Not StartSoft)) Then
              Begin
              Inc(CurrLen);
              WLen := CurrLen;
              GetString[CurrLen] := TmpCh;
              WPos := SqInfo^.TxtCtr;
              End
            Else
              StartSoft := False;
            End;
      Else
        Begin
        Inc(CurrLen);
        GetString[CurrLen] := TmpCh;
        End;
      End;
    If Not StrDone Then
      TmpCh := GetChar;
    End;
  If StrDone Then
    Begin
    GetString[0] := Chr(CurrLen);
    End
  Else
    If EOM Then
      Begin
      GetString[0] := Chr(CurrLen);
      End
    Else
      Begin
      If WLen = 0 Then
        Begin
        GetString[0] := Chr(CurrLen);
        Dec(SqInfo^.TxtCtr);
        End
      Else
        Begin
        GetString[0] := Chr(WLen);
        SqInfo^.TxtCtr := WPos;
        End;
      End;
end;
{var
  LineEnd: Word;
  i: word;
  tmp: string;
  cr: word;
  Kludge: Boolean;
begin
  tmp:='';
  LineEnd:=SqInfo^.TxtCtr+MaxLen;
  if LineEnd>SqInfo^.Frame.MsgLength then begin
    LineEnd:=SqInfo^.TxtCtr;
    EOM:=true;
  end;
  cr:=0;
  kludge:=false;
  for i:=SqInfo^.TxtCtr to LineEnd do begin
    if (SqInfo^.MsgChars[i]=#0) and (Kludge=false) then begin
      EOM:=true;
      cr:=i;
      break;
    end;
    if (SqInfo^.MsgChars[i]=#1) or ((SqInfo^.MsgChars[i]=#0) and Kludge) then begin
      if Kludge then begin
        cr:=i;
        if (SqInfo^.MsgChars[i]=#0) then inc(cr);
        break;
      end;
      Kludge:=true;
    end;
    if SqInfo^.MsgChars[i]=#13 then begin
      Kludge:=false;
      cr:=i;
      break;
    end;
  end;

  if cr>0 then begin
    Tmp[0]:=char(Cr-SqInfo^.TxtCtr);
    Move(SqInfo^.MsgChars[SqInfo^.TxtCtr],Tmp[1],length(tmp));
    if not Kludge then inc(cr);
    SqInfo^.TxtCtr:=cr;
    Wrapped:=false;
  end else begin
    i:=LineEnd;
    while (i>SqInfo^.TxtCtr) do begin
      if SqInfo^.MsgChars[i]=#32 then break;
      dec(i);
    end;
    Tmp[0]:=char(i-SqInfo^.TxtCtr);
    Move(SqInfo^.MsgChars[SqInfo^.TxtCtr],Tmp[1],length(tmp));
    if i=SqInfo^.TxtCtr then i:=LineEnd;
    SqInfo^.TxtCtr:=LineEnd;
    Wrapped:=true;
  end;
  GetString:=tmp;
end;}


Function SqMsgObj.GetChar: Char;
  Begin
  If ((SqInfo^.TxtCtr >= SqInfo^.Frame.MsgLength) Or
  (SqInfo^.MsgChars[SqInfo^.TxtCtr] = #0) and (SqInfo^.TxtCtr >SqInfo^.Frame.ControlLength)) Then
    Begin
    GetChar := #0;
    EOM:=true;
    End
  Else
    Begin
    if SqInfo^.MsgChars[SqInfo^.TxtCtr]<>#0 then GetChar := SqInfo^.MsgChars[SqInfo^.TxtCtr] else GetChar:=#13;
    Inc(SqInfo^.TxtCtr);
    End;
  End;


Function SqMsgObj.GetHighWater: LongInt; {Get high water umsgid}
  Begin
  GetHighWater := LongInt(SqInfo^.SqBase.HighWater);
  End;


Function SqMsgObj.GetHighMsgNum: LongInt; {Get highest msg number}
  Begin
  GetHighMsgNum := LongInt(SqInfo^.SqBase.Uid) - 1;
  End;


procedure SqMsgObj.ReadIdx;
var
    {$IFDEF VirtualPascal}
    NumRead: LongInt;
    {$ELSE}
    NumRead: Word;
    {$ENDIF}

begin
  IndexRead:=true;
  If SqInfo^.SqiAlloc > 0 Then
    If SqIdx <> Nil Then
      FreeMem(SqIdx, SqInfo^.SqiAlloc * SizeOf(SqIdxType));
  SqInfo^.SqiAlloc := FileSize(SqInfo^.SqiFile) + 100;
  If SqInfo^.SqiAlloc > SqIdxArraySize Then
    SqInfo^.SqiAlloc := SqIdxArraySize ;
  GetMem(SqIdx, SqInfo^.SqiAlloc * SizeOf(SqIdxType));
  If SqIdx = nil Then
    SqInfo^.Error := 999
  Else
    Begin
    Seek(SqInfo^.SqiFile, 0);
    If IoResult = 0 Then Begin
      If Not shRead(SqInfo^.SqiFile, SqIdx^, SqInfo^.SqiAlloc, NumRead) Then
        SqInfo^.Error := MKFileError;
    end else
      SqInfo^.Error := 300;
    If IoResult = 0 Then;
{    if FilePos(SqInfo^.SqiFile)<FileSize(SqInfo^.SqiFile) then
      MessageBox('Eine Squisharea darf maximal nur '+Long2Str(SqIdxArraySize)+
                 ' Nachrichten enthalten. Wenn mehr enthalten sind, kann dies zu fehler fuehren.',nil,mfWarning+mfOkButton);}
    If IoResult = 0 Then;
  end;
end;


Procedure SqMsgObj.WriteIdx;
  Begin
  If SqIdx = nil Then
    SqInfo^.Error := 999
  Else
    Begin
    Seek(SqInfo^.SqiFile, 0);
    Truncate(SqInfo^.SqiFile);
    If IoResult = 0 Then
      Begin
      If Not shWrite(SqInfo^.SqiFile, SqIdx^, SqInfo^.SqBase.NumMsg) Then
        SqInfo^.Error := MKFileError;
      End
    Else
      SqInfo^.Error := 300;
    End;
  End;


procedure SqMsgObj.SeekFirst(MsgNum: LongInt);
begin
  SqInfo^.CurrIdx := 1;
  if IndexRead=false then ReadIdx;
  while ((SqInfo^.CurrIdx <= SqInfo^.SqBase.NumMsg) and
         (MsgNum > LongInt(SqIdx^[SqInfo^.CurrIdx].UMsgId))) Do begin
    SeekNext;
    if (SqInfo^.CurrIdx<=0) or (SqInfo^.CurrIdx>SqIdxArraySize) then break;
  end;
end;


Function SqMsgObj.IdxHighest: LongInt;
  Var
    i: Word;
    Tmp: LongInt;

  Begin
  Tmp := 0;
  i := 1;
  While i <= SqInfo^.SqBase.NumMsg Do
    Begin
    If  SqIdx^[i].UMsgId > Tmp Then
      Tmp := SqIdx^[i].UMsgId;
    Inc(i);
    End;
  IdxHighest := Tmp;
  End;


Function SqMsgObj.GetMsgNum: LongInt;
  Begin
  If ((SqInfo^.CurrIdx <= SqInfo^.SqBase.NumMsg) and
      (SqInfo^.CurrIdx > 0) and (SqInfo^.CurrIdx <= SqIdxArraySize)) Then
    GetMsgNum := LongInt(SqIdx^[SqInfo^.CurrIdx].UMsgId)
  Else
    GetMsgNum := -1;
  End;


Procedure SqMsgObj.SeekNext;
  Begin
  Inc(SqInfo^.CurrIdx);
  End;


Procedure SqMsgObj.SeekPrior;
  Begin
  If SqInfo^.CurrIdx > 1 Then
    Dec(SqInfo^.CurrIdx)
  Else
    SqInfo^.CurrIdx := 0;
  End;


Function SqMsgObj.SeekFound: Boolean;
  Begin
  SeekFound := GetMsgNum >= 0;
  End;


Function SqMsgObj.GetIdxFramePos: LongInt;
  Begin
  If (SqInfo^.CurrIdx>0) and (SqInfo^.CurrIdx <= SqInfo^.SqBase.NumMsg) Then
    GetIdxFramePos := SqIdx^[SqInfo^.CurrIdx].Ofs
  Else
    GetIdxFramePos := -1;
  End;


Function SqMsgObj.GetIdxHash: LongInt;
  Begin
  If (SqInfo^.CurrIdx>0) and (SqInfo^.CurrIdx <= SqInfo^.SqBase.NumMsg) Then
    GetIdxHash := SqIdx^[SqInfo^.CurrIdx].Hash
  Else
    GetIdxHash := 0;
  End;


Function SqMsgObj.IsLocal: Boolean; {Is current msg local}
  Begin
  IsLocal := ((SqInfo^.MsgHdr.Attr and SqMsgLocal) <> 0);
  End;


Function SqMsgObj.IsCrash: Boolean; {Is current msg crash}
  Begin
  IsCrash := ((SqInfo^.MsgHdr.Attr and SqMsgCrash) <> 0);
  End;


Function SqMsgObj.IsKillSent: Boolean; {Is current msg kill sent}
  Begin
  IsKillSent := ((SqInfo^.MsgHdr.Attr and SqMsgKill) <> 0);
  End;


Function SqMsgObj.IsSent: Boolean; {Is current msg sent}
  Begin
  IsSent := ((SqInfo^.MsgHdr.Attr and SqMsgSent) <> 0);
  End;


Function SqMsgObj.IsFAttach: Boolean; {Is current msg file attach}
  Begin
  IsFAttach := ((SqInfo^.MsgHdr.Attr and SqMsgFile) <> 0);
  End;


Function SqMsgObj.IsReqRct: Boolean; {Is current msg request receipt}
  Begin
  IsReqRct := ((SqInfo^.MsgHdr.Attr and SqMsgRRQ) <> 0);
  End;


Function SqMsgObj.IsReqAud: Boolean; {Is current msg request audit}
  Begin
  IsReqAud := ((SqInfo^.MsgHdr.Attr and SqMsgArq) <> 0);
  End;


Function SqMsgObj.IsRetRct: Boolean; {Is current msg a return receipt}
  Begin
  IsRetRct := ((SqInfo^.MsgHdr.Attr and SqMsgCpt) <> 0);
  End;


Function SqMsgObj.IsFileReq: Boolean; {Is current msg a file request}
  Begin
  IsFileReq := ((SqInfo^.MsgHdr.Attr and SqMsgFreq) <> 0);
  End;


Function SqMsgObj.IsRcvd: Boolean; {Is current msg received}
  Begin
  IsRcvd := ((SqInfo^.MsgHdr.Attr and SqMsgRcvd) <> 0);
  End;


Function SqMsgObj.IsPriv: Boolean; {Is current msg priviledged/private}
  Begin
  IsPriv := ((SqInfo^.MsgHdr.Attr and SqMsgPriv) <> 0);
  End;


Function SqMsgObj.IsHold: Boolean; {Is current msg hold}
  Begin
  IsHold := ((SqInfo^.MsgHdr.Attr and SqMsgHold) <> 0);
  End;


Function SqMsgObj.IsEchoed: Boolean;
  Begin
  IsEchoed := ((SqInfo^.MsgHdr.Attr and SqMsgScanned) = 0);
  End;


Function SqMsgObj.IsDeleted: Boolean; {Is current msg deleted}
  Begin
  IsDeleted := False;
  End;


Function SqMsgObj.GetRefer: LongInt; {Get reply to of current msg}
  Begin
  GetRefer := LongInt(SqInfo^.MsgHdr.ReplyTo);
  End;


Procedure SqMsgObj.SetRefer(Num: LongInt); {Set reply to of current msg}
  Begin
  SqInfo^.MsgHdr.ReplyTo := LongInt(Num);
  End;


Function SqMsgObj.GetSeeAlso: LongInt; {Get see also msg}
  Begin
  GetSeeAlso := LongInt(SqInfo^.MsgHdr.Replies[1]);
  End;


Procedure SqMsgObj.SetSeeAlso(Num: LongInt); {Set see also msg}
  Begin
  SqInfo^.MsgHdr.Replies[1] := LongInt(Num);
  End;


Procedure SqMsgObj.SetAttr(St: Boolean; Mask: LongInt); {Set attribute}
  Begin
  If St Then
    SqInfo^.MsgHdr.Attr := SqInfo^.MsgHdr.Attr or Mask
  Else
    SqInfo^.MsgHdr.Attr := SqInfo^.MsgHdr.Attr and (Not Mask);
  End;


Procedure SqMsgObj.SetLocal(St: Boolean); {Set local status}
  Begin
  SetAttr(St, SqMsgLocal);
  End;


Procedure SqMsgObj.SetRcvd(St: Boolean); {Set received status}
  Begin
  SetAttr(St, SqMsgRcvd);
  End;


Procedure SqMsgObj.SetPriv(St: Boolean); {Set priveledge vs public status}
  Begin
  SetAttr(St, SqMsgPriv);
  End;


Procedure SqMsgObj.SetEcho(ES: Boolean);
  Begin
  SetAttr(Not ES, SqMsgScanned);
  End;


Procedure SqMsgObj.SetCrash(St: Boolean); {Set crash netmail status}
  Begin
  SetAttr(St, SqMsgCrash);
  End;


Procedure SqMsgObj.SetKillSent(St: Boolean); {Set kill/sent netmail status}
  Begin
  SetAttr(St, SqMsgKill);
  End;


Procedure SqMsgObj.SetSent(St: Boolean); {Set sent netmail status}
  Begin
  SetAttr(St, SqMsgSent);
  End;


Procedure SqMsgObj.SetFAttach(St: Boolean); {Set file attach status}
  Begin
  SetAttr(St, SqMsgFile);
  End;


Procedure SqMsgObj.SetReqRct(St: Boolean); {Set request receipt status}
  Begin
  SetAttr(St, SqMsgRrq);
  End;


Procedure SqMsgObj.SetReqAud(St: Boolean); {Set request audit status}
  Begin
  SetAttr(St, SqMsgarq);
  End;


Procedure SqMsgObj.SetRetRct(St: Boolean); {Set return receipt status}
  Begin
  SetAttr(St, SqMsgCpt);
  End;


Procedure SqMsgObj.SetFileReq(St: Boolean); {Set file request status}
  Begin
  SetAttr(St, SqMsgFreq);
  End;

procedure SqMsgObj.SetHold(sh : Boolean);
begin
  setAttr(sh, SqMsgHold);
end;

procedure SqMsgObj.InitMsgHdr;
begin
  SqInfo^.CurrentFramePos := GetIdxFramePos;
  SqInfo^.CurrentUID := SqIdx^[SqInfo^.CurrIdx].UMsgId;
  ReadMsgHdr(SqInfo^.CurrentFramePos);
end;


Procedure SqMsgObj.MsgTxtStartUp;
  Var
    CFrame: LongInt;

  Begin
  ReadFrame(SqInfo^.CurrentFramePos);
  ReadText(SqInfo^.CurrentFramePos);
  End;


Procedure SqMsgObj.SetMailType(MT: MsgMailType);
  Begin
  End;


Function SqMsgObj.GetSubArea: Word;
  Begin
  GetSubArea := 0;
  End;


Procedure SqMsgObj.ReWriteHdr;
  Var
    AlreadyLocked: Boolean;
    i: LongInt;


  Begin
  AlreadyLocked := SqInfo^.Locked;
  If Not AlreadyLocked Then
    If LockMsgBase Then;
  WriteFrame(SqInfo^.CurrentFramePos);
  WriteMsgHdr(SqInfo^.CurrentFramePos);
  i := 1;
  While ((i <= SqInfo^.SqBase.NumMsg) and (SqInfo^.CurrentFramePos <> SqIdx^[i].Ofs)) Do
    Inc(i);
  If SqIdx^[i].Ofs = SqInfo^.CurrentFramePos Then
    Begin
    If IsRcvd Then
      SqIdx^[i].Hash := 0
    Else
      SqIdx^[i].Hash := SqHashName(SqInfo^.MsgHdr.MsgTo);
    End;
  If Not AlreadyLocked Then
    If UnLockMsgBase Then;
  End;


Procedure SqMsgObj.DeleteMsg;
  Begin
  KillMsg(SqInfo^.CurrentUID);
  End;


Function SqMsgObj.NumberOfMsgs: LongInt;
Var
  TmpBase: Record
    Len    : Word;
    Rsvd1  : Word;
    NumMsg : LongInt;
  end;
  f: file;
begin
  if ioresult<>0 then;
  FileMode := fmReadOnly + fmDenyNone;
  assign(f,SqInfo^.FN+'.sqd');
  {$I-} reset(f,1);
  filemode:=fmReadWrite;
  blockread(f,TmpBase,Sizeof(TmpBase));
  close(f);
  if ioresult<>0 then NumberOfMsgs:=0 else NumberOfMsgs:=TmpBase.NumMsg;
end;


function SqMsgObj.GetLastRead: LongInt;
var
  LRec : LongInt;
  f    : file;
begin
  if ioresult <> 0 then;
  FileMode := fmReadOnly or fmDenyNone;
  Assign(f, SqInfo^.FN + '.sql');
  {$I-} Reset(f, 1);
{  Seek(f, Cfg.SquishUNum * SizeOf(LRec));}
  Blockread(f, LRec, Sizeof(LRec));
  Close(f);
  if ioresult <> 0 then
    GetLastRead := 0
  else
    GetLastRead := LRec;
end;

procedure SqMsgObj.SetLastRead(LR: LongInt);
type
  TBuf = array[1..4000] of byte;
var
  Num    : Word;
  Buf    : ^TBuf;
  f    : file;
begin
  New(Buf);
  fillchar(Buf^, sizeof(Buf^), 0);
  if ioresult <> 0 then;
  FileMode := fmReadWrite or fmDenyNone;
  Assign(f, SqInfo^.FN + '.sql');
  {$I-} Reset(f, 1);
  if ioresult <> 0 then {$I-} Rewrite(f, 1);
  if Sizeof(LR) > FileSize(f) then
  begin
    Seek(f, Filesize(f));
    while (Sizeof(LR) > FileSize(f)) and (ioresult = 0) do
    begin
      Num := (Sizeof(LR)) - FileSize(f);
      if Num > 4000 then Num := 4000;
      Blockwrite(f, Buf^, Num);
    end;
  end;
{  Seek(f, Cfg.SquishUNum * SizeOf(LR));}
  Blockwrite(f, LR, Sizeof(LR));
  Close(f);
  if ioresult <> 0 then;
  Dispose(Buf);
end;

Function SqMsgObj.GetMsgLoc: LongInt;
  Begin
  GetMsgLoc := GetMsgNum;
  End;


Procedure SqMsgObj.SetMsgLoc(ML: LongInt);
  Begin
  SeekFirst(ML);
  End;


Function SqMsgObj.GetMsgDisplayNum: LongInt;
  Begin
  GetMsgDisplayNum := SqInfo^.CurrIdx;
  End;


Function SqMsgObj.GetTxtPos: LongInt;
  Begin
  GetTxtPos := SqInfo^.TxtCtr;
  End;


Procedure SqMsgObj.SetTxtPos(TP: LongInt);
  Begin
  SqInfo^.TxtCtr := TP;
  End;


Function SqMsgObj.GetRealMsgNum: LongInt;
begin
  GetRealMsgNum:=SqInfo^.CurrIdx;
end;

function SqMsgObj.SetRead(RS: Boolean): boolean;
begin
  if IsRead=false then begin
    SetAttr(RS, SqMsgRead);
    SetRead:=true;
  end else
    SetRead:=false;
end;

function SqMsgObj.IsRead: Boolean;
begin
  IsRead:=((SqInfo^.MsgHdr.Attr and SqMsgRead)<>0);
end;

{ Copyright 1997 by Sascha Lammers }
procedure GetSquishInfo(fn: string; var cur, msgs: longint);
var
  num: longint;
  sr: searchrec;
  f: file;
begin
  FileMode := fmReadOnly or fmDenyNone;
  FindFirst(fn + '.sqi', AnyFile, sr);
  if doserror <> 0 then
    Msgs := 0
  else
    Msgs := sr.size div Sizeof(SqIdxType);
{$IFDEF OS2}
  FindClose(sr);
{$ENDIF}
  Assign(f, fn + '.sql');
  {$I-} reset(f, 1);
  blockread(f, num, Sizeof(Num));
  close(f);
  if ioresult <> 0 then
    Cur := 0
  else
    Cur := Num;
end;

End.

