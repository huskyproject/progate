{ $O+,F+,I-,S-,R-,V-}
Unit MKMsgAbs;       {Abstract Msg Object}

{$IfDef FPC}
 {$PackRecords 1}
{$EndIf}

Interface

Uses MKGlobT, Dos;

const
  msgUnkown  = 0;
  msgSquish  = 1;
  msgJAM     = 2;
  msgFido    = 3;
  msgHudson  = 4;
  msgEzy     = 5;

  MaxLen : Byte = 80;

Type MsgMailType = (mmtNormal, mmtEchoMail, mmtNetMail);

Type AbsMsgObj = Object
  Wrapped : Boolean;
  EOM     : Boolean;
  Constructor Init; {Initialize}
  Destructor Done; Virtual; {Done}
  function  GetID: Byte; Virtual;
  Procedure SetMsgPath(MP: String); Virtual; {Set msg path/other info}
  Function  OpenMsgBase: Word; Virtual; {Open the message base}
  Function  CloseMsgBase: Word; Virtual; {Close the message base}
  Function  CreateMsgBase(MaxMsg: Word; MaxDays: Word): Word; Virtual; {Create new message base}
  Function  MsgBaseExists: Boolean; Virtual; {Does msg base exist}
  Function  LockMsgBase: Boolean; Virtual; {Lock the message base}
  Function  UnLockMsgBase: Boolean; Virtual; {Unlock the message base}
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
  Procedure SetLocal(LS: Boolean); Virtual; {Set local status}
  Procedure SetRcvd(RS: Boolean); Virtual; {Set received status}
  function  SetRead(RS: Boolean): boolean; virtual;
  Procedure SetPriv(PS: Boolean); Virtual; {Set priveledge vs public status}
  Procedure SetCrash(SS: Boolean); Virtual; {Set crash netmail status}
  Procedure SetKillSent(SS: Boolean); Virtual; {Set kill/sent netmail status}
  Procedure SetSent(SS: Boolean); Virtual; {Set sent netmail status}
  Procedure SetFAttach(SS: Boolean); Virtual; {Set file attach status}
  Procedure SetReqRct(SS: Boolean); Virtual; {Set request receipt status}
  Procedure SetReqAud(SS: Boolean); Virtual; {Set request audit status}
  Procedure SetRetRct(SS: Boolean); Virtual; {Set return receipt status}
  Procedure SetFileReq(SS: Boolean); Virtual; {Set file request status}
  procedure SetHold(sh : Boolean); virtual; {Set hold status}
  Procedure DoString(Str: String); Virtual; {Add string to message text}
  Procedure DoChar(Ch: Char); Virtual; {Add character to message text}
  Procedure DoStringLn(Str: String); Virtual; {Add string and newline to msg text}
  Procedure DoKludgeLn(Str: String); Virtual; {Add ^A kludge line to msg}
  Function  WriteMsg: Word; Virtual; {Write msg to msg base}
  Function  GetChar: Char; Virtual; {Get msg text character}
  Function  GetString: String; Virtual;
  Function  GetFrom: String; Virtual; {Get from name on current msg}
  Function  GetTo: String; Virtual; {Get to name on current msg}
  Function  GetSubj: String; Virtual; {Get subject on current msg}
  Function  GetCost: Word; Virtual; {Get cost of current msg}
  Function  GetDate: String; Virtual; {Get date of current msg}
  Function  GetTime: String; Virtual; {Get time of current msg}
  Function  GetRefer: LongInt; Virtual; {Get reply to of current msg}
  Function  GetSeeAlso: LongInt; Virtual; {Get see also of current msg}
  Function  GetNextSeeAlso: LongInt; Virtual;
  Procedure SetNextSeeAlso(SAlso: LongInt); Virtual;
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
  Function  IsRead: Boolean; Virtual; {Is current msg received}
  Function  IsPriv: Boolean; Virtual; {Is current msg priviledged/private}
  Function  IsHold: Boolean; Virtual; {Is current msg hold}
  Function  IsDeleted: Boolean; Virtual; {Is current msg deleted}
  Procedure SetDeleted(tr: boolean); virtual;
  Function  IsEchoed: Boolean; Virtual; {Is current msg unmoved echomail msg}
  Function  GetMsgLoc: LongInt; Virtual; {To allow reseeking to message}
  Procedure SetMsgLoc(ML: LongInt); Virtual; {Reseek to message}
  Procedure InitMsgHdr; Virtual; {Do message set-up tasks}
  Procedure MsgTxtStartUp; Virtual; {Do message text start up tasks}
  Procedure StartNewMsg; Virtual; {Initialize for adding message}
  Procedure SeekFirst(MsgNum: LongInt); Virtual; {Start msg seek}
  Procedure SeekNext; Virtual; {Find next matching msg}
  Procedure SeekPrior; Virtual; {Prior msg}
  Function  SeekFound: Boolean; Virtual; {Msg was found}
  Function  GetHighMsgNum: LongInt; Virtual; {Get highest msg number}
  Procedure SetMailType(MT: MsgMailType); Virtual; {Set message base type}
  Function  GetSubArea: Word; Virtual; {Get sub area number}
  Procedure ReWriteHdr; Virtual; {Rewrite msg header after changes}
  Procedure DeleteMsg; Virtual; {Delete current message}
  Procedure SetEcho(ES: Boolean); Virtual; {Set echo status}
  Function  NumberOfMsgs: LongInt; Virtual; {Number of messages}
  Function  GetLastRead: LongInt; Virtual; {Get last read for user num}
  Procedure SetLastRead(LR: LongInt); Virtual; {Set last read}
  Function  GetMsgDisplayNum: LongInt; Virtual; {Get msg number to display}
  Function  GetTxtPos: LongInt; Virtual; {Get indicator of msg text position}
  Procedure SetTxtPos(TP: LongInt); Virtual; {Set text position}
  Function  GetHighActiveMsgNum: LongInt; Virtual; {Get highest active msg num}
  Function  GetLowActiveMsgNum: LongInt; Virtual; {Get lowest active msg num}
  Function  GetRealMsgNum: LongInt; Virtual;
  End;


Type AbsMsgPtr = ^AbsMsgObj;


Implementation


Constructor AbsMsgObj.Init;
  Begin
  End;


Destructor AbsMsgObj.Done;
  Begin
  End;


function  AbsMsgObj.GetID: Byte;
begin
  GetID:=msgUnkown;
end;

Procedure AbsMsgObj.SetMsgPath(MP: String);
  Begin
  End;


Function AbsMsgObj.OpenMsgBase: Word;
  Begin
  End;


Function AbsMsgObj.CloseMsgBase: Word;
  Begin
  End;


Function AbsMsgObj.LockMsgBase: Boolean;
  Begin
  End;


Function AbsMsgObj.UnLockMsgBase: Boolean;
  Begin
  End;


Procedure AbsMsgObj.SetDest(Var Addr: AddrType);
  Begin
  End;


Procedure AbsMsgObj.SetOrig(Var Addr: AddrType);
  Begin
  End;


Procedure AbsMsgObj.SetFrom(Name: String);
  Begin
  End;


Procedure AbsMsgObj.SetTo(Name: String);
  Begin
  End;


Procedure AbsMsgObj.SetSubj(Str: String);
  Begin
  End;


Procedure AbsMsgObj.SetCost(SCost: Word);
  Begin
  End;


Procedure AbsMsgObj.SetRefer(SRefer: LongInt);
  Begin
  End;


Procedure AbsMsgObj.SetSeeAlso(SAlso: LongInt);
  Begin
  End;


Procedure AbsMsgObj.SetDate(SDate: String);
  Begin
  End;


Procedure AbsMsgObj.SetTime(STime: String);
  Begin
  End;


Procedure AbsMsgObj.SetLocal(LS: Boolean);
  Begin
  End;


Procedure AbsMsgObj.SetRcvd(RS: Boolean);
  Begin
  End;


Procedure AbsMsgObj.SetPriv(PS: Boolean);
  Begin
  End;


Procedure AbsMsgObj.SetCrash(SS: Boolean);
  Begin
  End;


Procedure AbsMsgObj.SetKillSent(SS: Boolean);
  Begin
  End;


Procedure AbsMsgObj.SetSent(SS: Boolean);
  Begin
  End;


Procedure AbsMsgObj.SetFAttach(SS: Boolean);
  Begin
  End;


Procedure AbsMsgObj.SetReqRct(SS: Boolean);
  Begin
  End;


Procedure AbsMsgObj.SetReqAud(SS: Boolean);
  Begin
  End;


Procedure AbsMsgObj.SetRetRct(SS: Boolean);
  Begin
  End;


Procedure AbsMsgObj.SetFileReq(SS: Boolean);
  Begin
  End;

procedure AbsMsgObj.SetHold(SH : Boolean);

begin
end;

Procedure AbsMsgObj.DoString(Str: String);
  Var
    i: Word;

  Begin
  For i := 1 to Length(Str) Do
    DoChar(Str[i]);
  End;


Procedure AbsMsgObj.DoChar(Ch: Char);
  Begin
  End;


Procedure AbsMsgObj.DoStringLn(Str: String);
  Begin
  DoString(Str);
  DoChar(#13);
  End;

Procedure AbsMsgObj.DoKludgeLn(Str: String);
  Begin
  DoStringLn(Str);
  End;


Function AbsMsgObj.WriteMsg: Word;
  Begin
  End;


Function AbsMsgObj.GetChar: Char;
  Begin
  End;


Function AbsMsgObj.GetString: String;
  Var
    WPos: LongInt;
    WLen: Byte;
    StrDone: Boolean;
    TxtOver: Boolean;
    StartSoft: Boolean;
    CurrLen: Word;
    PPos: LongInt;
    TmpCh: Char;
    OldPos: LongInt;

  Begin
  If EOM Then
    GetString := ''
  Else
    Begin
    StrDone := False;
    CurrLen := 0;
    PPos := GetTxtPos;
    WPos := GetTxtPos;
    WLen := 0;
    StartSoft := Wrapped;
    Wrapped := True;
    OldPos := GetTxtPos;
    TmpCh := GetChar;
    While ((Not StrDone) And (CurrLen < MaxLen) And (Not EOM)) Do
      Begin
      Case TmpCh of
        #$00:;
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
                WLen := CurrLen;
                GetString[CurrLen] := TmpCh;
                WPos := GetTxtPos;
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
        Begin
        OldPos := GetTxtPos;
        TmpCh := GetChar;
        End;
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
          SetTxtPos(OldPos);
          End
        Else
          Begin
          GetString[0] := Chr(WLen);
          SetTxtPos(WPos);
          End;
        End;
    End;
  End;



Procedure AbsMsgObj.SeekFirst(MsgNum: LongInt);
  Begin
  End;


Procedure AbsMsgObj.SeekNext;
  Begin
  End;


Function AbsMsgObj.GetFrom: String;
  Begin
  End;


Function AbsMsgObj.GetTo: String;
  Begin
  End;


Function AbsMsgObj.GetSubj: String;
  Begin
  End;


Function AbsMsgObj.GetCost: Word;
  Begin
  End;


Function AbsMsgObj.GetDate: String;
  Begin
  End;


Function AbsMsgObj.GetTime: String;
  Begin
  End;


Function AbsMsgObj.GetRefer: LongInt;
  Begin
  End;


Function AbsMsgObj.GetSeeAlso: LongInt;
  Begin
  End;


Function AbsMsgObj.GetMsgNum: LongInt;
  Begin
  End;


Procedure AbsMsgObj.GetOrig(Var Addr: AddrType);
  Begin
  End;


Procedure AbsMsgObj.GetDest(Var Addr: AddrType);
  Begin
  End;


Function AbsMsgObj.IsLocal: Boolean;
  Begin
  End;


Function AbsMsgObj.IsCrash: Boolean;
  Begin
  End;


Function AbsMsgObj.IsKillSent: Boolean;
  Begin
  End;


Function AbsMsgObj.IsSent: Boolean;
  Begin
  End;


Function AbsMsgObj.IsFAttach: Boolean;
  Begin
  End;


Function AbsMsgObj.IsReqRct: Boolean;
  Begin
  End;


Function AbsMsgObj.IsReqAud: Boolean;
  Begin
  End;


Function AbsMsgObj.IsRetRct: Boolean;
  Begin
  End;


Function AbsMsgObj.IsFileReq: Boolean;
  Begin
  End;


Function AbsMsgObj.IsRcvd: Boolean;
  Begin
  End;


Function AbsMsgObj.IsPriv: Boolean;
  Begin
  End;

Function AbsMsgObj.IsHold: Boolean;
  Begin
  IsHold:=false;
  End;

Function AbsMsgObj.IsDeleted: Boolean;
begin
  IsDeleted:=false;
end;

Procedure AbsMsgObj.SetDeleted(tr: boolean);
begin
end;

Function AbsMsgObj.IsEchoed: Boolean;
  Begin
  End;


Function AbsMsgObj.GetMsgLoc: LongInt;
  Begin
  End;


Procedure AbsMsgObj.SetMsgLoc(ML: LongInt);
  Begin
  End;


Procedure AbsMsgObj.InitMsgHdr;
  Begin
  End;


Procedure AbsMsgObj.MsgTxtStartUp;
  Begin
  End;


Function AbsMsgObj.CreateMsgBase(MaxMsg: Word; MaxDays: Word): Word;
  Begin
  End;


Function AbsMsgObj.MsgBaseExists: Boolean;
  Begin
  End;


Procedure AbsMsgObj.StartNewMsg;
  Begin
  End;


Function AbsMsgObj.GetHighMsgNum: LongInt;
  Begin
  End;


Function AbsMsgObj.SeekFound: Boolean;
  Begin
  End;


Procedure AbsMsgObj.SetMailType(MT: MsgMailType);
  Begin
  End;


Function AbsMsgObj.GetSubArea: Word;
  Begin
  GetSubArea := 0;
  End;


Procedure AbsMsgObj.ReWriteHdr;
  Begin
  End;


Procedure AbsMsgObj.DeleteMsg;
  Begin
  End;


Procedure AbsMsgObj.SetEcho(ES: Boolean);
  Begin
  End;


Procedure AbsMsgObj.SeekPrior;
  Begin
  End;


Function AbsMsgObj.NumberOfMsgs: LongInt;
  Begin
  End;


Function AbsMsgObj.GetLastRead: LongInt;
  Begin
  End;

Procedure AbsMsgObj.SetLastRead(LR: LongInt);
  Begin
  End;

Function AbsMsgObj.GetMsgDisplayNum: LongInt;
  Begin
  GetMsgDisplayNum := GetMsgNum;
  End;

Function AbsMsgObj.GetTxtPos: LongInt;
  Begin
  GetTxtPos := 0;
  End;

Procedure AbsMsgObj.SetTxtPos(TP: LongInt);
  Begin
  End;


 {SetNextSeeAlso provided by 2:201/623@FidoNet Jonas@iis.bbs.bad.se}


Procedure AbsMsgObj.SetNextSeeAlso(SAlso: LongInt);
  Begin
  End;

Function AbsMsgObj.GetNextSeeAlso: LongInt;
  Begin
  GetNextSeeAlso:=0;
  End;


function AbsMsgObj.GetHighActiveMsgNum: LongInt;
begin
  SeekFirst(GetHighMsgNum);
  if not SeekFound then SeekPrior;
  if SeekFound then begin
    GetHighActiveMsgNum := GetMsgNum
  end else
    GetHighActiveMsgNum := 0;
end;


function AbsMsgObj.GetLowActiveMsgNum: LongInt;
begin
  SeekFirst(1);
  if not SeekFound then SeekNext;
  if SeekFound then begin
    GetLowActiveMsgNum := GetMsgNum
  end else
    GetLowActiveMsgNum := 1;
end;

Function AbsMsgObj.GetRealMsgNum: LongInt;
begin
  GetRealMsgNum:=GetMsgNum;
end;

function AbsMsgObj.SetRead(RS: Boolean): boolean;
begin
  if (IsRead=false) and (IsLocal=false) then begin
    SetRcvd(true);
    SetRead:=true;
  end else
    SetRead:=false;
end;


function AbsMsgObj.IsRead: Boolean;
begin
  IsRead:=IsRcvd;
end;


End.
