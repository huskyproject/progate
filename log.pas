Unit Log; {In LogDateien schreiben}
Interface

Uses
{$IfDef Linux}
 Linux,
{$EndIf}
 Types, GeneralP;

Const
 Binkley              = 1;
 FD                   = 2;
 DBridge              = 3;
 Opus                 = 4;


Procedure LogDone;
Function OpenLog(LogType : Byte; LogName : String80; ProgID : String8; Banner : String80) : Byte;
Procedure CloseLog(Handle : Byte);
Procedure LogWriteLn(Handle : Byte; ToWrite : String);
Procedure LogSetCurLevel(Handle : Byte; NewLevel : Byte);
Procedure LogSetLogLevel(Handle : Byte; NewLevel : Byte);
Procedure LogSetScrLevel(Handle : Byte; NewLevel : Byte);

Implementation
Uses DOS;

Type

{PTextBuf = ^TTextBuf;
TTextBuf = array[0..127] of Char;
TTextRec = record
  Handle:    Word;
  Mode:      Word;
  BufSize:   Word;
  Private:   Word;
  BufPos:    Word;
  BufEnd:    Word;
  BufPtr:    PTextBuf;
  OpenFunc:  Pointer;
  InOutFunc: Pointer;
  FlushFunc: Pointer;
  CloseFunc: Pointer;
  UserData:  array[1..16] of Byte;
  Name:      array[0..79] of Char;
  Buffer:    TTextBuf;
end;}

             PLogFile      =    ^TLogFile;
             TLogFile      =    Record
                                Datei : Text;
                                Name: String80;
                                LogType : Byte;
                                ProgID : String8;
                                Banner : String80;
                                CurLevel : Byte;
                                LogLevel : Byte;
                                ScrLevel : Byte;
                                end;

             PLogFileArray =    ^TLogFileArray;
             TLogFileArray =    Array[1..255] of PLogFile;

Const BinkChars            :    Array[1..5] of char = '!+:# ';
      FDChars              :    Array[1..5] of char = '     ';
      DBridgeChars         :    Array[1..5] of char = '     ';
      MonthNames           :    Array[1..12] of String[3] =
                                ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                                 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec');
      DayNames             :    Array[0..6] of String[3] =
                                ('Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat');

Var
    LogFiles : TLogFileArray;
    xyz      : Byte;
    Date     : TimeTyp;

Function Date2BinkStr(Date:TimeTyp) : String10;
var s:String[10];
begin
Str(Date.Day,s);
If (Byte(s[0]) = 1) then s := '0' + s;
Date2BinkStr:=s + ' ' + MonthNames[Date.Month];
end;

Function Date2FDStr(Date:TimeTyp) : String20;
var s,s2:String[10];
begin
s := DayNames[Date.DayOfWeek] + ' ';
Str(Date.Day,s2);
If (Byte(s2[0]) = 1) then s2 := '0' + s2;
s := s + s2 + ' ' + MonthNames[Date.Month] + ' ';
Str(Date.Year,s2);
If (Byte(s2[0]) = 1) then s2 := '0' + s2;
Date2FDStr:=s + ' ' + s2;
end;

Function Date2DBridgeStr(Date : TimeTyp) : String20;
  Function Word2Str(n: word): string8;
  var s: string8;
  begin
  str(n,s);
  if n < 10 then s := '0'+s;
  Word2Str := s;
  end;

begin
With Date do Date2DBridgeStr := Word2Str(Month)+'/'+Word2Str(Day)+'/'+copy(Word2Str(Year),3,2);
end;

Function Time2Str(Time:TimeTyp) : String10;
var s,s2:String[10];
begin
Str(Time.Hour,s2);
If (Byte(s2[0]) = 1) then s2 := '0' + s2;
s:=s2+':';
Str(Time.Min,s2);
If (Byte(s2[0]) = 1) then s2 := '0' + s2;
s:=s+s2+':';
Str(Time.Sec,s2);
If (Byte(s2[0]) = 1) then s2 := '0' + s2;
Time2Str:=s+s2;
end;

Procedure Init;
Var
 i: Byte;

 Begin
 For i := 1 to 255 do LogFiles[i] := NIL;
 End;

Procedure LogDone;
var i : Byte;
begin
For i := 1 to 255 do If LogFiles[i] <> nil then CloseLog(i);
end;


Function OpenLog(LogType : Byte; LogName : String80; ProgID : String8; Banner : String80) : Byte;
var i : Byte;
begin
For i := 1 to 255 do If LogFiles[i] = nil then begin
    New(LogFiles[i]);
    LogFiles[i]^.Name := LogName;
    Assign(LogFiles[i]^.Datei, LogName);
    {$I-} Append(LogFiles[i]^.Datei); {$I+}
    If IOResult <> 0 then
     Begin
     Assign(LogFiles[i]^.Datei, LogName);
     {$I-} ReWrite(LogFiles[i]^.Datei); {$I+}
     End;
    If (IOResult = 0) then begin
       LogFiles[i]^.LogType := LogType;
       LogFiles[i]^.ProgID := ProgID;
       LogFiles[i]^.Banner := Banner;
       LogFiles[i]^.LogLevel := 5;
       LogFiles[i]^.CurLevel := 2;
       LogFiles[i]^.ScrLevel := 0;
       Case LogType of
            Binkley : LogWriteLn(i, 'begin, ' + Banner);
            Opus    : LogWriteLn(i, 'begin, ' + Banner);
            FD      : begin
                      Today(Date);
                      Write(LogFiles[i]^.Datei, '----------  ', Date2FDStr(Date), ', ');
                      WriteLn(LogFiles[i]^.Datei, Banner);
                      end;
            end;
       OpenLog := i;
       Exit;
       end
    Else begin
         OpenLog := 0;
         Exit;
         end;
    end;
end;

Procedure CloseLog(Handle : Byte);
begin
If LogFiles[Handle] = nil then exit;
LogFiles[Handle]^.CurLevel := 2;
Case LogFiles[Handle]^.LogType of
     Binkley, Opus : LogWriteLn(Handle, 'end, ' + LogFiles[Handle]^.Banner + #10#10);
     end;
{$I-} Close(LogFiles[Handle]^.Datei); {$I+}
If IOResult <> 0 then WriteLn('Kann LogFile ', LogFiles[Handle]^.Name,
                              ' nicht schliessen!')
Else
 Begin
{$IfDef Linux}
 ChMod(LogFiles[Handle]^.Name, FilePerm);
{$EndIf}
 End;
Dispose(LogFiles[Handle]);
LogFiles[Handle] := Nil;
end;

Procedure LogWriteLn(Handle : Byte; ToWrite : String);
Var
  Error: Integer;

begin
If LogFiles[Handle] = nil then exit;
With LogFiles[Handle]^ do begin
     Case LogType of
          Binkley, Opus : begin
                          Now(Date);
                          Today(Date);
                          If (ScrLevel >= CurLevel) then
                             WriteLn(BinkChars[CurLevel], ' ',
                                Date2BinkStr(Date), ' ', Time2Str(Date), ' ',
                                ProgID, ' ', ToWrite);
                          If (LogLevel >= CurLevel) then
                             {$I-} WriteLn(Datei, BinkChars[CurLevel], ' ',
                                Date2BinkStr(Date), ' ', Time2Str(Date), ' ',
                                ProgID, ' ', ToWrite); {$I+}
                          Error := IOResult;
                          end;
          FD            : begin
                          Now(Date);
                          If (ScrLevel >= CurLevel) then
                             WriteLn(FDChars[CurLevel], ' ', Time2Str(Date), '  ', ToWrite);
                          If (LogLevel >= CurLevel) then
                             {$I-} WriteLn(Datei, FDChars[CurLevel], ' ', Time2Str(Date), '  ', ToWrite); {$I+}
                          Error := IOResult;
                          end;
          DBridge       : begin
                          Now(Date);
                          Today(Date);
                          If (ScrLevel >= CurLevel) then
                          WriteLn(Date2DBridgeStr(Date), ' ', Copy(Time2Str(Date), 1, 5), ' ', ToWrite);
                          If (LogLevel >= CurLevel) then
                          {$I-} WriteLn(Datei, Date2DBridgeStr(Date), ' ', Copy(Time2Str(Date), 1, 5), ' ', ToWrite); {$I+}
                          Error := IOResult;
                          end;
          end;
     end;
end;

Procedure LogSetCurLevel(Handle : Byte; NewLevel : Byte);
begin
If LogFiles[Handle] = nil then exit;
LogFiles[Handle]^.CurLevel := NewLevel;
end;

Procedure LogSetLogLevel(Handle : Byte; NewLevel : Byte);
begin
If LogFiles[Handle] = nil then exit;
LogFiles[Handle]^.LogLevel := NewLevel;
end;

Procedure LogSetScrLevel(Handle : Byte; NewLevel : Byte);
begin
If LogFiles[Handle] = nil then exit;
LogFiles[Handle]^.ScrLevel := NewLevel;
end;


begin
Init;
end.
