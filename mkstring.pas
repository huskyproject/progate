{ $O+,F+,I-,S-,R-,V-}
Unit MKString;

Interface

Uses {Objects, }Dos,
{$IfDef VirtualPascal}
Use32,
{$EndIf}
GeneralP;

const
  hexChars: array [0..$F] of Char = '0123456789ABCDEF';

Procedure MKStrCat(Var St: String; AStr: String);
Function LoCase(Chr: Char): Char;
Function padright(st:string;ch:char;l:integer):string;
Function PadLeft(St:String;Ch:Char;L:Integer): String;
function striplead(st:string;ch:char):string;
Function StripTrail(St:String;Ch:Char):String;
Function StripBoth(St:String;Ch:Char):String;
Function Lower(S : string) : string;
Function Upper(S : string) : string;
Function WWrap(St:String; Max:Byte):String;
function ExtractWord(Str : String; N : Integer) : String;
Function WordCount(Str : String) : Integer;
Function CommaStr(Number: LongInt): String;
Function Long2Str(Number: LongInt): String;
Function Bin2Str(Number: Byte): String;
Function Str2Bin(St: String): Byte;
Function Str2Long(St: String): LongInt;
Function HexLong(Number:LongInt): String;
Function HexStr(Number: Word): String;
Function HexByte(Number: Byte): String;
Function DateStr(DosDate: LongInt): String;
Function TimeStr(DosDate: LongInt): String;
Procedure AddBackSlash(Var InPath: String);
Function WithBackSlash(InPath: String): String;
{$IFDEF WINDOWS}
Function FormattedDate(DT: TDateTime; Mask: String): String;
{$ELSE}
Function FormattedDate(DT: DateTime; Mask: String): String;
{$ENDIF}
Function FormattedDosDate(DosDate: LongInt; Mask:String): String;
Function DOWStr(Dow: Word): String;
Function DOWShortStr(DOW: Word): String;
Function ReformatDate(ODate: String; Mask: String): String;
Function LongDate(DStr: String): LongInt;
Function TimeStr2Word(TS: String): Word;
Function Word2TimeStr(CTime: Word): String;
Function MonthStr(MonthNo: Word): String;
Function Az2Str(Var Str: String; MaxLen: Byte): String; {Convert asciiz to string}
Procedure Str2Az(Str: String; MaxLen: Byte; Var AZStr); {Convert string to asciiz}
Function MKDateToStr(MKD: String): String; {Convert YYMMDD to MM-DD-YY}
Function StrToMKDate(Str: String): String; {Convert MM-DD-YY to YYMMDD}
Function CleanChar(InChar: Char): Char;
Function IsNumeric(Str: String): Boolean;
Function PosLastChar(Ch: Char; St: String): Word;
Function Proper (Str : String) : String;
Function MakeName (Name : String): String;


Const
  CommaChar: Char = ',';

Var
  ExtraString: String;

Implementation


function LoCase(Chr: Char): Char;
begin
  case chr of
    'A'..'Z': LoCase:=char(byte(Chr)+32)
  else
    LoCase:=Chr;
  end;
end;


Procedure AddBackSlash(Var InPath: String);
  Begin
  If Length(InPath) > 0 Then
    Begin
    If InPath[Length(InPath)] <> DirSep Then
      Begin
      InPath[0] := Chr(Length(InPath) + 1);
      InPath[Length(InPath)] := DirSep;
      End;
    End;
  End;


Function WithBackSlash(InPath: String): String;
  Begin
  AddBackSlash(InPath);
  WithBackSlash := InPath;
  End;


Function Bin2Str(Number: Byte): String;
  Var
    Temp1: Byte;
    Temp2: Byte;
    i: Word;
    TempStr: String[8];

  Begin
  Temp1 := 0;
  Temp2 := $80;
  For i := 1 to 8 Do
    Begin
    If (Number and Temp2) <> 0 Then
      TempStr[i] := '1'
    Else
      TempStr[i] := '0';
    Temp2 := Temp2 shr 1;
    End;
  TempStr[0] := #8;
  Bin2Str := TempStr;
  End;


Function Str2Bin(St: String): Byte;
  Var
    i: Word;
    Temp1: Byte;
    Temp2: Byte;

  Begin
  St := StripBoth(St,' ');
  St := PadLeft(St,'0',8);
  Temp1 := 0;
  Temp2 := $80;
  For i := 1 to 8 Do
    Begin
    If St[i] = '1' Then
      Inc(Temp1,Temp2);
    Temp2 := Temp2 shr 1;
    End;
  Str2Bin := Temp1;
  End;

function Str2Long(St: String): LongInt;
var
   Temp: LongInt;
   Code: Integer;
begin
  Val(St,Temp,Code);
  Str2Long:=Temp;
end;

Function DateStr(DosDate: LongInt): String;
  Var
{$IFDEF WINDOWS}
    DT:TDateTime;
{$ELSE}
    DT: DateTime;
{$ENDIF}
    OutStr: String[8];
    TempStr: String[8];

  Begin
    UnPackTime(DosDate,DT);
    Str(DT.Month:2,TempStr);
    If TempStr[1] = ' ' Then
      OutStr[1] := '0'
    Else
      OutStr[1] := TempStr[1];
    OutStr[2] := TempStr[2];
    OutStr[3] := '-';
    Str(DT.Day:2,TempStr);
    If TempStr[1] = ' ' Then
      OutStr[4] := '0'
    Else
      OutStr[4] := TempStr[1];
    OutStr[5] := TempStr[2];
    OutStr[6] := '-';
    Str(DT.Year:4,TempStr);
    If TempStr[3] = ' ' Then
      OutStr[7] := '0'
    Else
      OutStr[7] := TempStr[3];
    OutStr[8] := TempStr[4];
    OutStr[0] := #8;
    DateStr := OutStr;
  End;

Function TimeStr(DosDate: LongInt): String;
  Var
{$IFDEF WINDOWS}
    DT: TDateTime;
{$ELSE}
    DT: DateTime;
{$ENDIF}
    OutStr: String[8];
    TempStr: String[8];

  Begin
    UnPackTime(DosDate,DT);
    Str(DT.Hour:2,TempStr);
    If TempStr[1] = ' ' Then
      OutStr[1] := '0'
    Else
      OutStr[1] := TempStr[1];
    OutStr[2] := TempStr[2];
    OutStr[3] := ':';
    Str(DT.Min:2,TempStr);
    If TempStr[1] = ' ' Then
      OutStr[4] := '0'
    Else
      OutStr[4] := TempStr[1];
    OutStr[5] := TempStr[2];
    OutStr[6] := ':';
    Str(DT.Sec:2,TempStr);
    If TempStr[1] = ' ' Then
      OutStr[7] := '0'
    Else
      OutStr[7] := TempStr[1];
    OutStr[8] := TempStr[2];
    OutStr[0] := #8;
    TimeStr := OutStr;
  End;

function HexByte(Number: Byte): string;
begin
  HexByte:=hexChars[Number shr 4]+hexChars[Number and $F];
end;

Function HexStr(Number: Word): String;
begin
  HexStr := HexByte(Number Shr 8) + HexByte(Number And $FF);
end;

function HexLong(Number: LongInt): String;
begin
  HexLong := HexStr(Number div $FFFF) + HexStr(Number mod $FFFF);
end;


function Long2Str(Number: LongInt): String;
var
  TempStr: String;
begin
  Str(Number,TempStr);
  Long2Str := TempStr;
end;


Function CommaStr(Number: LongInt): String;
  Var
    StrPos: Integer;
    NumberStr: String;

  Begin
  NumberStr := Long2Str(Number);
  StrPos := Length(NumberStr) - 2;
  While StrPos > 1 Do
    Begin
    Insert(',',NumberStr,StrPos);
    StrPos := StrPos - 3;
    End;
  CommaStr := NumberStr;
  End;





Function wordcount(str : string) : integer;

  var
    count : integer;
    i : integer;
    len : integer;

  begin
  len := length(str);
  count := 0;
  i := 1;
  while i <= len do
    begin
    while ((i <= len) and ((str[i] = #32) or (str[i] = #9) or (Str[i] = ';'))) do
      inc(i);
    if i <= len then
      inc(count);
    while ((i <= len) and ((str[i] <> #32) and (str[i] <> #9) and (Str[i] <> ';'))) do
      inc(i);
    end;
  wordcount := count;
  end;


function extractword(str : string; n : integer) : string;
  Var
    count : integer;
    i : integer;
    len : integer;
    done : boolean;
    retstr : string;

  Begin
  retstr := '';
  len := length(str);
  count := 0;
  i := 1;
  done := false;
  While (i <= len) and (not done) do
    Begin
    While ((i <= len) and ((str[i] = #32) or (str[i] = #9) or (Str[i] = ';'))) do
      inc(i);
    if i <= len then
      inc(count);
    if count = n then
      begin
      retstr[0] := #0;
      If (i > 1) Then
        If Str[i-1] = ';' Then
          RetStr := ';';
      while ((i <= len) and ((str[i] <> #32) and (str[i] <> #9) and (Str[i] <> ';'))) do
        begin
        inc(byte(retstr[0]));
        retstr[ord(retstr[0])] := str[i];
        inc(i);
        end;
      done := true;
      end
    Else
      while ((i <= len) and ((str[i] <> #32) and (str[i] <> #9) and (Str[i] <> ';'))) do
        inc(i);
    End;
  extractword := retstr;
  End;


Function WWrap(St:String; Max:Byte):String;
  Var
    TempStr: String;
    TempPos: Byte;

  Begin
  ExtraString := '';
  TempStr := St;
  If Length(TempStr) > Max Then
    Begin
    TempPos := Max;
    While ((TempStr[TempPos] <> ' ') And (TempPos > (Max - 20))
      And (TempPos > 1)) Do
      Dec(TempPos);
    If (Length(TempStr) > TempPos) Then
      ExtraString := Copy(TempStr,TempPos + 1,Length(TempStr) - TempPos);
    TempStr[0] := Chr(TempPos);
    End;
  WWrap := TempStr;
  End;


{Function Proper(St:String):String;
  Var
    TempStr: String;
    i: Integer;
    NextUp: Boolean;

  Begin
  If Length(St) = 0 Then
    Proper := ''
  Else
    Begin
    i := 1;
    NextUp := True;
    TempStr := St;
    While i <= Length(TempStr) Do
      Begin
      If ((TempStr[i] < 'A') Or (TempStr[i] > 'z')
        Or ((TempStr[i] > 'Z') And (TempStr[i] < 'a')) ) Then
        Begin
        NextUp := True;
        End
      Else
        Begin
        If NextUp = True Then
          Begin
          NextUp := False;
          TempStr[i] := UpCase(TempStr[i]);
          End
        Else
          Begin
          If TempStr[i] < 'a' Then
            TempStr[i] := Char(Ord(TempStr[i]) + 32);
          End;
        End;
      i := i + 1;
      End;
    Proper := TempStr;
    End;
  End;}


Function PadLeft(St:String;Ch:Char;L:Integer): String;
var
  TempStr: String;
  i: Word;
begin
  If Length(St) >= L Then
    PadLeft := Copy(St,1,L)
  else begin
    For i := 1 to (L - Length(St)) Do
      TempStr[i] := Ch;
    TempStr[0] := Chr(L - Length(St));
    PadLeft := TempStr + St;
  end;
end;


Function padright(st:string;ch:char;l:integer):string;
var
  i:          integer;
  tempstr:    string;
begin
  tempstr := st;
  if length(tempstr) > l then
    tempstr[0] := chr(l)
  else if length(tempstr) < l then begin
    for i := length(tempstr)+1 to l do tempstr[i] := ch;
    tempstr[0] := chr(l);
  end;
  padright := tempstr;
end;

function Lower(S : string) : string;
var
  tmp: string;
  i: integer;
begin
  tmp := '';
  for i:=1 to length(s) do
    Case s[i] of
     'A'..'Z' : tmp := tmp + char(byte(s[i])+32);
     'š' : tmp := tmp + '';
     '™' : tmp := tmp + '”';
     'Ž' : tmp := tmp + '„';
     else
       tmp := tmp + s[i];
    end;
  Lower := tmp;
end;

function Upper(S : string) : string;
var
  tmp: string;
  i: integer;
begin
  tmp := '';
  for i:=1 to length(s) do
    Case s[i] of
     'a'..'z' : tmp := tmp + char(byte(s[i])-32);
     '' : tmp := tmp + 'š';
     '”' : tmp := tmp + '™';
     '„' : tmp := tmp + 'Ž';
     else
       tmp := tmp + s[i];
    end;
  Upper := tmp;
end;

function striplead(st:string;ch:char):string;
var
  tempstr: string;
begin
  tempstr:=st;
  while ((TempStr[1]=Ch) and (Length(TempStr)>0)) do
    tempstr:=copy (tempstr,2,length(tempstr));
  striplead:=tempstr;
end;

function StripTrail(St: String; Ch: Char): String;
begin
  while ((length(St)>0) and (St[length(St)]=Ch)) Do Dec(byte(St[0]));
  StripTrail:=St;
end;

function StripBoth(St: String; Ch: Char): String;
begin
  StripBoth:=StripTrail(StripLead(St,Ch),Ch);
end;


{$IFDEF WINDOWS}
Function FormattedDate(DT: TDateTime; Mask: String): String;
{$ELSE}
Function FormattedDate(DT: DateTime; Mask: String): String;
{$ENDIF}
  Var
    DStr: String[2];
    MStr: String[2];
    MNStr: String[3];
    YStr: String[4];
    HourStr: String[2];
    MinStr: String[2];
    SecStr: String[2];
    TmpStr: String;
    CurrPos: Word;
    i: Word;

  Begin
  TmpStr := Mask;
  Mask := Upper(Mask);
  DStr := Copy(PadLeft(Long2Str(Dt.Day),'0',2),1,2);
  MStr := Copy(PadLeft(Long2Str(Dt.Month),'0',2),1,2);
  YStr := Copy(PadLeft(Long2Str(Dt.Year),'0',4),1,4);
  HourStr := Copy(PadLeft(Long2Str(Dt.Hour),' ', 2),1,2);
  MinStr := Copy(PadLeft(Long2Str(Dt.Min), '0',2),1,2);
  SecStr := Copy(PadLeft(Long2Str(Dt.Sec), '0',2),1,2);
  MNStr := MonthStr(Dt.Month);
  If (Pos('YYYY', Mask) = 0) Then
    YStr := Copy(YStr,3,2);
  CurrPos := Pos('DD', Mask);
  If CurrPos > 0 Then
    For i := 1 to Length(DStr) Do
      TmpStr[CurrPos + i - 1] := DStr[i];
  CurrPos := Pos('YY', Mask);
  If CurrPos > 0 Then
    For i := 1 to Length(YStr) Do
      TmpStr[CurrPos + i - 1] := YStr[i];
  CurrPos := Pos('MM', Mask);
  If CurrPos > 0 Then
    For i := 1 to Length(MStr) Do
      TmpStr[CurrPos + i - 1] := MStr[i];
  CurrPos := Pos('HH', Mask);
  If CurrPos > 0 Then
    For i := 1 to Length(HourStr) Do
      TmpStr[CurrPos + i - 1] := HourStr[i];
  CurrPos := Pos('SS', Mask);
  If CurrPos > 0 Then
    For i := 1 to Length(SecStr) Do
      TmpStr[CurrPos + i - 1] := SecStr[i];
  CurrPos := Pos('II', Mask);
  If CurrPos > 0 Then
    For i := 1 to Length(MinStr) Do
      TmpStr[CurrPos + i - 1] := MinStr[i];
  CurrPos := Pos('NNN', Mask);
  If CurrPos > 0 Then
    For i := 1 to Length(MNStr) Do
      TmpStr[CurrPos + i - 1] := MNStr[i];
  FormattedDate := TmpStr;
  End;


Function FormattedDosDate(DosDate: LongInt; Mask:String): String;
  Var
    {$IFDEF WINDOWS}
    DT: TDateTime;
    {$ELSE}
    DT: DateTime;
    {$ENDIF}

  Begin
  UnPackTime(DosDate, DT);
  FormattedDosDate := FormattedDate(DT, Mask);
  End;

function DOWStr(Dow: Word): String;
begin
  Case DOW of
    0: DOWStr := 'Sunday';
    1: DOWStr := 'Monday';
    2: DOWStr := 'Tuesday';
    3: DOWStr := 'Wednesday';
    4: DOWStr := 'Thursday';
    5: DOWStr := 'Friday';
    6: DOWStr := 'Saturday';
    else
      DOWStr := '?????';
  end;
end;

function DOWShortStr(DOW: Word): String;
begin
  DOWShortStr := Copy(DOWStr(Dow),1,3);
end;

Function ReformatDate(ODate: String; Mask: String): String;
  Var
    Code: Word;
    {$IFDEF WINDOWS}
    DT: TDateTime;
    {$ELSE}
    DT: DateTime;
    {$ENDIF}

  Begin
  Val(Copy(ODate,7,2), DT.Year, Code);
  Val(Copy(ODate,1,2), DT.Month, Code);
  Val(Copy(ODate,4,2), DT.Day, Code);
  If DT.Year < 80 Then
    Inc(DT.Year, 2000)
  Else
    Inc(DT.Year, 1900);
  ReformatDate := FormattedDate(DT, Mask);
  End;


Function Word2TimeStr(CTime: Word): String;
  Begin
  Word2TimeStr := PadLeft(Long2Str(Hi(CTime)),'0',2) + ':' +
    PadLeft(Long2Str(Lo(CTime)),'0',2);
  End;


Function TimeStr2Word(TS: String): Word;
  Var
    Vr: Word;
    Vr2: Word;
    Code: Word;

  Begin
  Val(Copy(TS,1,2), Vr, Code);
  Val(Copy(TS,4,2), Vr2, Code);
  TimeStr2Word := Vr2 + (Vr shl 8);
  End;


function MonthStr(MonthNo: Word): String;
begin
  Case MonthNo of
    01: MonthStr := 'Jan';
    02: MonthStr := 'Feb';
    03: MonthStr := 'Mar';
    04: MonthStr := 'Apr';
    05: MonthStr := 'May';
    06: MonthStr := 'Jun';
    07: MonthStr := 'Jul';
    08: MonthStr := 'Aug';
    09: MonthStr := 'Sep';
    10: MonthStr := 'Oct';
    11: MonthStr := 'Nov';
    12: MonthStr := 'Dec';
    else
      MonthStr := '???';
  end;
end;

function Az2Str(Var Str: String; MaxLen: Byte): String; {Convert asciiz to string}
var
  i: Word;
  TmpStr: String;
begin
  For i := 1 to MaxLen do TmpStr[i] := Str[i-1];
{  Move(Str, TmpStr[1], MaxLen);}
  TmpStr[0] := Chr(MaxLen);
  i := Pos(#0, TmpStr);
  If i > 0 Then TmpStr[0] := Chr(i - 1);
  Az2Str := TmpStr;
end;

procedure Str2Az(Str: String; MaxLen: Byte; Var AZStr); {Convert string to asciiz}
begin
  if Length(Str) >= MaxLen then begin
    Str[MaxLen] := #0;
    Move(Str[1], AZStr, MaxLen);
  end else begin
    Str[Length(Str) + 1] := #0;
    Move(Str[1], AZStr, Length(Str) + 1);
  end;
end;

Function MKDateToStr(MKD: String): String; {Convert YYMMDD to MM-DD-YY}
  Begin
  MKDateToStr := Copy(MKD,3,2) + '-' + Copy(MKD,5,2) + '-' +
    Copy(MKD,1,2);
  End;


Function StrToMKDate(Str: String): String; {Convert MM-DD-YY to YYMMDD}
  Begin
  StrToMKDate := Copy(Str,7,2) + Copy(Str,1,2) + Copy(Str,4,2);
  End;


Function CleanChar(InChar: Char): Char;
  Const
    CtlChars: String[32] = 'oooooooooXoollo><|!Pg*|^v><-^v';
    HiChars: String[64] = 'CueaaaageeeiiiAAEaaooouuyOUcLYPfarounNao?--//!<>***|||||||||||||';
    HiChars2: String[64]= '|--|-+||||=+|=++-=--==-||||*****abcnEduto0nd80En=+><fj/~oo.vn2* ';

  Begin
  Case InChar of
    #0..#31: CleanChar := CtlChars[Ord(InChar) + 1];
    #128..#191: CleanChar := HiChars[Ord(InChar) - 127];
    #192..#255: CleanChar := HiChars2[Ord(InChar) - 191];
    Else
      CleanChar := InChar;
    End;
  End;


Function IsNumeric(Str: String): Boolean;
  Var
    i: Word;

begin
  IsNumeric := True;
  for i := 1 To Length(Str) Do
    If not (Str[i] in ['0'..'9']) Then IsNumeric := False;
end;


Function LongDate(DStr: String): LongInt;
  Var
    {$IFDEF WINDOWS}
    DT: TDateTime;
    {$ELSE}
    DT: DateTime;
    {$ENDIF}
    DosDate: LongInt;

  Begin
  DT.Year := Str2Long(Copy(DStr,7,2));
  If Dt.Year < 80 Then
    Inc(DT.Year, 2000)
  Else
    Inc(DT.Year, 1900);
  DT.Month := Str2Long(Copy(DStr,1,2));
  DT.Day := Str2Long(Copy(DStr,4,2));
  DT.Hour := 0;
  DT.Min := 0;
  DT.Sec := 0;
  PackTime(DT, DosDate);
  LongDate := DosDate;
  End;


Procedure MKStrCat(Var St: String; AStr: String);
  Var
    i: Word;

  Begin
  i := Length(AStr);
  If i + Length(St) > 255 Then
    i := 255 - Length(St);
  Move(AStr[1], St[Length(St) + 1], i);
  Inc(byte(St[0]), i);
  End;


Function PosLastChar(Ch: Char; St: String): Word;
  Var
    i: Word;

  Begin
  i := Length(St);
  While ((i > 0) and (st[i] <> ch)) Do
    Dec(i);
  PosLastChar := i;
  End;

function Proper (Str : String) : String;
  var
    I     : Integer;
    Space : Boolean;
  begin
      Space := True;
      Str := Lower(Str);
      for I := 1 to Length (Str) do
        If Space and (Ord (Str [I]) in [97..122]) then begin
              Space := False;
              Str[I] := Upcase (Str [I]);
        end else If (Space = False) and (Str[I] = ' ') then
              Space := True;
    Proper := Str;
  end;

function MakeName (Name : String): String;
  var
    Comma : String[2];
  begin
    If Pos (' ', Name) > 0 then Comma := ', ' else Comma := '';
    MakeName := Copy (Name, Pos (' ', Name) + 1, Length (Name) - Pos (' ', Name))
                + Comma + Copy (Name, 1, Pos (' ', Name) - 1) + #0;
  end;

End.
