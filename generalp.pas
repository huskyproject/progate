Unit GeneralP;
{Version 1.2}
interface
uses
{$IfNDef GPC}
  DOS,
{$EndIf}
{$IfDef SPEED}
  BseDOS, BseDev,
{$EndIf}
{$IfDef VIRTUALPASCAL}
 {Use32,} OS2Base, OS2Def,
{$EndIf}
{$IfDef LINUX}
  Linux,
{$EndIf}
  Strings,
  Types;

Const
{$IfDef LINUX}
  DirSep = '/';
{$Else}
  DirSep = '\';
{$EndIf}

{$IfDef GPC}
  pi = 3.14159265358979323846;
  MaxLongInt = MaxInt;
{$EndIf}

  Leer='                                                                                      ';
  C1970 = 2440588;
  D0 =    1461;
  D1 =  146097;
  D2 = 1721119;
  WkDaysEng  : Array[0..6] of String[9] = ('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday');
  WkDaysGer  : Array[0..6] of String[10] = ('Sonntag', 'Montag', 'Dienstag', 'Mittwoch', 'Donnerstag', 'Freitag', 'Samstag');
  WkDays3Eng : Array[0..6] of String[3] = ('Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat');
  WkDays2Eng : Array[0..6] of String[2] = ('Su', 'Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa');
  WkDays3Ger : Array[0..6] of String[3] = ('Son', 'Mon', 'Die', 'Mit', 'Don', 'Fre', 'Sam');
  WkDays2Ger : Array[0..6] of String[2] = ('So', 'Mo', 'Di', 'Mi', 'Do', 'Fr', 'Sa');
  MonthsEng  : Array[1..12] of String[9] = ('January', 'February', 'March', 'April', 'May', 'June',
                                            'July', 'August', 'September', 'October', 'November', 'December');
  MonthsGer  : Array[1..12] of String[9] = ('Januar', 'Februar', 'M„rz', 'April', 'Mai', 'Juni',
                                            'Juli', 'August', 'September', 'Oktober', 'November', 'Dezember');
  Months3Eng : Array[1..12] of String[3] = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                                            'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec');
  Months3Ger : Array[1..12] of String[3] = ('Jan', 'Feb', 'M„r', 'Apr', 'Mai', 'Jun',
                                            'Jul', 'Aug', 'Sep', 'Okt', 'Nov', 'Dez');

      CRC16Tab : ARRAY[0..255] OF WORD = (
      $0000, $1021, $2042, $3063, $4084, $50a5, $60c6, $70e7,
      $8108, $9129, $a14a, $b16b, $c18c, $d1ad, $e1ce, $f1ef,
      $1231, $0210, $3273, $2252, $52b5, $4294, $72f7, $62d6,
      $9339, $8318, $b37b, $a35a, $d3bd, $c39c, $f3ff, $e3de,
      $2462, $3443, $0420, $1401, $64e6, $74c7, $44a4, $5485,
      $a56a, $b54b, $8528, $9509, $e5ee, $f5cf, $c5ac, $d58d,
      $3653, $2672, $1611, $0630, $76d7, $66f6, $5695, $46b4,
      $b75b, $a77a, $9719, $8738, $f7df, $e7fe, $d79d, $c7bc,
      $48c4, $58e5, $6886, $78a7, $0840, $1861, $2802, $3823,
      $c9cc, $d9ed, $e98e, $f9af, $8948, $9969, $a90a, $b92b,
      $5af5, $4ad4, $7ab7, $6a96, $1a71, $0a50, $3a33, $2a12,
      $dbfd, $cbdc, $fbbf, $eb9e, $9b79, $8b58, $bb3b, $ab1a,
      $6ca6, $7c87, $4ce4, $5cc5, $2c22, $3c03, $0c60, $1c41,
      $edae, $fd8f, $cdec, $ddcd, $ad2a, $bd0b, $8d68, $9d49,
      $7e97, $6eb6, $5ed5, $4ef4, $3e13, $2e32, $1e51, $0e70,
      $ff9f, $efbe, $dfdd, $cffc, $bf1b, $af3a, $9f59, $8f78,
      $9188, $81a9, $b1ca, $a1eb, $d10c, $c12d, $f14e, $e16f,
      $1080, $00a1, $30c2, $20e3, $5004, $4025, $7046, $6067,
      $83b9, $9398, $a3fb, $b3da, $c33d, $d31c, $e37f, $f35e,
      $02b1, $1290, $22f3, $32d2, $4235, $5214, $6277, $7256,
      $b5ea, $a5cb, $95a8, $8589, $f56e, $e54f, $d52c, $c50d,
      $34e2, $24c3, $14a0, $0481, $7466, $6447, $5424, $4405,
      $a7db, $b7fa, $8799, $97b8, $e75f, $f77e, $c71d, $d73c,
      $26d3, $36f2, $0691, $16b0, $6657, $7676, $4615, $5634,
      $d94c, $c96d, $f90e, $e92f, $99c8, $89e9, $b98a, $a9ab,
      $5844, $4865, $7806, $6827, $18c0, $08e1, $3882, $28a3,
      $cb7d, $db5c, $eb3f, $fb1e, $8bf9, $9bd8, $abbb, $bb9a,
      $4a75, $5a54, $6a37, $7a16, $0af1, $1ad0, $2ab3, $3a92,
      $fd2e, $ed0f, $dd6c, $cd4d, $bdaa, $ad8b, $9de8, $8dc9,
      $7c26, $6c07, $5c64, $4c45, $3ca2, $2c83, $1ce0, $0cc1,
      $ef1f, $ff3e, $cf5d, $df7c, $af9b, $bfba, $8fd9, $9ff8,
      $6e17, $7e36, $4e55, $5e74, $2e93, $3eb2, $0ed1, $1ef0);

Var
 FilePerm: Word; {Permission used for created files under Linux}
 DirPerm: Word; {Permission used for created directories under Linux}
 ChangePerm: Boolean; {change permissions when copying or moving files?}


{$IfDef GPC}
Procedure Assign ( Var T: Text; Name: String255 );
Procedure FillChar ( Var Dest: Void; Count: Integer; C: Char );
Function ParamCount: Integer;  (* This is stupid. *)
Function ParamStr ( i: Integer ): String255;
Function GetEnv ( Entry: String255 ): String255;
Function UpCase ( Ch: Char ): Char;
function StrPas(Src: CString): String255;
function StrPCopy(Dest: CString; Src: String): CString;
Function Exec(prog, params: String255): Integer;
{$EndIf GPC}

{$IfDef FPC}
Procedure Delay(secs: Word);
{$EndIf}

{$IfNDef SPEED}
Procedure GetFTime2(var f; var Year, Month, Day, Hour, Min, Sec: Word);
{$EndIf}

Function LowCase(Ch:Char) : Char;
Function UpStr(_Str: String255) : String255;
Function LowStr(_Str: String255) : String255;
Function Date2Str(Date: TimeTyp) : String10;
Function Time2Str(Time: TimeTyp) : String10;
Function Str2Date(_Str:String255; var Date:TimeTyp):boolean;
Function Str2Time(_Str:String255; var Time:TimeTyp):boolean;
Procedure Today(var Date : TimeTyp);
Procedure Now(var Time : TimeTyp);
FUNCTION statusbar(total,aktuell:LONGINT; Laenge:BYTE):STRING255;
Function WordToHex(w: Word):String4;
Procedure FileList(Start: String255; FileSpec : Byte);
Function LowerOf(a, b : LongInt) : LongInt;
Function TimeDiff(Time1, Time2 : TimeTyp): LongInt; {in Sekunden}
Function KillLeadingSpcs(s: String255): String255;
Function KillTrailingSpcs(s: String255): String255;
Function KillSpcs(s: String): String;
Function AddDirSep(s: String255): String255;
Function GregorianToJulian(DT: TimeTyp): ULong;
Procedure JulianToGregorian(JulianDN : ULong; Var Year, Month, Day : Word);
Procedure UnixToDt(SecsPast: ULong; Var Dt: TimeTyp);
Function DTToUnixDate(DT: TimeTyp): ULong;
Function DTToUnixStr(DT: TimeTyp): String20;
Function DTToUnixHexStr(DT: TimeTyp): String8;
Function ToUnixDate(FDate: LongInt): ULong;
Function IntToStr(x: LongInt):String255;
Function IntToStr0(x: LongInt):String255;
Function IntToStr03(x: Word):String3;
Function StrToInt(s: String255): LongInt;
Function FileExist(fn: String255):Boolean;
Function DirExist(fn: String255):Boolean;
Function LastPos(SubStr, S: String255): Byte;
Function MakeDir(Dir: String128): Boolean;
Function RepEnv(s: String255):String255;
Function Translate(s: String255; IChar, OChar: Char): String255;
Function DosAppend(var f: File): Integer;
Function MoveFile(OName, NName: String255): Boolean;
Function RepFile(OName, NName: String255): Boolean;
Function CopyFile(OName, NName: String255): Boolean;
Function DelFile(Name: String255): Boolean;
Function TruncFile(Name: String255): Boolean;
Function CreateSem(Name: String255): Boolean;
Procedure GetFileTime(Name: String255; var Year, Month, Day, Hour, Min, Sec: Word);
Function GetFSize(Name: String255): LongInt;
Function leapyear (c, y : Byte) : Boolean;
Function DaysInMonth (DT:TimeTyp; m : Byte) : Byte;
Function DayOfYear (DT: TimeTyp) : Word;
function CRC16(s:string255):word;
Function GetCRC16(fn: String255): Word;

implementation

Const fCarry = $0001;


{$IfDef GPC}

Procedure Assign ( Var T: Text; Name: String255 );
Var
  B: BindingType;

begin (* Assign *)
  unbind ( T );
  B:= binding ( T );
  B.Name:= Name + chr ( 0 );
  bind ( T, B );
  B:= binding ( T );
end (* Assign *);

Procedure FillChar ( Var Dest: Void; Count: Integer; C: Char );

Type
  BytePtr = ^Byte;

Var
  p, q: BytePtr;

begin (* FillChar *)
  (*$W-*)  (* Warning "dereferencing `void *' pointer" is a minor bug in GPC *)
  p:= @Dest;
  (*$W+*)
  q:= BytePtr ( LongInt ( p ) + Count );
  while LongInt ( p ) < LongInt ( q ) do
    begin
      p^:= ord ( C );
      LongInt ( p ) := LongInt(p) + 1;
    end (* while *);
end (* FillChar *);

Function rtsParamCount: Integer;
AsmName '_p_paramcount';

Function rtsParamStr ( i: Integer; Var S: String255 ): Boolean;
AsmName '_p_paramstr';


Function ParamCount: Integer;  (* This is stupid. *)

begin (* ParamCount *)
  ParamCount:= rtsParamCount - 1;
end (* ParamCount *);


Function ParamStr ( i: Integer ): String255;

Var
  S: String255;

begin (* ParamStr *)
  if rtsParamStr ( i, S ) then
    ParamStr:= Trim ( S )
  else
    ParamStr:= '';
end (* ParamStr *);


Function CGetEnv ( Entry: __CString__ ): PChar;
AsmName 'getenv';


Function GetEnv ( Entry: String255 ): String255;

Var
  C: PChar;
  Contents: String255;

begin (* GetEnv *)
  C:= CGetEnv ( Entry );
  Contents:= '';
  if C <> Nil then
    while ( C^ <> chr ( 0 ) )
     and ( length ( Contents ) < Contents.Capacity ) do
      begin
        Contents:= Contents + C^;
        LongInt ( C ) := LongInt(C)+1;
      end (* while *);
  GetEnv:= Contents;
end (* GetEnv *);

Function UpCase ( Ch: Char ): Char;

begin (* UpCase *)
  if ( Ch >= 'a' ) and ( Ch <= 'z' ) then
    dec ( Ch, ord ( 'a' ) - ord ( 'A' ) );
  UpCase:= Ch;
end (* UpCase *);

{ Convert a "C" string to a "Pascal" string }
function StrPas(Src: CString): String255;
var
 S : String255;

 begin
 S := '';
 if (Src <> NIL) then while ( (Src^ <> chr(0)) AND (length(S) < S.capacity)) do
  begin
  S := S + Src^;
  Word(Src) := Word(Src)+1;
  end;
 StrPas := S;
 end;

{ Convert a "Pascal" string to a "C" string }
function StrPCopy(Dest: CString; Src: String): CString;
var
 c: integer;
 p: CString;

 begin
 p := Dest;
 for c:=1 to length(Src) do
  begin
  p^ := Src[c];
  word(p) := word(p)+1;
  end;
 p^ := chr(0);
 StrPCopy := Dest;
 end;

function system(name : CString): integer; C;

Function Exec(prog, params: String255): Integer;
var
 pName: CString;

 begin
 getmem(pName, 256);
 pName := StrPCopy(pName, prog+params);
 Exec := system(pName);
 freemem(pName, 256);
 end;

Function _itoa (value: integer; s: cstring; radix: integer): CString; C;
Function _ltoa (value: LongInt; s: cstring; radix: integer): CString; C;
Function _ultoa (value: ULong; s: cstring; radix: integer): CString; C;

{$EndIf GPC}


{$IfDef FPC}
Procedure Delay(secs: Word);
Var
 i: Word;

 Begin
 {bogus delay}
 For i := 1 to 10000 do Write;
 End;
{$EndIf}


Function LowCase(Ch:Char):Char;
 Begin
 if (Ch >= 'A') and (Ch <= 'Z') then LowCase := Char(Byte(Ch) + 32)
 Else LowCase := Ch;
 End;

Function UpStr(_Str:String255) : String255;
Var
 s:String255;
 i:Byte;

 Begin
 s := _str;
 For i:= 1 to Length(_str) do s[i]:=UpCase(_str[i]);
 UpStr:= s;
 End;

Function LowStr(_Str:String255) : String255;
Var
 s:String255;
 i:Byte;

 Begin
 s[0] := _str[0];
 For i:= 1 to Length(_str) do s[i]:= LowCase(_str[i]);
 LowStr:= s;
 End;

Function Date2Str(Date:TimeTyp) : String10;
var
 s,s2:String[10];
 i: Byte;

begin
s2 := IntToStr(Date.Day);
If (length(s2) < 2) then s2 := '0'+s2
Else If (s2[1] = ' ') then s2[1] := '0';
s:=s2+'.';
s2 := IntToStr(Date.Month);
If (length(s2) < 2) then s2 := '0'+s2
Else If (s2[1] = ' ') then s2[1] := '0';
s:=s+s2+'.';
s2 := IntToStr(Date.Year);
If (length(s2) < 4) then
 Begin
 for i := 1 to (4 - length(s2)) do s2 := '0' + s2;
 If (s2[4] = ' ') then s2[4] := '0';
 End
Else
 Begin
 If (s2[1] = ' ') then s2[1] := '0';
 If (s2[2] = ' ') then s2[2] := '0';
 If (s2[3] = ' ') then s2[3] := '0';
 If (s2[4] = ' ') then s2[4] := '0';
 End;
Date2Str:=s+s2;
end;

Function Time2Str(Time:TimeTyp) : String10;
var s,s2:String[10];
begin
s2 := IntToStr(Time.Hour);
If (length(s2) < 2) then s2 := '0'+s2
Else If (s2[1] = ' ') then s2[1] := '0';
s:=s2+':';
s2 := IntToStr(Time.Min);
If (length(s2) < 2) then s2 := '0'+s2
Else If (s2[1] = ' ') then s2[1] := '0';
s:=s+s2+':';
s2 := IntToStr(Time.Sec);
If (length(s2) < 2) then s2 := '0'+s2
Else If (s2[1] = ' ') then s2[1] := '0';
Time2Str:=s+s2;
end;

Function Str2Date(_Str:String255; var Date:TimeTyp):boolean;
var
 OK:boolean;
{$IfDef VIRTUALPASCAL}
  Error:LongInt;
{$Else}
  Error:integer;
{$EndIf}

begin
OK:=Pos('.', _Str)=3;
If OK then begin
   Val(Copy(_Str, 1, 2), Date.Day, Error);
   Delete(_Str, 1, 3);
   OK:=(Pos('.', _Str)=3) and (Error=0);
   If OK then begin
      Val(Copy(_Str, 1, 2), Date.Month, Error);
      Delete(_Str, 1, 3);
      OK:=(Error=0);
      If OK then Val(Copy(_Str, 1, 4), Date.Year, Error);
      OK:=(Error=0);
      end;
   end;
Str2Date:=OK;
end;

Function Str2Time(_Str:String255; var Time:TimeTyp):boolean;
var
 OK:boolean;
{$IfDef VIRTUALPASCAL}
  Error:LongInt;
{$Else}
  Error:integer;
{$EndIf}

begin
OK:=(Pos(':', _Str)=3);
If OK then begin
   Val(Copy(_Str, 1, 2), Time.Hour, Error);
   Delete(_Str, 1, 3);
   OK:=(Pos(':', _Str)=3) and (Error=0);
   If OK then begin
      Val(Copy(_Str, 1, 2), Time.Min, Error);
      Delete(_Str, 1, 3);
      OK:=(Error=0);
      end;
      If OK then begin
         Val(Copy(_Str, 1, 2), Time.Sec, Error);
         OK:=(Error=0);
         end;
   end;
Str2Time:=OK;
end;

{$IfDef VIRTUALPASCAL}
Procedure Today(var Date : TimeTyp);
Var
 Y, M, D, DOW: LongInt;
begin
GetDate(Y, M, D, DOW);
With Date do
 Begin
 Year := Y;
 Month := M;
 Day := D;
 DayOfWeek := DOW;
 End;
end;
{$Else}
Procedure Today(var Date : TimeTyp);
begin
With Date do DOS.GetDate(Year, Month, Day, DayOfWeek);
end;
{$EndIf}

{$IfDef VIRTUALPASCAL}
Procedure Now(var Time : TimeTyp);
Var
 H, M, S, S100: LongInt;

begin
GetTime(H, M, S, S100);
With Time do
 Begin
 Hour := H;
 Min := M;
 Sec := S;
 Sec100 := S100;
 End;
end;
{$Else}
Procedure Now(var Time : TimeTyp);
begin
With Time do DOS.GetTime(Hour, Min, Sec, Sec100);
end;
{$EndIf}

FUNCTION statusbar(total,aktuell:LONGINT; Laenge:BYTE):STRING255;
{*               kleine Fortschrittsanzeige                 *}
var i:LONGINT;
    s:STRING255;
    a:BYTE;
BEGIN
  s[0]:=CHR(Laenge); a:=Round(aktuell/total*laenge);
  FOR i:=1 to a DO s[i]:=#178; FOR i:=a+1 to laenge DO s[i]:=#176;
  statusbar:=s;
END;

Function WordToHex(w: Word):String4;
const
  hexChars: array [0..$F] of Char =
    '0123456789abcdef';
begin
WordToHex:=hexChars[Hi(w) shr 4]+hexChars[Hi(w) and $F]+
           hexChars[Lo(w) shr 4]+hexChars[Lo(w) and $F];
end;

Procedure FileList(Start: String255; FileSpec : Byte);
Var
  SRec: SearchRec;
Begin
  WriteLn(Start);
  FindFirst(Start + DirSep + '*.*', FileSpec, SRec);
  While (DOS.DosError = 0) Do Begin
    If ((SRec.Attr And FileSpec) > 0)
       And not ((SRec.Name = '.') or (SRec.Name = '..')) Then FileList(Start + DirSep + SRec.Name, FileSpec);
    FindNext(SRec);
    End;
End;

Function LowerOf(a, b : LongInt): LongInt;
begin
If a < b then LowerOf := a Else LowerOf := b;
end;

Function TimeDiff(Time1, Time2 : TimeTyp): LongInt; {in Sekunden}
var TDiff : LongInt;
begin
TDiff:=LongInt(LongInt(Time1.Hour) - LongInt(Time2.Hour)) * 3600;
TDiff:=TDiff + LongInt(LongInt(Time1.Min) - LongInt(Time2.Min)) * 60;
TDiff:=TDiff + LongInt(LongInt(Time1.Sec) - LongInt(Time2.Sec));
TimeDiff:= Abs(TDiff);
end;

Function KillLeadingSpcs(s: String255):String255;
  Begin
  While (s[1] = ' ') and (Length(s) > 0) do Delete(s, 1, 1);
  KillLeadingSpcs := s;
  End;

Function KillTrailingSpcs(s: String255):String255;
  Begin
  While (s[Length(s)] = ' ') and (Length(s) > 0) do Delete(s, Length(s), 1);
  KillTrailingSpcs := s;
  End;

Function KillSpcs(s: String): String; {kill leading and trailing spaces}
 Begin
 While (s[1] in [' ', #9]) and (Length(s) > 0) do Delete(s, 1, 1);
 While (s[Length(s)] in [' ', #9]) and (Length(s) > 0) do Delete(s, Length(s), 1);
 KillSpcs := s;
 End;

Function AddDirSep(s: String255): String255;
 Begin
 If (s[Byte(s[0])] <> DirSep) then AddDirSep := s + DirSep
 Else AddDirSep := s;
 End;

Function GregorianToJulian(DT: TimeTyp): ULong;
Var
  Century: ULong;
  XYear: ULong;
  Temp: ULong;
  Month: ULong;

  Begin
  Month := DT.Month;
  If Month <= 2 Then
    Begin
    Dec(DT.Year);
    Month := Month + 12;
    End;
  Dec(Month,3);
  Century := DT.Year Div 100;
  XYear := DT.Year Mod 100;
  Century := (Century * D1) shr 2;
  XYear := (XYear * D0) shr 2;
  GregorianToJulian :=  ((((Month * 153) + 2) div 5) + DT.Day) + D2
    + XYear + Century;
  End;

Procedure JulianToGregorian(JulianDN : ULong; Var Year, Month,
  Day : Word);

  Var
    Temp,
    XYear: ULong;
    YYear,
    YMonth,
    YDay: Integer;

  Begin
  Temp := (((JulianDN - D2) shl 2) - 1);
  XYear := (Temp Mod D1) or 3;
  JulianDN := Temp Div D1;
  YYear := (XYear Div D0);
  Temp := ((((XYear mod D0) + 4) shr 2) * 5) - 3;
  YMonth := Temp Div 153;
  If YMonth >= 10 Then
    Begin
    YYear := YYear + 1;
    YMonth := YMonth - 12;
    End;
  YMonth := YMonth + 3;
  YDay := Temp Mod 153;
  YDay := (YDay + 5) Div 5;
  Year := YYear + (JulianDN * 100);
  Month := YMonth;
  Day := YDay;
  End;

Procedure UnixToDt(SecsPast: ULong; Var Dt: TimeTyp);
  Var
    DateNum: ULong;

  Begin
  Datenum := (SecsPast Div 86400) + c1970;
  JulianToGregorian(DateNum, DT.Year, DT.Month, DT.day);
  SecsPast := SecsPast Mod 86400;
  DT.Hour := SecsPast Div 3600;
  SecsPast := SecsPast Mod 3600;
  DT.Min := SecsPast Div 60;
  DT.Sec := SecsPast Mod 60;
  End;

Function DTToUnixDate(DT: TimeTyp): ULong;
   Var
     SecsPast, DaysPast: ULong;

  Begin
  DaysPast := GregorianToJulian(DT) - c1970;
  SecsPast := DT.Sec + ULong(DT.Min)*60 + ULong(DT.Hour)*3600 + DaysPast*86400;
  DTToUnixDate := SecsPast;
  End;

Function ToUnixDate(FDate: LongInt): ULong;
  Var
{$IfDef VIRTUALPASCAL}
      DT: DOS.DateTime;
{$Else}
      DT: DateTime;
{$EndIf}
      DT2: TimeTyp;

  Begin
  UnpackTime(Fdate, Dt);
  dt2.Day := dt.day;
  dt2.Month := dt.Month;
  dt2.Year := dt.Year;
  dt2.Hour := dt.Hour;
  dt2.Min := dt.Min;
  dt2.Sec := dt.Sec;
  dt2.Sec100 := 0;
  ToUnixDate := DTToUnixDate(Dt2);
  End;

Function DTToUnixStr(DT: TimeTyp): String20;
Var
  s : String[20];

  Begin
  Str(DTToUnixDate(DT), s);
  DTToUnixStr := s;
  End;

Function DTToUnixHexStr(DT: TimeTyp): String8;
Var
  s : String[20];
  i: ULong;

  Begin
  i := DTToUnixDate(DT);
  s := WordToHex(word(i SHR 16)) + WordToHex(word(i));
  DTToUnixHexStr := s;
  End;

Function IntToStr(x: LongInt):String255;
Var
  s : String255;
{$IfDef GPC}
  cs: CString;
{$EndIf}

  Begin
{$IfDef GPC}
  GetMem(cs, 256);
  cs := _itoa(x, cs, 10);
  s := StrPas(cs);
  FreeMem(cs, 256);
{$Else}
  Str(x, s);
{$EndIf}
  IntToStr := s;
  End;

Function IntToStr0(x: LongInt):String255;
Var
  s : String255;
  i: Byte;

  Begin
  s := IntToStr(x);
  For i := 1 to length(s) do if s[i] = ' ' then s[i] := '0';
  IntToStr0 := s;
  End;

Function IntToStr03(x: Word):String3;
Var
  s : String[3];
  i: Byte;

  Begin
  s := IntToStr(x);
  If (length(s) = 1) then s := '0'+s;
  If (length(s) = 2) then s := '0'+s;
  For i := 1 to 3 do if s[i] = ' ' then s[i] := '0';
  IntToStr03 := s;
  End;

Function StrToInt(s: String255): LongInt;
Var
 x: LongInt;
{$IfDef VIRTUALPASCAL}
 Error : LongInt;
{$Else}
 Error : Integer;
{$EndIf}

 Begin
 Val(s, x, Error);
 If (Error <> 0) then StrToInt := 0 Else StrToInt := x;
 End;

Function FileExist(fn: String255):Boolean;
Var
  f: File;

  Begin
  Assign(f, fn);
  {$I-} ReSet(f); {$I+}
  If (IOResult = 0) then
    Begin
    {$I-} Close(f); {$I+}
    FileExist := (IOResult <> 0) or (IOResult = 0);
    End
  Else FileExist := False;
  End;

Function DirExist(fn: String255):Boolean;
Var
  SRec: SearchRec;

  Begin
  If (fn[2] = ':') and (Length(fn) = 2) then DirExist := True
  Else If (fn[2] = ':') and (fn[3] = '\') and (Length(fn) = 3) then DirExist := True
  Else
   Begin
   FindFirst(fn, Directory, SRec);
   DirExist := (DOS.DOSError = 0);
{$IfDef OS2}
   FindClose(SRec);
{$EndIf}
   End;
  End;

Function LastPos(SubStr, S: String255): Byte;
Var
  i: Byte;
  Begin
  LastPos := 0;
  For i := (Length(s)-Length(SubStr)) DownTo 1 do
    If (Copy(s, i, Length(SubStr)) = SubStr) Then
    Begin
    LastPos := i;
    Break;
    End;
  End;

Function MakeDir(Dir: String128): Boolean;
  Begin
  {$I-} MkDir(Dir); {$I+}
  If (IOResult <> 0) Then
    Begin
    If (Pos(DirSep, Dir) <> 0) Then
      Begin
      MakeDir := MakeDir(Copy(Dir, 1, LastPos(DirSep, Dir) - 1));
      {$I-} MkDir(Dir); {$I+}
      If (IOResult = 0) then
       Begin
{$IfDef Linux}
       Chmod(Dir, DirPerm);
{$EndIf}
       MakeDir := True;
       End
      Else MakeDir := False;
      End
    Else MakeDir := False;
    End
  Else
   Begin
{$IfDef Linux}
   Chmod(Dir, DirPerm);
{$EndIf}
   MakeDir := True;
   End;
  End;

Function RepEnv(s: String255):String255;
Var
  s1, s2, s3: String255;
  i: Byte;

  Begin
  s1 := s;
  i := 1;
  While (i < Length(s1)) do
   Begin
   If (s1[i] = '%') then
    Begin
    Delete(s1, i, 1);
    If not (s1[i] = '%') then
     Begin
     s3 := Copy(s1, i, Length(s1)-i+1);
     If ((Pos('%', s3) = 0) or
      ((Pos(' ', s3) > 0) and (Pos(' ', s3) < Pos('%', s3)))) then
      Begin
      Insert('%', s1, i);
      End
     Else
      Begin
      s2 := Copy(s1, i, Pos('%', s1) - i);
      Delete(s1, i, Pos('%', s1) - i + 1);
      Insert(DOS.GetEnv(UpStr(s2)), s1, i);
      End;
     End;
    End;
   Inc(i);
   End;
  RepEnv := s1;
  End;

Function Translate(s: String255; IChar, OChar: Char): String255;
Var
  s1: String255;
  i: Byte;

  Begin
  If (IChar = OChar) then
    Begin
    Translate := s;
    Exit;
    End;
  s1 := s;
  i := Pos(IChar, s1);
  While (i <> 0) do
    Begin
    s1[i] := OChar;
    i := Pos(IChar, s1);
    End;
  Translate := s1;
  End;


Function DosAppend(var f: File): Integer;
Var
 rc: Integer;

  Begin
{$IfDef SPEED}
  {$I-} Append(f); {$I+}
  If (IOResult <> 0) then
   Begin
   {$I-} ReWrite(f); {$I+}
   DOSAppend := IOResult;
   End
  Else DosAppend := 0;
{$Else}
  {$I-}
  ReSet(f);
  If (IOResult <> 0) then
   Begin
   ReWrite(f);
   rc := IOResult;
   DosAppend := rc;
   End
  Else
   Begin
   Seek(f, FileSize(f));
   DosAppend := IOResult;
   End;
  {$I+}
{$EndIf}
  End;

Function MoveFile(OName, NName: String255): Boolean;
{$IfDef SPEED}
Var
  rc: APIRet;
  cs1, cs2: CString;

  Begin
  If FileExist(NName) then MoveFile := False
  Else
    Begin
    cs1 := OName;
    cs2 := NName;
    rc := DosMove(cs1, cs2);
    If (rc <> 0) then
      Begin
      rc := DosCopy(cs1, cs2, 0);
      If (rc <> 0) then
        Begin
        MoveFile := False;
        End
      Else
        Begin
        rc := DosDelete(cs1);
        MoveFile := (rc = 0);
        End;
      End
    Else MoveFile := True;
    End;
  End;

{$Else}
 {$IfDef VIRTUALPASCAL}
Var
  rc: LongInt;
  cs1, cs2: PChar;

  Begin
  If FileExist(NName) then MoveFile := False
  Else
    Begin
    GetMem(cs1, 256);
    GetMem(cs2, 256);
    StrPCopy(cs1, OName);
    StrPCopy(cs2, NName);
    rc := DosMove(cs1, cs2);
    If (rc <> 0) then
      Begin
      rc := DosCopy(cs1, cs2, 0);
      If (rc <> 0) then
        Begin
        MoveFile := False;
        End
      Else
        Begin
        rc := DosDelete(cs1);
        MoveFile := (rc = 0);
        End;
      End
    Else MoveFile := True;
    FreeMem(cs1, 256);
    FreeMem(cs2, 256);
    End;
  End;

 {$Else}

Var
  f: File;

  Begin
  If FileExist(NName) then MoveFile := False
  Else
    Begin
    Assign(f, OName);
    {$I-} Rename(f, NName); {$I+}
    If ((IOResult <> 0) or not FileExist(NName)) then
      Begin
{$IfDef LINUX}
      shell('cp '+OName+' '+NName);
      If ChangePerm then ChMod(NName, FilePerm);
{$Else}
      SwapVectors;
      Exec(GetEnv('COMSPEC'), '/C copy '+OName+' '+NName);
      SwapVectors;
{$EndIf}
      If (FileExist(OName) and FileExist(NName)) then
        Begin
        Assign(f, OName);
        {$I-} Erase(f); {$I+}
        MoveFile := (IOResult = 0);
        End
      Else MoveFile := False;
      End
    Else MoveFile := True;
    End;
  End;
 {$EndIf}
{$EndIf}

Function RepFile(OName, NName: String255): Boolean;
{$IfDef SPEED}
Var
  rc: APIRet;
  cs1, cs2: CString;

  Begin
  cs1 := OName;
  cs2 := NName;
  rc := DosMove(cs1, cs2);
  If (rc <> 0) then
    Begin
    rc := DosCopy(cs1, cs2, 1);
    If (rc <> 0) then
      Begin
      RepFile := False;
      End
    Else
      Begin
      rc := DosDelete(cs1);
      RepFile := (rc = 0);
      End;
    End
  Else RepFile := True;
  End;

{$Else}
Var
  f: File;

  Begin
  Assign(f, OName);
  {$I-} Rename(f, NName); {$I+}
  If ((IOResult <> 0) or not FileExist(NName)) then
    Begin
{$IfDef LINUX}
    shell('cp '+OName+' '+NName);
    If ChangePerm then Chmod(NName, FilePerm);
{$Else}
    SwapVectors;
    Exec(GetEnv('COMSPEC'), '/C copy '+OName+' '+NName);
    SwapVectors;
{$EndIf}
    If (FileExist(OName) and FileExist(NName)) then
      Begin
      Assign(f, OName);
      {$I-} Erase(f); {$I+}
      RepFile := (IOResult = 0);
      End
    Else RepFile := False;
    End
  Else RepFile := True;
  End;
{$EndIf}

Function CopyFile(OName, NName: String255): Boolean;
{$IfDef SPEED}
Var
  cs1, cs2: CString;

  Begin
  cs1 := OName;
  cs2 := NName;
  CopyFile := (DosCopy(cs1, cs2, 0) = 0);
  End;

{$Else}

  Begin
{$IfDef LINUX}
  shell('cp '+OName+' '+NName);
  If ChangePerm then Chmod(NName, FilePerm);
{$Else}
  SwapVectors;
  Exec(GetEnv('COMSPEC'), '/C copy '+OName+' '+NName);
  SwapVectors;
{$EndIf}
  CopyFile := FileExist(NName);
  End;
{$EndIf}

Function DelFile(Name: String255): Boolean;
Var
  f: File;

  Begin
  Assign(f, Name);
  {$I-} Erase(f); {$I+}
  DelFile := ((IOResult = 0) and not FileExist(Name));
  End;

Function TruncFile(Name: String255): Boolean;
Var
  f: File;

  Begin
  Assign(f, Name);
  {$I-} ReWrite(f); {$I+}
  If (IOResult = 0) then
   Begin
   {$I-} Close(f); {$I+}
   TruncFile := (IOResult = 0);
   End
  Else TruncFile := False;
  End;

Function CreateSem(Name: String255): Boolean;
Var
  f: Text;
  i: Integer;

  Begin
  Assign(f, Name);
  {$I-} ReWrite(f); {$I+}
  If (IOResult = 0) then
   Begin
   {$I-} WriteLn(f); {$I+}
   i := IOResult;
   {$I-} Close(f); {$I+}
{$IfDef Linux}
   Chmod(Name, FilePerm);
{$EndIf}
   CreateSem := (IOResult = 0) and (i = 0);
   End
  Else CreateSem := False;
  End;

{$IfNDef SPEED}
Procedure GetFTime2(var f; var Year, Month, Day, Hour, Min, Sec: Word);
Var
  i: LongInt;
{$IfDef VIRTUALPASCAL}
  DT: DOS.DateTime;
{$Else}
  DT: DateTime;
{$EndIf}

  Begin
  GetFTime(f, i);
  UnPackTime(i, DT);
  Year := DT.Year;
  Month := DT.Month;
  Day := DT.Day;
  Hour := DT.Hour;
  Min := DT.Min;
  Sec := DT.Sec;
  End;
{$EndIf}

Procedure GetFileTime(Name: String255; var Year, Month, Day, Hour, Min, Sec: Word);
Var
  f: File;

  Begin
  Assign(f, Name);
  {$I-} ReSet(f); {$I-}
  If (IOResult = 0) then
    Begin
    GetFTime2(f, Year, Month, Day, Hour, Min, Sec);
    {$I-} Close(f); {$I+}
    If (IOResult = 0) then ;
    End;
  End;

Function GetFSize(Name: String255): LongInt;
Var
  f: File of Byte;

  Begin
  Assign(f, Name);
  {$I-} ReSet(f); {$I+}
  If (IOResult = 0) then
    Begin
    GetFSize := FileSize(f);
    {$I-} Close(f); {$I+}
    If (IOResult = 0) then ;
    End
  Else GetFSize := 0;
  End;

Function leapyear (c, y : Byte) : Boolean;
begin
  if (y and 3) <> 0 then
          leapyear := False
  else
        if y <> 0 then
          leapyear := True
  else
        if (c and 3) = 0 then
          leapyear := True
  else
          leapyear := False;
end;

Function DaysInMonth (DT:TimeTyp; m : Byte) : Byte;
begin
  if m = 2 then
          if leapyear(DT.Year div 100, DT.Year mod 100) then
                  DaysInMonth := 29
    else
                  DaysInMonth := 28
  else
          DaysInMonth := 30 + (($15AA shr m) and 1);
end;

Function DayOfYear (DT: TimeTyp) : Word;
Var i, j : Integer;
begin
  j := DT.Day;
  If (DT.Month > 1) then For i := 1 to pred(DT.Month) do
   j := j + DaysInMonth(DT,i);
  DayOfYear := j;
end;

function CRC16(s:string255):word;  { By Kevin Cooney }
var
  crc : longint;
  t,r : byte;
begin
  crc:=0;
  for t:=1 to length(s) do
  begin
    crc:=(crc xor (ord(s[t]) shl 8));
    for r:=1 to 8 do
      if (crc and $8000)>0 then
        crc:=((crc shl 1) xor $1021)
          else
            crc:=(crc shl 1);
  end;
  CRC16:=(crc and $FFFF);
end;

Function GetCRC16(fn: String255): Word;
Type
 PBuff = ^TBuff;
 TBuff = Array[1..65530] of Byte;

Var
 f: File;
 Buf: PBuff;
{$IfDef SPEED}
 nr: LongWord;
{$Else}
 {$IfDef VIRTUALPASCAL}
 nr: LongInt;
 {$Else}
 nr: Word;
 {$EndIf}
{$EndIf}
 i, j: Word;
 CRC: Longint;

 Begin
 CRC := $0000;
 Assign(f, fn);
 {$I-} ReSet(f, 1); {$I+}
 If (IOResult <> 0) then
  Begin
  GetCRC16 := $FFFF;
  Exit;
  End;
 New(Buf);
  Repeat
  BlockRead(f, Buf^, 65530, nr);
  If (nr > 0) then
   Begin
   For i := 1 to nr do
    Begin
    crc:=(crc xor (ord(Buf^[i]) shl 8));
    for j:=1 to 8 do
     if (crc and $8000)>0 then crc:=((crc shl 1) xor $1021)
     else crc:=(crc shl 1);
    End;
   End;
  Until (nr < 65530);
 GetCRC16 := (CRC and $FFFF);
 Dispose(Buf);
 Close(f);
 End;

Begin
{$IfDef Linux}
If (DOS.GetEnv('UMASK') <> '') then
 Begin
 FilePerm := Octal(StrToInt(DOS.GetEnv('UMASK')));
 FilePerm := 511 and not FilePerm;
 DirPerm := FilePerm;
 End
Else
 Begin
 FilePerm := 493; {octal 755}
 DirPerm := 493; {octal 755}
 End;
{$Else}
FilePerm := 0; DirPerm := 0;
{$EndIf}
ChangePerm := False;
end.

