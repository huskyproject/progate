Unit Types; {Stellt verschiedene Typen und Objekte zur VerfÅgung}
interface

type
{$IfDef GPC}
     {integer varies per target machine, usually 32Bit}
     ShortInt           = __byte__ integer;      {8  Bit, s}
     Byte               = __unsigned__ ShortInt; {8  Bit, u}
     _Integer           = __short__ integer;     {16 Bit, s}
     Word               = __unsigned__ int;      {16 Bit, u}
     LongInt            = __long__ integer;      {32 Bit, s}
     ULong              = __unsigned__ LongInt;  {32 Bit, u}
     Comp               = __longlong__ Integer;  {64 Bit, s}
     Single             = __short__ real;
     Extended           = __long__ real;
     Pointer            = ^Void;
     PChar              = ^Char;
     CString            = __cstring__;   { C style string }
{$Else}
 {$IfDef SPEED}
 {SP/2}
     _Integer           = Integer;
 {$Else}
  {$IfDef VIRTUALPASCAL}
  {VP}
     _Integer           = Integer;
     ULong              = LongInt;
  {$Else}
   {$IfDef VER70}
   {BP 7.0}
     _Integer           = Integer;
     ULong              = LongInt;
   {$Else}
    {$IfDef FPC}
    {$PackRecords 1}
     _Integer           = Integer;
     ULong              = LongInt;
    {$Else}
    {everything else}
     _Integer           = Integer;
     ULong              = LongInt;
    {$EndIf}
   {$EndIf}
  {$EndIf}
 {$EndIf}
{$EndIf}

     TimeTyp            = Record
                          Year,Month,Day,DayOfWeek:Word;
                          Hour,Min,Sec,Sec100:Word;
                          END;

     String3            = String[3];
     String4            = String[4];
     String8            = String[8];
     String10           = String[10];
     String12           = String[12];
     String20           = String[20];
     String30           = String[30];
     String40           = String[40];
     String50           = String[50];
     String80           = String[80];
     String128          = String[128];
     String255          = String[255];

     TChar = Array[0..65534] of Char;
     PChar2 = ^TChar;

implementation

begin
end.
