{ $O+,F+,I-,S-,R-,V-}
Unit MKDos;

Interface

Function GetDosDate: LongInt;
Function GetDOW: Word;

Implementation

Uses Dos;

Function GetDosDate: LongInt;
  Var
    {$IFDEF WINDOWS}
    DT: TDateTime;
    {$ELSE}
    DT: DateTime;
    {$ENDIF}
    DosDate: LongInt;
    {$IFDEF VirtualPascal}
    DOW: LongInt;
    {$ELSE}
    DOW: Word;
    {$ENDIF}
    {$IfDef SPEED}
    Day, Month, Year: Word;
    Hour, Min, Sec: Word;
    {$EndIf}

  Begin
{$IfDef SPEED}
  GetDate(Year, Month, Day, DOW);
  GetTime(Hour, Min, Sec, DOW);
  DT.Day := Day;
  DT.Month := Month;
  DT.Year := Year;
  DT.Hour := Hour;
  DT.Min := Min;
  DT.Sec := Sec;
{$Else}
  GetDate(DT.Year, DT.Month, DT.Day, DOW);
  GetTime(DT.Hour, DT.Min, DT.Sec, DOW);
{$EndIf}
  PackTime(DT, DosDate);
  GetDosDate := DosDate;
  End;


Function GetDOW: Word;
  Var
    {$IFDEF WINDOWS}
    DT: TDateTime;
    {$ELSE}
    DT: DateTime;
    {$ENDIF}
    {$IFDEF VirtualPascal}
    DOW: LongInt;
    {$ELSE}
    DOW: Word;
    {$ENDIF}
    {$IfDef SPEED}
    Day, Month, Year: Word;
    {$EndIf}

  Begin
{$IfDef SPEED}
  GetDate(Year, Month, Day, DOW);
  DT.Year := Year;
  DT.Month := Month;
  DT.Day := Day;
{$Else}
  GetDate(DT.Year, DT.Month, DT.Day, DOW);
{$EndIf}
  GetDOW := DOW;
  End;


End.
