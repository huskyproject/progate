{
ÚÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ¿
³                                                                           ³
³      ÛÛÛ° Û°  Û° ÛÛÛ°   ÛÛÛ° ÛÛÛ° Û°   ÛÛÛ°   Û° Û° Û°  Û° ÛÛÛ° ÛÛÛ°      ³
³       Û°  ÛÛ° Û°  Û°    Û°    Û°  Û°   Û°     Û° Û° ÛÛ° Û°  Û°   Û°       ³
³       Û°  Û°Û°Û°  Û°    ÛÛ°   Û°  Û°   ÛÛ°    Û° Û° Û°Û°Û°  Û°   Û°       ³
³       Û°  Û° ÛÛ°  Û°    Û°    Û°  Û°   Û°     Û° Û° Û° ÛÛ°  Û°   Û°       ³
³      ÛÛÛ° Û°  Û° ÛÛÛ°   Û°   ÛÛÛ° ÛÛÛ° ÛÛÛ°   ÛÛÛÛ° Û°  Û° ÛÛÛ°  Û°       ³
³                                                                           ³
³      Ver. : 1.00b ...... (c) 1996 by Stephan Zehrer ...... FreeWare       ³
³                                                                           ³
ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´
³ IniFile Unit dient zur verarbeitung von config Dateien in Textform wie    ³
³ INI oder CFG.                                                             ³
³ Hier einige Features von IniFile Unit :                                   ³
³   - Einfache Bedinung (4 Routinen fuer Grund Funktionen)                  ³
³   - Alles in einem Object, daduch mehrer Listen gleichzeitig nutzbar      ³
³   - Aufleilung in Untergruppen (Sectionen)                                ³
³   - Kommentarverwaltung von jede Option (';')                             ³
³   - kommplette Einlesen der Ini File in eine einfach verkettete Liste     ³
³   - schnelle Verarbeitung da keine lese/schreib zugriffe Waeren des       ³
³     ein und auslesens.                                                    ³
³   - DataBase Funktionen                                                   ³
³     ( Aufbau von kleine Datenbanken in Textform wie z.B. PLZ Listen oder  ³
³       Listen von Telefon Nummern )                                        ³
³                                                                           ³
³     !!! Achtung Version ohne externe Functionen (siehe Dateiende) !!!     ³
³                                                                           ³
ÃÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ´
³ Diese Version wurde ausgibig von mir getestet. Es kann trotzdem vorkommen ³
³ das sich Fehler einschleichen.                                            ³
³ Bitte schicken Sie einen Bug report an : Stephan Zehrer@2:2487/9001.14    ³
³                                                                           ³
³ Der Autor uebernimmt keine Haftung fuer Schaeden, die durch dieses Programm³
³ entstanden sind.                                                          ³
ÀÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÙ

changed by Sascha Silbe
}
{$X+}{$R-}{ $L-}{ $D-}{$Y-}{$X+}{$G+}
unit IniFile;

interface

uses DOS;

type FileStr    = {String [12]} String[128]; {Externer Typ}
     pOptRec = ^tOptRec;
     tOptRec = record               {Record fuer die Optionen}
                 Name    : String[20]; {Name, wenn ';' dann nur Kommentarzeile}
{$IfDef MKNL}
                 Value   : String; {Wert}
{$Else}
                 Value   : String[80]; {Wert}
{$EndIf}
                 Comment : String[100]; {Kommentar}
                 PrevOpt : pOptRec; {Zeiger auf vorherige Option}
                 NextOpt : pOptRec; {Zeiger auf naechste Option}
               end;
     pSecRec = ^tSecRec;
     tSecRec = record               {Record fuer die Sectionen}
                 Name : String[20]; {Name der Secion, immer grossbustaben}
                 Options : pOptRec; {Zeiger auf die Optionen}
                 PrevSec : pSecRec; {Zeiger auf vorherige Section}
                 NextSec : pSecRec; {Zeiger auf naechste Section}
               end;

type IniObj = object
                FileName   : FileStr;
                Sep        : Char;    {default = '='}
                                      {Achtung aenderungen werden nicht
                                       in der ini Datei gespeichert}
                CommentPos : byte;    {Wenn 0 dann deaktiviert, sonnst
                                       position an der die Kommentare
                                       ausgerichtet werden, natuerlich nur
                                       wenn der normal Eintrag nicht laenger
                                       ist. default = 0}
                NotFound   : String[20];  {String der zurueckgegeben wird wenn
                                       ein eintrag nicht gefunden wurde
                                       default = ''}
                f          : Text;
                IniTree    : pSecRec;  {Zeiger auf die 1. Section}
                AktSec     : pSecRec;  {nur intern benutzt}
                AktOpt     : pOptRec;  {nur intern benutzt}
                constructor Init (AFileName : FileStr);
                { Initalisiert die Ini Datei }
                destructor Done;
                { Schreibt die Eintraege und loeschen den Verkettung }
                procedure SetSeperator (ASep : Char);
                { Aendert den Seperator, default (=) }
                procedure SetNotFound  (ANotFound : String);
                { Aendert den NoFound String, default () }
                procedure SetCommentPos (ACommentPos : byte);
                { Aendert die CommentPos, default (0) }
                function ReadEntry ( Section : String;
                                     Option  : String ) : String;
                { Liefert den Wert des Eintrags }
                procedure WriteEntry ( Section : String;
                                       Option  : String;
                                       Value   : String;
                                       Comment : String);
                { Aendert/ Definiert eine Eintrag }
                procedure AddEntry ( Section : String;
                                     Option  : String;
                                     Value   : String;
                                     Comment : String);
                { Fuegt einen Eintrag ans Ende der Section an }
                procedure InsertEntry ( Section : String;
                                        Option  : String;
                                        Value   : String;
                                        Comment : String);
                { Fuegt einen Eintrag an der aktuellen Position ein }
                procedure DelEntry ( Section : String;
                                     Option  : String;
                                     DelSec  : Boolean );
                { Loescht eine Eintrag }
                { --------- Datenbank Routinen -------- }
                { Mit den Datenbank Functionen ist es moeglich
                  auch Eintraege zu Lesen deren Options Name
                  man nicht kennt. Wie kleine Datenbanken, wie
                  z.B. eine kleine Liste von PLZ und ihren Ortnamen
                  oder Telefonnummern ...
                  Die Functionen sind Sections orientiert geschrieben,
                  es ist dadurch moeglich Eine Datenbank und Programm
                  Einstellungen zu kombinieren.
                  Die Daten werden nicht Sortiert, neue Eintraege werden
                  einfach hinten angehaengt.}
                procedure SetSection (Section : String);
                { Setzt die Interen Variabel AktSec, existierd die Section
                  nicht wird eine neu Section erstellet.
                  Setzt AktOpt auf den ersten gueltigen Eintrag
                  ( wenn es einen gibt !!) }
                { DIESE PROCEDURE SOLLT ALS ERSTES AUFGREUFEN WERDEN}
                procedure ReSetSec;
                { Setzt AktOpt wirde auf den 1 Wert. }
                function GetSecNum (Section : String ) : integer;
                { gibt die Anzahl der Eintraegein einer Section }
                { dabei werden Kommentarzeilen ingnoriert. }
                { zurueck. Wenn Rueckgabewert 0 ist dann ist entweder kein }
                { Eintrag vorhanden oder die Section existiert nicht.}
                function SetNextOpt : boolean;
                { Setzt AktSec auf die naechste Option und gibt false
                  zurueck falls wenn das ende Erreicht ist.
                  Kommentarzeilen werden uebergangen}
                function SetPrevOpt : boolean;
                { Setzt AktSec auf die vorherige Option und gibt false
                  zurueck falls wenn der Anfang Erreicht ist.
                  Kommentarzeilen werden uebergangen}
                function ReSecEnName  : String;
                { Was so viel heisst wie ReadSectionEntryName }
                { gibt den Namen der Aktuellen Option zurueck }
                { Ist AktOpt = NIL wird der NotFound String zurueck gegeben }
                function ReSecEnValue : String;
                { gibt den Wert der Aktuellen Option zurueck }
                { Ist AktOpt = NIL wird der NotFound String zurueck gegeben }
                function SearchSecEntry (Name : String ) : String;
                { Sucht nach einen Eintrag und gibt seine Wert zurueck. }
                { AktOpt wird nicht geaendert !! }
                procedure WriteSecEntry (Name    : String;
                                         Value   : String;
                                         Comment : String);
                { Schreibz den Eintrag neu oder aendert den Wert, der
                  Aktuellen Section
                  AktOpt wird nicht geaendert !!
                  Achtung !! wurde keine Section gesetzt wird der Eintrag
                  in eine falsche oder in keine Section geschrieben !!}
                procedure AddSecEntry (Name    : String;
                                       Value   : String;
                                       Comment : String);
                { Haengt einen neuen Eintrag hinten an, der Aktuellen Section
                  AktOpt wird nicht geaendert !!
                  Achtung !! wurde keine Section gesetzt wird der Eintrag
                  in eine falsche oder in keine Section geschrieben !!}
                procedure InsertSecEntry (Name    : String;
                                          Value   : String;
                                          Comment : String);
                { Fuegt einen neuen Eintrag ein, der Aktuellen Section
                  AktOpt wird nicht geaendert !!
                  Achtung !! wurde keine Section gesetzt wird der Eintrag
                  in eine falsche oder in keine Section geschrieben !!}
                procedure DelSecEntry (Name : String);
                { Loescht eine Eintrag in der Aktuellen Section
                  AktOpt wird nicht geaendert !!
                  Achtung !! wurde keine Section gesetzt wird kein oder
                  ein falscher Eintrag geloescht }
                procedure DelCurEntry (DelSec  : Boolean);
                { Loescht eine Eintrag in der Aktuellen Section
                  AktOpt wird nicht geaendert !!
                  Achtung !! wurde keine Section gesetzt wird kein oder
                  ein falscher Eintrag geloescht }
                { ---------- interen Routinen --------- }
                function SearchSection (ASection : String;
                                        Last : Boolean ) : boolean;
                function SearchOption  (AOption : String;
                                        Last : Boolean ) : boolean;
                procedure ReadIni;
                procedure WriteIni;
                procedure DelIni;
                procedure ShowTree;
              end;

implementation
{****************************** externe Routinen ****************************}
{ Die hier externen Routinen stammen aus meiner Toolbox welche ich aus alle
  moeglichen Quellen zusammen gestellt habe. Hier die Routinen die fuer
  IniFile Unit noetig sind. Quellen : PRUSSG,SWAG,TOOLBOX,DOS,FIDO...        }

{Function FileExists(FileName: string; attr : Word) : Boolean;
var f: SearchRec;
begin
  findfirst(Filename, attr, f);
  if doserror = 0 then Fileexists := true else Fileexists := false;
end;}

Function FillStr (AStr : String; Len : byte; Ch : Char) : String;
begin
  if Length (AStr) > Len then Exit;
  while Length (AStr) < Len do AStr := AStr + Ch;
  FillStr := AStr;
end;
Function StrCut (AStr : String) : String;
begin
  while (Length(AStr) - 1 >= 0) AND
        (AStr [Length(AStr)] in [#32,#9]) DO
    AStr[0] := chr(Length(AStr) - 1);
  StrCut := AStr;
end;
Function CutStr (AStr : String) : String;
begin
  while (Length(AStr) - 1 >= 0) AND
        (AStr [1] in [#32,#9]) DO
    AStr := Copy (AStr,2,Length(AStr) - 1);
  CutStr := AStr;
end;

Function UpStr(S1:String) : String;
{Asm Code replaced by Sascha Silbe}
Var
  s:String;
  i:Byte;

Begin
s[0]:= S1[0];
For i:= 1 to Byte(s1[0]) do s[i]:= UpCase(s1[i]);
UpStr:= s;
End;

Function KillSpcs(s: String): String; {kill leading and trailing spaces}
 Begin
 While (s[1] in [' ', #9]) and (Length(s) > 0) do Delete(s, 1, 1);
 While (s[Length(s)] in [' ', #9]) and (Length(s) > 0) do Delete(s, Length(s), 1);
 KillSpcs := s;
 End;


{****************************** externe Routinen ****************************}
function NewSec : pSecRec;
var ASec : pSecRec;
begin
  New (ASec);
  ASec^.Name := '';
  ASec^.Options := NIL;
  ASec^.PrevSec := NIL;
  ASec^.NextSec := NIL;
  NewSec := ASec;
end;
function NewOpt : pOptRec;
var AOpt : pOptRec;
begin
  New (AOpt);
  AOpt^.Name := '';
  AOpt^.Value := '';
  AOpt^.Comment := '';
  AOpt^.PrevOpt := NIL;
  AOpt^.NextOpt := NIL;
  NewOpt := AOpt;
end;
{****************************************************************************}
constructor IniObj.Init(AFileName: FileStr);
begin
  FileName := AFileName;
  Assign (f,FileName);
  Sep := '=';
  NotFound := '';
  CommentPos := 0;
  IniTree := NIL;
  AktSec := NIL;
  AktOpt := NIL;
  ReadIni;
end;
destructor IniObj.Done;
begin
  WriteIni;
  DelIni;
end;
{****************************************************************************}

procedure IniObj.SetSeperator(ASep : Char);
begin
  Sep := ASep;
end;
procedure IniObj.SetNotFound(ANotFound: String);
begin
  NotFound := ANotFound;
end;
procedure   IniObj.SetCommentPos(ACommentPos: Byte);
begin
  CommentPos := ACommentPos;
end;
{****************************************************************************}

procedure IniObj.ReadIni;
var ASec : pSecRec;
    AOpt : pOptRec;
    X,Y  : byte;
    Str  : String;
begin
 {$I-} Reset (F); {$I+}
 If IOResult <> 0 then
   Begin
{    WriteLn('ReadIni: Couldn''t open file!');}
   Exit;
   end;
 while not Eof(F) do
  Begin
  ReadLn (f,Str);
  While (Str[Length(Str)] in [#13, #10]) do Dec(Str[0]);
  KillSpcs(Str);
  if Length (Str) > 0 then
   begin
   if Str[1] = '[' then
    begin
    ASec := NewSec;
    X := Pos (']',Str);
    if X > 1 then Dec (X,2) else Dec(x, 1);
    ASec^.Name := UpStr(KillSpcs(Copy (Str,2,X)));
    if IniTree = NIL then IniTree := ASec;
    if AktSec <> NIL then
     Begin
     AktSec^.NextSec := ASec;
     ASec^.PrevSec := AktSec;
     End;
    AktSec := ASec;
    end
   else
    begin
    X := Pos (Sep,Str); Y := Pos (' ;',Str);
    If (Str[1] = ';') then Y := 1;
    if (Y > 0) or (X > 0) then
     begin
     AOpt := NewOpt;
     if Str[1] = ';' then
      begin
      AOpt^.Name := ';'; {Kommentarzeile}
      AOpt^.Comment := Copy (Str,2,Length(Str)-1);
      end
     else
      begin
      If (x = 0) then
       begin
       AOpt^.Name := KillSpcs(Copy (Str, 1, y-1));
       AOpt^.Value := '';
       AOpt^.Comment := KillSpcs(Copy(Str, y+1, Length(str)-y));
       end
      else
       begin
       AOpt^.Name := KillSpcs(Copy (Str,1,X-1));
       if Y <> 0 then
        begin
        AOpt^.Value := KillSpcs(Copy (Str,X+1,Y-X-1));
        AOpt^.Comment := KillSpcs(Copy (Str,Y+1,Length(Str)-Y));
        end
       else
        begin
        AOpt^.Value := KillSpcs(Copy (Str,X+1,Length(Str)-X));
        AOpt^.Comment := '';
        end;
       end;
      end;
     end
    else
     begin
     AOpt^.Name := KillSpcs(Str);
     AOpt^.Value := '';
     AOpt^.Comment := '';
     end;
    if IniTree = NIL then
     begin
     IniTree := NewSec;
     AktSec := IniTree;
     end;
    if AktSec^.Options = NIL then AktSec^.Options := AOpt
    else AktOpt^.NextOpt := AOpt;
    AOpt^.PrevOpt := AktOpt;
    AktOpt := AOpt;
    end;
   end;
  end;
 Close (f);
end;
procedure IniObj.WriteIni;
const Comment : String = '';
      OptVal  : String = '';
begin
  if IniTree = Nil then Exit;
{  FileMode := 2;}
  {$I-} Rewrite (f); {$I+}
  If IOResult <> 0 then
    Begin
{    WriteLn('WriteIni: Couldn''t open file!');}
    Exit;
    End;
  AktSec := IniTree;
  AktOpt := AktSec^.Options;
  {$I-}
  while AktSec <> NIL do begin
    if AktSec^.Name <> '' then WriteLn (f,'['+UpStr(AktSec^.Name)+']');
    while AktOpt <> NIL do begin
      if AktOpt^.Name = ';' then WriteLn (f,AktOpt^.Name+AktOpt^.Comment)
      else begin
        OptVal :=  AktOpt^.Name+'='+ AktOpt^.Value;
        if AktOpt^.Comment <> '' then begin
          if CommentPos <> 0 then OptVal := FillStr (OptVal,CommentPos,' ');
          Comment := '  ;'+AktOpt^.Comment
        end;
        WriteLn (f, OptVal + Comment);
        Comment := ''; OptVal := '';
      end;
      AktOpt := AktOpt^.NextOpt;
    end;
    AktSec := AktSec^.NextSec;
    If AktSec <> Nil then AktOpt := AktSec^.Options;
  end;
  If IOResult <> 0 then
    Begin
{    WriteLn('WriteIni: Couldn''t write file!');}
    End;

  Close (f); {$I-}
  If IOResult <> 0 then
    Begin
{    WriteLn('WriteIni: Couldn''t close file!');}
    End;
end;
procedure IniObj.DelIni;
var ASec : pSecRec;
    AOpt : pOptRec;
    X    : byte;
    Str  : String;
begin
  if IniTree = Nil then Exit;
  AktSec := IniTree;
  AktOpt := AktSec^.Options;
  while AktSec <> NIL do begin
    ASec := AktSec^.NextSec;
    if AktSec <> NIl then Dispose (AktSec);
    while AktOpt <> NIL do begin
      AOpt := AktOpt^.NextOpt;
      if AktOpt <> NIL then Dispose (AktOpt);
      AktOpt := AOpt;
    end;
    AktSec := ASec;
    If AktSec <> Nil then AktOpt := AktSec^.Options;
  end;
end;
{****************************************************************************}
function IniObj.SearchSection (ASection : String;
                               Last     : boolean ) : boolean;
{ Suchen nach der Section. Ist Last auf true wird AktSec auf die Section
  vor der gesuchten gesetzt, ist Last auf false wird AktSec auf die
  gesuchte Section gesetzt, oder bei nicht finden auf die letzte der
  Verkettung. Wird eine Section gefunde ist der Rueckgabewert der Function
  true, ansonsten false.
  Zur beschleunigung der Suche : ist AktSec schon das gesuchte wird nicht
  gesucht, wie z.B. durch WriteSecEntry }
var Found : boolean;
    ASec  : pSecRec;
begin
  if IniTree = Nil then begin
    SearchSection := false;
    Exit;
  end;
  found := false;
  ASection := UpStr (ASection);
  ASec := NIL;
  If AktSec = NIL then AktSec := IniTree
  Else
    if (AktSec^.Name = ASection) and (not Last) then Found := true
    else AktSec := IniTree;
  while (AktSec <> NIL) and (not Found) do begin
    if ASection = AktSec^.Name then Found := true
    Else
     begin
      ASec := AktSec;
      AktSec := AktSec^.NextSec;
     end;
  end;
  if Last or (AktSec = NIL) then AktSec := ASec;
  SearchSection := found;
end;
function IniObj.SearchOption (AOption : String;
                              Last    : boolean) : boolean;
{ Suchen nach der Option. Ist Last auf true wird AktOpt auf die Option
  vor der gesuchten gesetzt, ist Last auf false wird AktOpt auf die
  gesuchte Option gesetzt, oder bei nicht finden auf die letzte der
  Verkettung, Nur wenn gar keine Verkettung unter dieser Section
  existiert wird AktOpt auf NIL gesetzt. Aber dann ist auch der
  rueckgabewert der Function false
  Zur beschleunigung der Suche : ist AktOpt schon das gesuchte wird nicht
  gesucht}

var Found : boolean;
    AOpt  : pOptRec;
begin
  if IniTree = Nil then begin
    SearchOption := false;
    Exit;
  end;
  found := false;
  AOpt := NIL;
  if (UpStr(AktOpt^.Name) = UpStr(AOption)) and (not Last) then Found := true
  else AktOpt := AktSec^.Options;
  while (AktOpt <> NIL) and (not Found) do begin
    if UpStr(AOption) = UpStr(AktOpt^.Name) then Found := true;
    if not Found then begin
      AOpt :=  AktOpt;
      AktOpt := AktOpt^.NextOpt;
    end;
  end;
  If Last or (AktOpt = NIL) then AktOpt := AOpt;
  SearchOption := found;
end;
{****************************************************************************}
function IniObj.ReadEntry ( Section : String; Option  : String ) : String;
Var Value : String;
begin
  if SearchSection (Section,false) then
    if SearchOption (Option,false) then
     Value := AktOpt^.Value
    else Value := NotFound;
  ReadEntry := Value;
end;
procedure IniObj.WriteEntry(Section, Option, Value, Comment: String);
begin
  if SearchSection (Section,false) then
    if SearchOption (Option,false) then
     begin
       AktOpt^.Value := Value;
       if Comment <> '' then AktOpt^.Comment := Comment;
     end else
     begin
       AktOpt^.NextOpt := NewOpt;
       AktOpt := AktOpt^.NextOpt;
       AktOpt^.Name := Option;
       AktOpt^.Value := Value;
       AktOpt^.Comment := Comment;
     end
  else begin
    if IniTree = NIL then begin
      IniTree := NewSec;
      AktSec := IniTree;
    end else begin
      AktSec^.NextSec := NewSec;
      AktSec := AktSec^.NextSec;
    end;
    AktSec^.Name := UpStr(Section);
    AktSec^.Options := NewOpt;
    AktOpt := AktSec^.Options;
    AktOpt^.Name := Option;
    AktOpt^.Value := Value;
    AktOpt^.Comment := Comment;
  end;
end;
procedure IniObj.AddEntry(Section, Option, Value, Comment: String);
Var
  AOpt : pOptRec;
begin
  if SearchSection (Section,false) then
     begin
       AOpt := AktOpt;
       While (AOpt^.NextOpt <> Nil) do AOpt := AOpt^.NextOpt;
       AOpt^.NextOpt := NewOpt;
       AOpt^.PrevOpt := AktOpt;
       AOpt := AOpt^.NextOpt;
       AOpt^.Name := Option;
       AOpt^.Value := Value;
       AOpt^.Comment := Comment;
     end
  else begin
    if IniTree = NIL then begin
      IniTree := NewSec;
      AktSec := IniTree;
    end else begin
      AktSec^.NextSec := NewSec;
      AktSec^.NextSec^.PrevSec := AktSec;
      AktSec := AktSec^.NextSec;
    end;
    AktSec^.Name := UpStr(Section);
    AktSec^.Options := NewOpt;
    AktOpt := AktSec^.Options;
    AktOpt^.Name := Option;
    AktOpt^.Value := Value;
    AktOpt^.Comment := Comment;
  end;
end;
procedure IniObj.InsertEntry(Section, Option, Value, Comment: String);
Var
  AOpt : pOptRec;
begin
  if SearchSection (Section,false) then
     begin
       AOpt := AktOpt^.NextOpt;
       AktOpt^.NextOpt := NewOpt;
       AktOpt^.NextOpt^.PrevOpt := AktOpt;
       AktOpt^.NextOpt^.NextOpt := AOpt;
       AOpt := AktOpt^.NextOpt;
       AOpt^.Name := Option;
       AOpt^.Value := Value;
       AOpt^.Comment := Comment;
     end
  else begin
    if IniTree = NIL then begin
      IniTree := NewSec;
      AktSec := IniTree;
    end else begin
      AktSec^.NextSec := NewSec;
      AktSec^.NextSec^.PrevSec := AktSec;
      AktSec := AktSec^.NextSec;
    end;
    AktSec^.Name := UpStr(Section);
    AktSec^.Options := NewOpt;
    AktOpt := AktSec^.Options;
    AktOpt^.Name := Option;
    AktOpt^.Value := Value;
    AktOpt^.Comment := Comment;
  end;
end;
procedure IniObj.DelEntry ( Section : String;
                            Option  : String;
                            DelSec  : Boolean );
var AOpt : pOptRec;
    ASec : pSecRec;
begin
  if SearchSection (Section,false) then
    if SearchOption (Option,false) then begin
      AOpt := AktOpt;
      SearchOption (Option,true);
      if AktOpt <> NIL then
        Begin
        AktOpt^.NextOpt := AOpt^.NextOpt;
        AOpt^.NextOpt^.PrevOpt := AktOpt;
        End
      else
        Begin
        AktSec^.Options := AOpt^.NextOpt;
        AOpt^.NextOpt^.PrevOpt := Nil;
        End;
      if AOpt <> NIL then Dispose (AOpt);
      if (AktSec^.Options = NIL) and DelSec then begin
        ASec := AktSec;
        SearchSection (Section,true);
        if AktSec <> NIL then
          Begin
          AktSec^.NextSec := ASec^.NextSec;
          ASec^.NextSec^.PrevSec := AktSec;
          End
        else
          Begin
          IniTree := ASec^.NextSec;
          ASec^.NextSec^.PrevSec := Nil;
          End;
        if ASec <> NIL then Dispose (ASec);
      end;
    end;
end;
{****************************************************************************}
procedure IniObj.ShowTree;
const Comment : String = '';
      OptVal  : String = '';
begin
  if IniTree = Nil then Exit;
  AktSec := IniTree;
  AktOpt := AktSec^.Options;
  while AktSec <> NIL do begin
    if AktSec^.Name <> '' then WriteLn ('['+AktSec^.Name+']');
    while AktOpt <> NIL do begin
      if AktOpt^.Name = ';' then WriteLn (AktOpt^.Name+AktOpt^.Comment)
      else begin
        OptVal :=  AktOpt^.Name+'='+ AktOpt^.Value;
        if AktOpt^.Comment <> '' then begin
          if CommentPos <> 0 then OptVal := FillStr (OptVal,CommentPos,' ');
          Comment := '  ;'+AktOpt^.Comment
        end;
        WriteLn (OptVal + Comment);
        Comment := ''; OptVal := '';
      end;
      AktOpt := AktOpt^.NextOpt;
    end;
    AktSec := AktSec^.NextSec;
    If (AktSec <> Nil) then AktOpt := AktSec^.Options;
  end;
end;

{****************************************************************************}
function IniObj.SetPrevOpt : boolean;

begin
  if AktOpt^.PrevOpt <> Nil then begin
    repeat AktOpt := AktOpt^.PrevOpt
    until (AktOpt^.Name <> ';') or (AktOpt^.PrevOpt = Nil);
    if (AktOpt^.PrevOpt = Nil) and ( AktOpt^.Name = ';')
     then SetPrevOpt := false else SetPrevOpt := true;
  end else SetPrevOpt := false;
end;
function IniObj.SetNextOpt : boolean;

begin
  if AktOpt^.NextOpt <> Nil then begin
    repeat AktOpt := AktOpt^.NextOpt
    until (AktOpt^.Name <> ';') or (AktOpt^.NextOpt = Nil);
    if (AktOpt^.NextOpt = Nil) and ( AktOpt^.Name = ';')
     then SetNextOpt := false else SetNextOpt := true;
  end else SetNextOpt := false;
end;
function IniObj.GetSecNum (Section : String ) : integer;
var Num  : Integer;
    AOpt : pOptRec;
begin
  Num := 0;
  AOpt := AktOpt;
  if SearchSection (Section,false) then begin
    AktOpt := AktSec^.Options;
    while AktOpt <> NIL do begin
      if AktOpt^.Name[1] <> ';' then Inc (Num);
      if not SetNextOpt then AktOpt := NIL;
    end;
  end;
  AktOpt := AOpt;
  GetSecNum := Num;
end;
procedure IniObj.SetSection (Section : String);
begin
  if not SearchSection (Section,false) then begin
    WriteEntry (Section,';','','');
  end;
  ReSetSec;
end;
procedure IniObj.ReSetSec;
begin
  AktOpt := AktSec^.Options;
  if AktOpt^.Name = ';' then SetNextOpt;
end;
function IniObj.ReSecEnName  : String;
begin
  if AktOpt = NIL then begin
    ReSecEnName := NotFound;
    Exit;
  end;
  ReSecEnName := AktOpt^.Name;
end;

function IniObj.ReSecEnValue : String;
begin
  if AktOpt = NIL then begin
    ReSecEnValue := NotFound;
    Exit;
  end;
  ReSecEnValue := AktOpt^.Value;
end;
function  IniObj.SearchSecEntry (Name : String ) : String;
var AOpt : pOptRec;
begin
  if AktSec = NIL then begin
    SearchSecEntry := NotFound;
    Exit;
  end;
  AOpt := AktOpt;
  SearchSecEntry := ReadEntry (AktSec^.Name,Name);
  AktOpt := AOpt;
end;
procedure IniObj.WriteSecEntry (Name    : String;
                                Value   : String;
                                Comment : String);
var AOpt : pOptRec;
begin
  if AktSec = NIL then Exit;
  AOpt := AktOpt;
  WriteEntry (AktSec^.Name,Name,Value,'');
  AktOpt := AOpt;
end;
procedure IniObj.AddSecEntry (Name    : String;
                              Value   : String;
                              Comment : String);
var AOpt : pOptRec;
begin
  if AktSec = NIL then Exit;
  AOpt := AktOpt;
  AddEntry (AktSec^.Name,Name,Value,'');
  AktOpt := AOpt;
end;
procedure IniObj.InsertSecEntry (Name    : String;
                                 Value   : String;
                                 Comment : String);
var AOpt : pOptRec;
begin
  if AktSec = NIL then Exit;
  AOpt := AktOpt;
  InsertEntry (AktSec^.Name,Name,Value,'');
  AktOpt := AOpt;
end;
procedure IniObj.DelSecEntry (Name  : String);
var AOpt : pOptRec;
begin
  if AktSec = NIL then Exit;
  AOpt := AktOpt;
  DelEntry (AktSec^.Name,Name,false);
  AktOpt := AOpt;
end;
procedure IniObj.DelCurEntry(DelSec: Boolean);
var AOpt : pOptRec;
    ASec : pSecRec;
begin
If (AktOpt = Nil) then Exit
Else If (AktOpt = AktSec^.Options) Then
  Begin
  AktSec^.Options := AktOpt^.NextOpt;
  AktOpt^.NextOpt^.PrevOpt := Nil;
  End
Else If (AktOpt^.NextOpt = Nil) then
  Begin
  AktOpt^.PrevOpt^.NextOpt := Nil;
  End
Else
  Begin
  AktOpt^.PrevOpt^.NextOpt := AktOpt^.NextOpt;
  AktOpt^.NextOpt^.PrevOpt := AktOpt^.PrevOpt;
  End;
Dispose(AktOpt);
if (AktSec^.Options = NIL) and DelSec then
  Begin
  If (AktSec^.PrevSec = Nil) then
    Begin
    If (AktSec^.NextSec <> Nil) then
      Begin
      AktSec^.NextSec^.PrevSec := Nil;
      IniTree := AktSec^.NextSec;
      End
    Else IniTree := Nil;
    End
  Else
    Begin
    AktSec^.PrevSec^.NextSec := AktSec^.NextSec;
    AktSec^.NextSec^.PrevSec := AktSec^.PrevSec;
    End;
  Dispose(AktSec);
  End;
end;

{****************************************************************************}
end.
{ Externale Prceduren,Functionen & Typen
  FileStr (T) : String Type fuer Dateiname. (String[12])
  UpStr   (F) : wandelt alle Buchstaben in Grossbuchstaben.
  CutStr  (F) : Schneidet vorstehende Leerzeichen und Tabs ab.
  StrCut  (F) : Schneidet nachstehende Leerzeichen und Tabs ab.
  FillStr (F) : Fuellt eine String mit eine Zeichen auf eine bestimmte Laenge
  FileExists (F) : Prueft ob eine Datei Existiert (siehe Online Hilfe) mit
                   Attribut ueberpruefung
}
{05.04.96 : Begin mit der Grundstruktur, Aufbau eines Objectes, Bug Fixes
 06.04.96 : BugFixes, Implementierung Comments,SetCommentPos,NotFound,
            DelEntry, ausgiebiger Test der Unit
 07.04.96 : DataBase Routinen (Tested)

Sascha Silbe:
 12.07.98 : fixed some bugs
}
