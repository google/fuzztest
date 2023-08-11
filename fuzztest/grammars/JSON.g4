// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Based on JSON spec at http://json.org.
//
// With some simplifications:
// - Restricted character set (e.g., no unicode chars).
// - No escape sequences (e.g., \n, \t, \uff01, etc.)

grammar JSON_GRAMMAR;

json : element ;

value : object | array | STRING | NUMBER | 'true' | 'false' | 'null' ;

object : '{' '}' | '{' members '}' ;

members : member | member ',' members ;

member : STRING ':' element ;

array : '[' ']' | '[' elements ']' ;

elements : element (',' element)* ;

element : value ;

STRING : '"' CHARACTER* '"' ;

CHARACTER : [a-zA-Z0-9_];

NUMBER : INTEGER FRACTION? EXPONENT? ;

INTEGER : DIGIT | ONETONINE DIGITS | '-' DIGIT | '-' ONETONINE DIGITS ;

DIGITS : DIGIT+ ;

DIGIT : '0' | ONETONINE ;

ONETONINE : [1-9] ;

FRACTION : '.' DIGITS ;

EXPONENT : [Ee] SIGN? ONETONINE DIGIT?;

SIGN : '+' | '-' ;

WSPACE : [ \t\n\r]+ -> skip;
