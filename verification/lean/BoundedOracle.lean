import RefinedProtocol

namespace LinkChat

/-!
  Executable bounded oracle for the Rust conformance harness.

  `refinedStep` in the formal model is intentionally noncomputable because
  it uses a classical proposition decider. This file therefore gives an
  executable Boolean presentation of the same six-field `refinedValid`
  predicate and `refinedCommit` transition for a finite test corpus. The
  Rust harness compares only the resulting finite projection summaries.
-/

inductive OracleEndpoint where
  | alice
  | bob
  deriving Repr, DecidableEq

structure OraclePackage where
  keyId : Nat
  mailboxToken : Nat
  deriving Repr, DecidableEq

structure OracleState where
  sessionId : Nat
  turn : Nat
  alice : OraclePackage
  bob : OraclePackage
  consumedMessageIds : List Nat
  deriving Repr, DecidableEq

structure OracleMessage where
  sessionId : Nat
  turn : Nat
  direction : OracleEndpoint
  messageId : Nat
  receiverKeyId : Nat
  receiverToken : Nat
  deriving Repr, DecidableEq

def oracleLeader (turn : Nat) : OracleEndpoint :=
  if turn % 2 = 0 then .alice else .bob

def oracleReceiver (s : OracleState) (endpoint : OracleEndpoint) : OraclePackage :=
  match endpoint with
  | .alice => s.alice
  | .bob => s.bob

def oracleOther : OracleEndpoint → OracleEndpoint
  | .alice => .bob
  | .bob => .alice

def oracleValid (s : OracleState) (m : OracleMessage) : Bool :=
  m.sessionId == s.sessionId &&
  m.turn == s.turn &&
  m.direction == oracleLeader s.turn &&
  m.receiverKeyId == (oracleReceiver s (oracleOther m.direction)).keyId &&
  m.receiverToken == (oracleReceiver s (oracleOther m.direction)).mailboxToken &&
  !(s.consumedMessageIds.contains m.messageId)

def oracleCommit (s : OracleState) (m : OracleMessage) (next : OraclePackage) : OracleState :=
  match m.direction with
  | .alice =>
      { s with
        turn := s.turn + 1
        bob := next
        consumedMessageIds := m.messageId :: s.consumedMessageIds }
  | .bob =>
      { s with
        turn := s.turn + 1
        alice := next
        consumedMessageIds := m.messageId :: s.consumedMessageIds }

def oracleStep (s : OracleState) (m : OracleMessage) (next : OraclePackage) : OracleState :=
  if oracleValid s m then oracleCommit s m next else s

def base : OracleState :=
  { sessionId := 9
    turn := 0
    alice := { keyId := 10, mailboxToken := 11 }
    bob := { keyId := 20, mailboxToken := 22 }
    consumedMessageIds := [] }

def validAlice : OracleMessage :=
  { sessionId := 9
    turn := 0
    direction := .alice
    messageId := 7
    receiverKeyId := 20
    receiverToken := 22 }

def wrongSession : OracleMessage :=
  { validAlice with sessionId := 99 }

def wrongKey : OracleMessage :=
  { validAlice with receiverKeyId := 999 }

def wrongToken : OracleMessage :=
  { validAlice with receiverToken := 99 }

def future : OracleMessage :=
  { validAlice with turn := 2 }

def validBob : OracleMessage :=
  { sessionId := 9
    turn := 1
    direction := .bob
    messageId := 8
    receiverKeyId := 10
    receiverToken := 11 }

def nextBob : OraclePackage := { keyId := 21, mailboxToken := 23 }
def nextAlice : OraclePackage := { keyId := 12, mailboxToken := 24 }

def joinConsumed : List Nat → String
  | [] => "-"
  | x :: xs =>
      xs.foldl (fun output value => output ++ "," ++ toString value) (toString x)

def summary (label : String) (before : OracleState) (message : OracleMessage)
    (next : OraclePackage) : String :=
  let accepted := oracleValid before message
  let after := oracleStep before message next
  let alice := after.alice
  let bob := after.bob
  s!"{label}|{if accepted then 1 else 0}|{after.turn}|{alice.keyId}|{bob.keyId}|{alice.mailboxToken}|{bob.mailboxToken}|{joinConsumed after.consumedMessageIds}"

def runOracle : IO Unit := do
  let afterAlice := oracleStep base validAlice nextBob
  let cases := [
    summary "base-valid" base validAlice nextBob,
    summary "base-wrong-session" base wrongSession nextBob,
    summary "base-wrong-key" base wrongKey nextBob,
    summary "base-wrong-token" base wrongToken nextBob,
    summary "base-future" base future nextBob,
    summary "after-alice-replay" afterAlice validAlice nextAlice,
    summary "after-alice-valid-bob" afterAlice validBob nextAlice
  ]
  for line in cases do
    IO.println line

end LinkChat

def main : IO Unit := LinkChat.runOracle
