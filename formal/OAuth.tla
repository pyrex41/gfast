------------------------------ MODULE OAuth ------------------------------
EXTENDS Naturals, FiniteSets
CONSTANTS Codes, Refreshes, Actors, Capacity, None
Tokens == Codes \cup Refreshes
VARIABLES live, unused, pending, consumed, granted
vars == <<live, unused, pending, consumed, granted>>

Init == /\ live = {}
        /\ unused = Tokens
        /\ pending = [a \in Actors |-> None]
        /\ consumed = [t \in Tokens |-> 0]
        /\ granted = [t \in Tokens |-> 0]

Room(t) == IF t \in Codes THEN Cardinality(live \cap Codes) < Capacity
           ELSE Cardinality(live \cap Refreshes) < Capacity

\* Issuance is atomic under the store mutex. IDs are never reused.
Issue(t) == /\ t \in unused /\ Room(t)
            /\ live' = live \cup {t}
            /\ unused' = unused \ {t}
            /\ UNCHANGED <<pending, consumed, granted>>

\* Represents a matching client/redirect and non-expired token. Invalid
\* credentials are a stuttering step (they cannot consume or issue).
Consume(a, t) == /\ pending[a] = None /\ t \in live
                 /\ live' = live \ {t}
                 /\ pending' = [pending EXCEPT ![a] = t]
                 /\ consumed' = [consumed EXCEPT ![t] = @ + 1]
                 /\ UNCHANGED <<unused, granted>>

\* Time is abstracted to nondeterministic expiration before consumption.
Expire(t) == /\ t \in live
             /\ live' = live \ {t}
             /\ UNCHANGED <<unused, pending, consumed, granted>>

\* PKCE/scope rejection, issuance failure, or store saturation burns the
\* consumed token. It does not resurrect it or produce credentials.
Reject(a) == /\ pending[a] # None
             /\ pending' = [pending EXCEPT ![a] = None]
             /\ UNCHANGED <<live, unused, consumed, granted>>

Grant(a, replacement) ==
    /\ pending[a] # None
    /\ replacement \in (unused \cap Refreshes) /\ Room(replacement)
    /\ live' = live \cup {replacement}
    /\ unused' = unused \ {replacement}
    /\ granted' = [granted EXCEPT ![pending[a]] = @ + 1]
    /\ pending' = [pending EXCEPT ![a] = None]
    /\ UNCHANGED consumed

Next == \/ \E t \in Tokens : Issue(t) \/ Expire(t)
        \/ \E a \in Actors, t \in Tokens : Consume(a, t)
        \/ \E a \in Actors : Reject(a)
        \/ \E a \in Actors, r \in Refreshes : Grant(a, r)

TypeOK == /\ live \subseteq Tokens /\ unused \subseteq Tokens
          /\ pending \in [Actors -> Tokens \cup {None}]
          /\ consumed \in [Tokens -> Nat] /\ granted \in [Tokens -> Nat]
AtMostOnce == \A t \in Tokens : consumed[t] <= 1 /\ granted[t] <= 1
NoUnconsumedGrant == \A t \in Tokens : granted[t] <= consumed[t]
BoundedStores == /\ Cardinality(live \cap Codes) <= Capacity
                /\ Cardinality(live \cap Refreshes) <= Capacity
NoResurrection == \A t \in Tokens : consumed[t] > 0 => t \notin live
Spec == Init /\ [][Next]_vars
=============================================================================
