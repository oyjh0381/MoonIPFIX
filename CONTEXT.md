# MoonIPFIX

MoonIPFIX defines the domain language for consuming exporter-produced, template-driven IPFIX flow telemetry while preserving session scope, field meaning, and decoding evidence.

## Language

**IPFIX Message**:
A version 10 protocol message exported as one length-delimited unit containing a header and zero or more Sets.
_Avoid_: Packet, capture, NetFlow message

**Exporting Process**:
The protocol participant that creates IPFIX Messages from metered flow information.
_Avoid_: Packet source, client, probe process

**Collecting Process**:
The protocol participant that receives IPFIX Messages and interprets Data Records using session-scoped Templates.
_Avoid_: Packet sniffer, database, server socket

**Transport Session**:
The RFC-defined association within which Template identity and lifetime are scoped between an Exporting Process and a Collecting Process.
_Avoid_: File, message, Observation Domain

**Session Key**:
An opaque caller-supplied identity representing one Transport Session to MoonIPFIX.
_Avoid_: Source address, connection string, Observation Domain ID

**Observation Domain**:
The largest set of Observation Points for which an Exporting Process can provide Observation Point identifiers without ambiguity, identified within an IPFIX Message by its Observation Domain ID.
_Avoid_: Transport Session, exporter, network

**Set**:
A length-delimited collection inside an IPFIX Message whose Set ID identifies Template, Options Template, or Data content.
_Avoid_: Message, record batch, packet

**Template**:
A session- and Observation-Domain-scoped ordered definition of the Information Elements encoded by Data Records under one Template ID.
_Avoid_: Schema file, JSON schema, global record type

**Options Template**:
A Template that distinguishes Scope Fields from the option fields describing those scopes.
_Avoid_: Configuration, ordinary Template, CLI option

**Template Withdrawal**:
An IPFIX record that ends the applicability of one or more Templates in their Transport Session and Observation Domain scope.
_Avoid_: Session reset, expiry guess, Data Record deletion

**Data Set**:
A Set with an ID in the Data Set range whose payload contains Data Records governed by the Template with the same ID.
_Avoid_: Dataset, capture, Template Set

**Data Record**:
One ordered sequence of field values decoded according to a specific Template.
_Avoid_: Packet, row without Template identity, Message

**Field Specifier**:
The Template entry that identifies an Information Element, its encoded length, and any Enterprise Number.
_Avoid_: Field value, registry entry, column name

**Information Element**:
A named, typed unit of flow information identified by an element ID and, when enterprise-specific, a Private Enterprise Number.
_Avoid_: JSON property, arbitrary tag, Field Specifier

**Enterprise Information Element**:
An Information Element whose identity is scoped by a Private Enterprise Number rather than only the IANA element ID space.
_Avoid_: Unknown field, vendor string, standard Information Element

**Registry Snapshot**:
A dated, reproducible capture of IANA IPFIX Information Element metadata used to interpret standard field identities and data types.
_Avoid_: Live registry, runtime download, Template Store

**Template Store**:
The current set of applicable Templates indexed by Session Key, Observation Domain ID, and Template ID.
_Avoid_: Registry Snapshot, database, global Template map

**Sequence Gap**:
A discontinuity between expected and observed IPFIX Sequence Numbers, evaluated with the protocol's Data Record counting rules.
_Avoid_: Missing byte, parse error, message index gap

**Diagnostic**:
A structured observation about decoding validity, compatibility, sequence continuity, or enforced limits, anchored to an input offset and protocol context when available.
_Avoid_: Console log, guessed recovery, exception text

**Need More Data**:
A non-error decoding result stating that the current chunk ends before the declared IPFIX Message can be completed.
_Avoid_: Truncation error, retry, invalid Message

**Output Record**:
A schema-versioned JSONL object representing a decoded protocol event, record, Template change, statistic, or Diagnostic.
_Avoid_: Data Record, console line, unversioned JSON
