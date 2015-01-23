# Cloning Mosh

What's novel about mosh?

1.  State Synchronisation Protocol

     *  low-latency object synchronisation (e.g. treat keyboard input and screen
        display as objects)
     *  client roaming
     *  cope well with lossy network paths
     *  survive client suspend/resume (server treats it as temporary network
        loss)
     *  **potentially useful for other low-latency communication applications**

2.  Predictive Local Echo

     *  probably not more widely applicable


## Sources

 *  [Mosh homepage][]
 *  [Mosh paper][]
 *  [Mosh draft paper][]
 *  [presentation][] at the 2012 USENIX Annual Technical Conference,
    including [slides][]
 *  Mosh source code as of [version 1.2.4][]

[Mosh homepage]: https://mosh.mit.edu/
[Mosh paper]: https://mosh.mit.edu/mosh-paper.pdf
[Mosh draft paper]: https://mosh.mit.edu/mosh-paper-draft.pdf
[presentation]: https://www.usenix.org/conference/atc12/technical-sessions/presentation/winstein
[slides]: https://www.usenix.org/sites/default/files/conference/protected-files/winstein_atc12_slides.pdf
[version 1.2.4]: https://github.com/keithw/mosh/tree/688bf21b079c7adf30b87e0f4d8b75e709d5d161


## Datagram Layer

(Mosh paper §2.2 p2; draft paper §2.3 p3.)

Data travels over UDP.

Client may roam; server may not.  Server sends to the address+port from which it
received the most recent genuine packet.
Server port is specified by server while bootstrapping.

Estimating round-trip time and its variation: use modified version of
[RFC 6298][]:

>    *  RTT --- round-trip time
>    *  SRTT --- smoothed round-trip time
>    *  RTTVAR --- round-trip time variation
>    *  RTO --- retransmission timeout
>    *  G --- clock granularity
>    *  K --- 4
>    *  alpha --- 1/8
>    *  beta --- 1/4
>    *  RTO~max~ --- 60s
>
>   Basic algorithm:
>
>   1.  RTT~0~ = 1s
>
>   2.  On initial RTT measurement R (or optionally after too many
>       retransmission timeouts):
>        *  new SRTT := R
>        *  new RTTVAR := R / 2
>
>   3.  On subsequent RTT measurements R':
>        *  new RTTVAR := (1 - beta) * RTTVAR + beta * |SRTT - R'|
>        *  new SRTT := (1 - alpha) * SRTT + alpha * R'
>
>   4.  Recompute RTO after RTT measurements:
>        *  new RTO := mid (50ms, SRTT + max (G, K * RTTVAR), RTO~max~)
>
>   5.  Recompute RTO after retransmission timeout:
>        *  new RTO := min (2 * RTO, RTO~max~)

[RFC 6298]: https://tools.ietf.org/html/rfc6298


## Cryptographic Module

(Draft paper §2.2 p3.)

AES-128 in [OCB mode][] (version 3; see [src/crypto/ocb.cc:2][]), described in
[RFC 7253].

Packet format (see [Packet::tostring()][]):

1.  64 bit nonce (big-endian, network byte order; see [Nonce::Nonce()][])
     *  high bit is 1 for server to client, 0 for client to server
     *  lower 63 bits are a counter, starting at 0 (see next\_seq in
        [Connection::new_packet()][] and [Connection::Connection()][])
     *  nonce as fed to encryption routines is 96 bits long, padded with 0s at
        the start
2.  encrypted payload
     *  lower 16 bits of local ms timer (big-endian, network byte order)
     *  lower 16 bits of last timestamp received (big-endian, network byte
        order), adjusted for how long we've held it;
        \~0 if we have not received a new timestamp within the past second (see
        [Connection::new_packet()])
     *  payload from transport layer

There is no associated data (which OCB authenticates but does not encrypt),
apart from the nonce.

Encryption parameters (see [Session::Session()][] and [ae_init()][]):

 *  key length = 128 bits
 *  nonce length = 96 bits
 *  tag length = 128 bits

Die after sending 2^47^ blocks (not packets) in either direction, to preserve
OCB's privacy and authenticity properties.

[OCB mode]: http://en.wikipedia.org/wiki/OCB_mode
[src/crypto/ocb.cc:2]: https://github.com/keithw/mosh/blob/688bf21b079c7adf30b87e0f4d8b75e709d5d161/src/crypto/ocb.cc#L2
[Packet::tostring()]: https://github.com/keithw/mosh/blob/688bf21b079c7adf30b87e0f4d8b75e709d5d161/src/network/network.cc#L86
[Connection::new_packet()]: https://github.com/keithw/mosh/blob/688bf21b079c7adf30b87e0f4d8b75e709d5d161/src/network/network.cc#L99
[Connection::Connection()]: https://github.com/keithw/mosh/blob/688bf21b079c7adf30b87e0f4d8b75e709d5d161/src/network/network.cc#L202
[Nonce::Nonce()]: https://github.com/keithw/mosh/blob/688bf21b079c7adf30b87e0f4d8b75e709d5d161/src/crypto/crypto.cc#L167
[Session::Session()]: https://github.com/keithw/mosh/blob/688bf21b079c7adf30b87e0f4d8b75e709d5d161/src/crypto/crypto.cc#L148
[ae_init()]: https://github.com/keithw/mosh/blob/688bf21b079c7adf30b87e0f4d8b75e709d5d161/src/crypto/ocb.cc#L642
[RFC 7253]: http://www.rfc-editor.org/rfc/rfc7253.txt


## Transport Layer

(Mosh paper §2.3 p3; draft paper §2.4 p4.)

Transports diffs from specified states: messages are idempotent.

Diff is encapsulated in an `Instruction` defined using protocol buffers (use
[hprotoc][] to generate Haskell code), compressed using zlib (see
[src/network/compressor.cc][]) and
then fragmented manually to ensure each UDP packet is sent as a single IP packet
and not further fragmented en route.
No attempt is made to make individual packets meaningful on their own: packets
are split into MTU-sized chunks.
See [TransportSender<>::send_in_fragments()][] and
[Fragmenter::make_fragments()].

Format of a fragment (see [Fragment::tostring()][] and [class Fragment][]):

 *  64 bit instruction id, in network byte order
 *  16 bit fragment id, in network byte order
     *  high bit is set iff this is the final fragment of the instruction
     *  lower 15 bits are the fragment number (first fragment is 0)
 *  remainder is a chunk of compressed payload

Fragments are then encrypted as above before being sent as a UDP packet.

Not immediately clear how the MTU is detected (MTU of last resort is 500 bytes).

[src/network/compressor.cc]: https://github.com/keithw/mosh/blob/688bf21b079c7adf30b87e0f4d8b75e709d5d161/src/network/compressor.cc
[TransportSender<>::send_in_fragments()]: https://github.com/keithw/mosh/blob/688bf21b079c7adf30b87e0f4d8b75e709d5d161/src/network/transportsender.cc#L306
[Fragmenter::make_fragments()]: https://github.com/keithw/mosh/blob/688bf21b079c7adf30b87e0f4d8b75e709d5d161/src/network/transportfragment.cc#L157
[Fragment::tostring()]: https://github.com/keithw/mosh/blob/688bf21b079c7adf30b87e0f4d8b75e709d5d161/src/network/transportfragment.cc#L56
[class Fragment]: https://github.com/keithw/mosh/blob/688bf21b079c7adf30b87e0f4d8b75e709d5d161/src/network/transportfragment.h#L49
[hprotoc]: http://hackage.haskell.org/package/hprotoc


## Prospective resend optimisation

See [TransportSender<>::attempt_prospective_resend_optimization()][].

[TransportSender<>::attempt_prospective_resend_optimization()]: https://github.com/keithw/mosh/blob/688bf21b079c7adf30b87e0f4d8b75e709d5d161/src/network/transportsender.cc#L382


## Diff of screen display

See [Complete::diff_from()][].

[Complete::diff_from()]: https://github.com/keithw/mosh/blob/688bf21b079c7adf30b87e0f4d8b75e709d5d161/src/statesync/completeterminal.cc#L72


## Diff of keyboard input

See [UserStream::diff_from()][].

[UserStream::diff_from()]: https://github.com/keithw/mosh/blob/688bf21b079c7adf30b87e0f4d8b75e709d5d161/src/statesync/user.cc#L61


## Server bootstrapping output

Over initial e.g. SSH connection (initial blank line, then):

    MOSH CONNECT 60002 JE3b4xDf9o6S3RHtlP3uvw

    mosh-server (mosh 1.2.4a)
    Copyright 2012 Keith Winstein <mosh-devel@mit.edu>
    License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
    This is free software: you are free to change and redistribute it.
    There is NO WARRANTY, to the extent permitted by law.

    [mosh-server detached, pid = 28094]

where

 *  `60002` --- server UDP port
 *  `JE3b4xDf9o6S3RHtlP3uvw` --- shared encryption key (base64-encoded?)
