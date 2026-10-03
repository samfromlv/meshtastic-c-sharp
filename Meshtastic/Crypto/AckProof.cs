using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Google.Protobuf;
using Meshtastic.Protobufs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Meshtastic.Crypto;

/// <summary>
/// Pairwise ACK proof: an authenticated delivery receipt from the actual recipient of a direct message.
/// C# port of firmware's src/mesh/AckProof.cpp and CryptoEngine::ackProofCompute (Meshtastic 2.8.1+).
/// </summary>
/// <remarks>
/// <para>
/// Explicit acks are ROUTING_APP packets, which are excluded from PKC, so an ack is protected only by the channel
/// PSK and anyone holding that PSK can forge one. When both endpoints hold PKI keys they already share a Curve25519
/// secret, so the recipient proves receipt with a short MAC carried in <c>Routing.ack_proof</c>:
/// </para>
/// <code>
/// proof = HMAC-SHA256( sharedKey, "ack" | LE32(from) | LE32(to) | LE32(request_id) | routing )[0..8)
/// </code>
/// <para>
/// <c>sharedKey</c> is SHA256(X25519(own private, peer public)), the same key <see cref="PKIEncryption"/> uses.
/// <c>routing</c> is the encoded Routing message WITHOUT the ack_proof field, exactly as the bytes travelled.
/// It is never re-encoded, so fields this build does not know about are covered too.
/// </para>
/// <para>Caller contract for <see cref="Verify"/> (firmware: ReliableRouter::ackProofPermitsAction):</para>
/// <list type="bullet">
/// <item>Only the node the original packet was ADDRESSED to can prove receipt. The MAC only proves its author holds
/// a pairwise key with us, and every keyed peer does, so verify only when the ack's From equals the original packet's
/// To, and pass THAT node's public key. Passing the key of whoever the ack merely claims to be from accepts a proof
/// minted by any other keyed peer.</item>
/// <item>Verification costs one X25519 and an attacker chooses when it is paid, so only verify acks for requests that
/// are actually outstanding.</item>
/// <item>The verdict is advisory. <see cref="MeshPacket.Types.AckProofStatus.AckProofAbsent"/> is the normal case for
/// older firmware and non-PKI peers and must not be treated as a failure. Only the original sender can verify;
/// relays cannot, so a forged ack still propagates.</item>
/// <item>PKI_UNKNOWN_PUBKEY and NO_CHANNEL naks are emitted precisely because no shared secret exists, so they never
/// carry a proof.</item>
/// </list>
/// </remarks>
public static class AckProof
{
    /// <summary>Length of <c>Routing.ack_proof</c> (firmware: ACK_PROOF_SIZE, protobuf option max_size:8).</summary>
    public const int ProofSize = 8;

    /// <summary>Protobuf field number of <c>Routing.ack_proof</c>.</summary>
    public const int FieldNumber = Routing.AckProofFieldNumber;

    private const int KeySize = 32;

    private const int WireTypeVarint = 0;
    private const int WireType64Bit = 1;
    private const int WireTypeLengthDelimited = 2;
    private const int WireType32Bit = 5;

    private const uint NodeNumBroadcast = 0xFFFFFFFF;
    private const uint NodeNumBroadcastNoLora = 1;

    // Domain separation only, never secret. Fixed length and followed by fixed-width fields, so the HMAC input is
    // unambiguous without length prefixes. No trailing NUL on the wire.
    private static ReadOnlySpan<byte> Label => "ack"u8;

    /// <summary>
    /// Is this a packet shaped like an explicit ack/nak a proof can be attached to? A decoded ROUTING_APP unicast
    /// with a request_id (firmware: isProvableAck).
    /// </summary>
    public static bool IsProvableAck(MeshPacket? packet)
    {
        if (packet is null || packet.PayloadVariantCase != MeshPacket.PayloadVariantOneofCase.Decoded) return false;

        var decoded = packet.Decoded;
        return decoded.Portnum == PortNum.RoutingApp
            && decoded.RequestId != 0
            && packet.To != NodeNumBroadcast
            && packet.To != NodeNumBroadcastNoLora;
    }

    /// <summary>
    /// Derives the 8-byte proof (firmware: CryptoEngine::ackProofCompute). Both endpoints compute the same value
    /// from opposite halves of the key pair, over the same direction tuple (the acker is <paramref name="ackFrom"/>).
    /// </summary>
    /// <param name="ownPrivateKey">Our 32-byte X25519 private key.</param>
    /// <param name="peerPublicKey">The other endpoint's 32-byte X25519 public key.</param>
    /// <param name="ackFrom">Node number the ack is from.</param>
    /// <param name="ackTo">Node number the ack is addressed to.</param>
    /// <param name="requestId">Id of the packet being acknowledged (<c>Data.request_id</c>).</param>
    /// <param name="routing">Encoded Routing message without the ack_proof field.</param>
    /// <param name="proof">The proof, or null when none can be computed.</param>
    /// <returns>
    /// False when there is nothing to prove with: an all-zero own key, a peer key that is missing or not 32 bytes,
    /// or a weak (low-order) peer key that X25519 rejects.
    /// </returns>
    /// <exception cref="ArgumentException">Our own private key is not 32 bytes.</exception>
    public static bool TryCompute(byte[] ownPrivateKey, byte[]? peerPublicKey, uint ackFrom, uint ackTo, uint requestId,
        ReadOnlySpan<byte> routing, [NotNullWhen(true)] out byte[]? proof)
    {
        ArgumentNullException.ThrowIfNull(ownPrivateKey);
        if (ownPrivateKey.Length != KeySize)
            throw new ArgumentException("X25519 private key must be 32 bytes", nameof(ownPrivateKey));

        proof = null;
        if (peerPublicKey is null || peerPublicKey.Length != KeySize) return false;
        if (!ownPrivateKey.AsSpan().ContainsAnyExcept((byte)0)) return false; // no identity yet

        var sharedKey = TryDeriveSharedKey(ownPrivateKey, peerPublicKey);
        if (sharedKey is null) return false;

        var message = new byte[Label.Length + 3 * sizeof(uint) + routing.Length];
        var span = message.AsSpan();
        Label.CopyTo(span);
        var offset = Label.Length;
        BinaryPrimitives.WriteUInt32LittleEndian(span[offset..], ackFrom);
        offset += sizeof(uint);
        BinaryPrimitives.WriteUInt32LittleEndian(span[offset..], ackTo);
        offset += sizeof(uint);
        BinaryPrimitives.WriteUInt32LittleEndian(span[offset..], requestId);
        offset += sizeof(uint);
        routing.CopyTo(span[offset..]);

        var mac = HMACSHA256.HashData(sharedKey, message);
        proof = mac.AsSpan(0, ProofSize).ToArray();

        CryptographicOperations.ZeroMemory(mac);
        CryptographicOperations.ZeroMemory(sharedKey); // do not leave the pairwise secret lying around
        return true;
    }

    /// <summary>Same SHA256(X25519(priv, pub)) derivation PKI packet encryption uses (see <see cref="PKIEncryption"/>).</summary>
    private static byte[]? TryDeriveSharedKey(byte[] ownPrivateKey, byte[] peerPublicKey)
    {
        var secret = new byte[KeySize];
        try
        {
            new X25519PrivateKeyParameters(ownPrivateKey, 0)
                .GenerateSecret(new X25519PublicKeyParameters(peerPublicKey, 0), secret);
            return SHA256.HashData(secret);
        }
        catch (InvalidOperationException)
        {
            // BouncyCastle throws when the agreement is all zeroes, i.e. a low-order peer key. That is the
            // firmware's weak-point rejection in setDHPublicKey.
            return null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    /// <summary>
    /// Reads the proof out of an encoded Routing payload (firmware: ackProofExtract). Walks the protobuf wire format
    /// rather than assuming the proof is the trailing field.
    /// </summary>
    /// <param name="routingPayload">Encoded Routing message (<c>Data.payload</c> of an ack/nak).</param>
    /// <param name="proof">The 8 proof bytes.</param>
    /// <param name="fieldStart">Offset of the field's tag byte, i.e. where the proof field begins.</param>
    /// <param name="fieldLength">Total encoded length of the field (tag + length + proof).</param>
    /// <returns>
    /// False if the field is absent or the message is malformed. Malformed includes a proof that is not exactly
    /// <see cref="ProofSize"/> bytes and a message carrying more than one proof field (two proofs mean two possible
    /// excisions and so two possible verdicts, so neither is picked).
    /// </returns>
    public static bool TryExtract(ReadOnlySpan<byte> routingPayload, [NotNullWhen(true)] out byte[]? proof, out int fieldStart, out int fieldLength)
    {
        proof = null;
        fieldStart = 0;
        fieldLength = 0;

        byte[]? foundProof = null;
        var foundStart = 0;
        var foundLength = 0;
        var position = 0;

        while (position < routingPayload.Length)
        {
            var tagStart = position;
            if (!TryReadVarint(routingPayload, ref position, out var key) || key > uint.MaxValue) return false;

            var tag = (uint)(key >> 3);
            var wireType = (int)(key & 7);

            if (tag == FieldNumber && wireType == WireTypeLengthDelimited)
            {
                if (foundProof is not null) return false; // duplicate proof field

                // A wrong length is malformed, not a near miss: an honest sender emits exactly ProofSize bytes.
                if (!TryReadVarint(routingPayload, ref position, out var length) || length != ProofSize) return false;
                if (routingPayload.Length - position < ProofSize) return false;

                foundProof = routingPayload.Slice(position, ProofSize).ToArray();
                position += ProofSize;
                foundStart = tagStart;
                foundLength = position - tagStart;
                continue;
            }

            if (!TrySkipField(routingPayload, ref position, wireType)) return false;
        }

        if (foundProof is null) return false;

        proof = foundProof;
        fieldStart = foundStart;
        fieldLength = foundLength;
        return true;
    }

    private static bool TryReadVarint(ReadOnlySpan<byte> data, ref int position, out ulong value)
    {
        value = 0;
        for (var shift = 0; shift <= 63 && position < data.Length; shift += 7)
        {
            var b = data[position++];
            if (shift == 63 && b > 1) return false; // would overflow 64 bits
            value |= (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0) return true;
        }
        return false; // truncated, or longer than 10 bytes
    }

    private static bool TrySkipField(ReadOnlySpan<byte> data, ref int position, int wireType)
    {
        switch (wireType)
        {
            case WireTypeVarint:
                return TryReadVarint(data, ref position, out _);
            case WireType64Bit:
                return TryAdvance(data, ref position, 8);
            case WireType32Bit:
                return TryAdvance(data, ref position, 4);
            case WireTypeLengthDelimited:
                if (!TryReadVarint(data, ref position, out var length) || length > (ulong)(data.Length - position)) return false;
                position += (int)length;
                return true;
            default:
                return false; // groups and invalid wire types, as nanopb's pb_skip_field
        }
    }

    private static bool TryAdvance(ReadOnlySpan<byte> data, ref int position, int count)
    {
        if (data.Length - position < count) return false;
        position += count;
        return true;
    }

    /// <summary>
    /// Attaches a proof to a freshly built ROUTING ack/nak (firmware: ackProofAttachWithKey). Sets
    /// <c>Routing.AckProof</c> on the decoded payload and re-serializes it. The MAC covers the Routing message as it
    /// serializes without the proof, which is exactly what the receiver rebuilds by cutting the proof field out of the
    /// bytes it got. For an ack built from the generated Routing this is byte-for-byte what firmware's append yields.
    /// </summary>
    /// <param name="ownPrivateKey">Our (the acker's) 32-byte X25519 private key.</param>
    /// <param name="peerPublicKey">Public key of the node the ack is addressed to (<c>ackPacket.To</c>).</param>
    /// <param name="ackPacket">
    /// The ack/nak to sign. <c>Decoded.Payload</c> must be an encoded Routing message; it is replaced with the signed
    /// one. A proof already present is replaced, not duplicated.
    /// </param>
    /// <param name="ownNodeNum">
    /// Our node number, used as the sender when <c>ackPacket.From</c> is 0 (firmware: getFrom, for packets that have
    /// not been stamped with a sender yet).
    /// </param>
    /// <returns>
    /// True if a proof was attached. False, with the packet untouched, when it is not a provable ack (see
    /// <see cref="IsProvableAck"/>), the sender is unknown, the payload is not a valid Routing message, no proof can be
    /// computed, or the payload has no room for the 10 extra bytes. The ack is then simply sent unproven rather than
    /// truncated.
    /// </returns>
    public static bool Sign(byte[] ownPrivateKey, byte[]? peerPublicKey, MeshPacket ackPacket, uint ownNodeNum = 0)
    {
        ArgumentNullException.ThrowIfNull(ownPrivateKey);
        ArgumentNullException.ThrowIfNull(ackPacket);
        if (!IsProvableAck(ackPacket)) return false;

        var from = ackPacket.From != 0 ? ackPacket.From : ownNodeNum;
        if (from == 0) return false;

        var decoded = ackPacket.Decoded;

        Routing routing;
        try
        {
            routing = Routing.Parser.ParseFrom(decoded.Payload);
        }
        catch (InvalidProtocolBufferException)
        {
            return false;
        }

        // Hash the message as it serializes WITHOUT the proof: that is what the receiver rebuilds by cutting the proof
        // field out of the bytes it got. Clearing first also means signing twice replaces the proof, not duplicates it.
        routing.AckProof = ByteString.Empty;
        if (!TryCompute(ownPrivateKey, peerPublicKey, from, ackPacket.To, decoded.RequestId, routing.ToByteArray(), out var proof)) return false;

        routing.AckProof = ByteString.CopyFrom(proof);
        var signed = routing.ToByteString();
        if (signed.Length > (int)Constants.DataPayloadLen) return false; // out of room: send unproven rather than truncating

        decoded.Payload = signed;
        return true;
    }

    /// <summary>
    /// Checks the proof on a received ack/nak against the id of the packet it claims to acknowledge
    /// (firmware: ackProofVerifyWithKey). See the class remarks for the caller contract: this is the mechanism only,
    /// and the caller must have established that <c>ackPacket.From</c> is the node the original packet was addressed
    /// to and that <paramref name="peerPublicKey"/> is that node's key.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Why this works on the raw payload bytes instead of a parsed <see cref="Routing"/> (unlike <see cref="Sign"/>):
    /// the MAC covers the Routing message exactly as the SENDER serialized it, and the sender is firmware we do not
    /// control. To check it we must rebuild those exact bytes, and the only way that is guaranteed is to take the
    /// received bytes and cut the proof field out of them.
    /// </para>
    /// <para>
    /// Parsing, clearing <c>AckProof</c> and re-serializing would only reproduce them if this library's serializer
    /// happens to agree with the sender's. It does not always: Google.Protobuf writes fields it does not know after
    /// the ones it does, so an ack from a firmware that has added a Routing field would come out in a different order,
    /// hash differently, and a genuine ack would be reported as <c>AckProofInvalid</c>, i.e. as forged. A parse would
    /// also quietly keep only the last of two proof fields, where the byte walk in <see cref="TryExtract"/> rejects the
    /// message as malformed. <see cref="Sign"/> can use the generated type because it hashes whatever it serializes
    /// itself, so both ends of its own round trip agree by construction.
    /// </para>
    /// </remarks>
    /// <param name="ownPrivateKey">Our (the original sender's) 32-byte X25519 private key.</param>
    /// <param name="peerPublicKey">Public key of the node that should have produced the ack, or null if unknown.</param>
    /// <param name="ackPacket">The received ack/nak. Not modified.</param>
    /// <param name="requestId">Id of our outstanding packet that this ack claims to acknowledge.</param>
    /// <returns>
    /// <see cref="MeshPacket.Types.AckProofStatus.AckProofAbsent"/> when no (readable) proof is attached;
    /// <see cref="MeshPacket.Types.AckProofStatus.AckProofNoKey"/> when one is present but there is no usable key to
    /// judge it; otherwise <see cref="MeshPacket.Types.AckProofStatus.AckProofValid"/> or
    /// <see cref="MeshPacket.Types.AckProofStatus.AckProofInvalid"/>.
    /// </returns>
    public static MeshPacket.Types.AckProofStatus Verify(byte[] ownPrivateKey, byte[]? peerPublicKey, MeshPacket ackPacket, uint requestId)
    {
        ArgumentNullException.ThrowIfNull(ownPrivateKey);
        ArgumentNullException.ThrowIfNull(ackPacket);

        if (ackPacket.PayloadVariantCase != MeshPacket.PayloadVariantOneofCase.Decoded)
            return MeshPacket.Types.AckProofStatus.AckProofAbsent;

        var payload = ackPacket.Decoded.Payload.Span;
        if (!TryExtract(payload, out var claimed, out var fieldStart, out var fieldLength))
            return MeshPacket.Types.AckProofStatus.AckProofAbsent;
        if (peerPublicKey is null || peerPublicKey.Length != KeySize)
            return MeshPacket.Types.AckProofStatus.AckProofNoKey;

        // The Routing message the sender hashed: the received bytes with the proof field's range removed. Deliberately
        // not parse + clear + re-serialize, which can reorder fields we do not know (see the remarks above).
        var routing = new byte[payload.Length - fieldLength];
        payload[..fieldStart].CopyTo(routing);
        payload[(fieldStart + fieldLength)..].CopyTo(routing.AsSpan(fieldStart));

        if (!TryCompute(ownPrivateKey, peerPublicKey, ackPacket.From, ackPacket.To, requestId, routing, out var expected))
            return MeshPacket.Types.AckProofStatus.AckProofNoKey;

        return CryptographicOperations.FixedTimeEquals(claimed, expected)
            ? MeshPacket.Types.AckProofStatus.AckProofValid
            : MeshPacket.Types.AckProofStatus.AckProofInvalid;
    }
}
