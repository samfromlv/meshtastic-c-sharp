using Google.Protobuf;
using Meshtastic.Crypto;
using Meshtastic.Protobufs;

namespace Meshtastic.Test.Crypto;

/// <summary>
/// Ported from firmware's test/test_ack_proof, plus a known-answer vector computed independently in Python
/// (hashlib + cryptography) straight from the byte layout in CryptoEngine::ackProofCompute.
/// </summary>
public class AckProofTests
{
    private const uint Alice = 0x0A0A0A0A; // sends the DM, verifies the ack
    private const uint Bob = 0x0B0B0B0B;   // receives the DM, produces the ack
    private const uint Carol = 0x0C0C0C0C; // a third node whose key Alice also holds
    private const uint RequestId = 0xABCD1234;
    private const uint NodeNumBroadcast = 0xFFFFFFFF;

    // Encoded Routing { error_reason = NONE }.
    private static readonly byte[] RoutingNone = [0x18, 0x00];

    private static (byte[] privateKey, byte[] publicKey) NewIdentity() => PKIEncryption.GenerateKeyPair();

    private static MeshPacket MakeAck(uint from, uint to, uint requestId) => new()
    {
        From = from,
        To = to,
        Id = 0x5150,
        Decoded = new Protobufs.Data
        {
            Portnum = PortNum.RoutingApp,
            RequestId = requestId,
            Payload = new Routing { ErrorReason = Routing.Types.Error.None }.ToByteString(),
        },
    };

    private static MeshPacket SignedAck(byte[] ackerPrivateKey, byte[] recipientPublicKey, uint from = Bob, uint to = Alice)
    {
        var ack = MakeAck(from, to, RequestId);
        AckProof.Sign(ackerPrivateKey, recipientPublicKey, ack).Should().BeTrue();
        return ack;
    }

    private static byte[] Payload(MeshPacket packet) => packet.Decoded.Payload.ToByteArray();

    private static void SetPayload(MeshPacket packet, byte[] payload) => packet.Decoded.Payload = ByteString.CopyFrom(payload);

    private static byte[] Compute(byte[] privateKey, byte[] peerPublicKey, uint from, uint to, uint requestId, byte[] routing)
    {
        AckProof.TryCompute(privateKey, peerPublicKey, from, to, requestId, routing, out var proof).Should().BeTrue();
        return proof!;
    }

    [Test]
    public void ProofMatchesKnownAnswerVector()
    {
        var alicePrivate = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
        var bobPrivate = Enumerable.Range(33, 32).Select(i => (byte)i).ToArray();
        var alicePublic = PKIEncryption.GetPublicKeyFromPrivateKey(alicePrivate);
        var bobPublic = PKIEncryption.GetPublicKeyFromPrivateKey(bobPrivate);

        Convert.ToHexString(alicePublic).Should().BeEquivalentTo("07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c");
        Convert.ToHexString(bobPublic).Should().BeEquivalentTo("5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b");

        // Both endpoints, same direction tuple (Bob is the acker).
        Convert.ToHexString(Compute(bobPrivate, alicePublic, Bob, Alice, RequestId, RoutingNone)).Should().BeEquivalentTo("7c1e5c422777aa72");
        Convert.ToHexString(Compute(alicePrivate, bobPublic, Bob, Alice, RequestId, RoutingNone)).Should().BeEquivalentTo("7c1e5c422777aa72");

        // A longer routing blob (carries an unknown field), to cover the variable-length tail of the HMAC input.
        byte[] longerRouting = [0x18, 0x00, 0x4A, 0x03, 0x11, 0x22, 0x33];
        Convert.ToHexString(Compute(bobPrivate, alicePublic, Bob, Alice, RequestId, longerRouting)).Should().BeEquivalentTo("a3e15a53767d6b60");

        // And the full wire form Sign produces: Routing bytes, then tag 0x22, length 8, proof.
        var ack = MakeAck(Bob, Alice, RequestId);
        AckProof.Sign(bobPrivate, alicePublic, ack).Should().BeTrue();
        Convert.ToHexString(Payload(ack)).Should().BeEquivalentTo("180022087c1e5c422777aa72");
    }

    // Both endpoints derive the same value from opposite halves of the key pair, and nobody else can.
    [Test]
    public void ProofIsPairwiseAndSymmetric()
    {
        var alice = NewIdentity();
        var bob = NewIdentity();
        var mallory = NewIdentity();

        var fromBob = Compute(bob.privateKey, alice.publicKey, Bob, Alice, RequestId, RoutingNone);
        var fromAlice = Compute(alice.privateKey, bob.publicKey, Bob, Alice, RequestId, RoutingNone);
        var fromMallory = Compute(mallory.privateKey, alice.publicKey, Bob, Alice, RequestId, RoutingNone);

        fromAlice.Should().Equal(fromBob);
        fromMallory.Should().NotEqual(fromBob);
    }

    [Test]
    public void ProofBindsRequestId()
    {
        var alice = NewIdentity();
        var bob = NewIdentity();

        var a = Compute(bob.privateKey, alice.publicKey, Bob, Alice, RequestId, RoutingNone);
        var b = Compute(bob.privateKey, alice.publicKey, Bob, Alice, RequestId + 1, RoutingNone);

        b.Should().NotEqual(a);
    }

    // X25519 is symmetric, so without the direction bound an A->B proof would equal the B->A proof.
    [Test]
    public void ProofBindsDirection()
    {
        var alice = NewIdentity();
        var bob = NewIdentity();

        var forward = Compute(bob.privateKey, alice.publicKey, Bob, Alice, RequestId, RoutingNone);
        var reverse = Compute(bob.privateKey, alice.publicKey, Alice, Bob, RequestId, RoutingNone);

        reverse.Should().NotEqual(forward);
    }

    // An ack and a nak for one packet differ only in the Routing payload. Channel crypto has no integrity check, so
    // if the payload were not bound a PSK holder could flip a proven success into a failure.
    [Test]
    public void ProofBindsRoutingBytes()
    {
        var alice = NewIdentity();
        var bob = NewIdentity();
        var ack = SignedAck(bob.privateKey, alice.publicKey);

        AckProof.Verify(alice.privateKey, bob.publicKey, ack, RequestId).Should().Be(MeshPacket.Types.AckProofStatus.AckProofValid);

        var payload = Payload(ack);
        payload[1] = (byte)Routing.Types.Error.MaxRetransmit; // exactly what a CTR bit-flip buys the attacker
        SetPayload(ack, payload);

        AckProof.Verify(alice.privateKey, bob.publicKey, ack, RequestId).Should().Be(MeshPacket.Types.AckProofStatus.AckProofInvalid);
    }

    // Without an identity there is nothing to prove with, and we must fail rather than emit a constant.
    [Test]
    public void ComputeFailsWithoutPrivateKey()
    {
        var peer = NewIdentity();

        AckProof.TryCompute(new byte[32], peer.publicKey, Bob, Alice, RequestId, RoutingNone, out var proof).Should().BeFalse();
        proof.Should().BeNull();
    }

    [Test]
    public void ComputeRejectsWeakOrMalformedPeerKey()
    {
        var self = NewIdentity();

        // All-zero public key is a low-order point; the X25519 agreement must reject it.
        AckProof.TryCompute(self.privateKey, new byte[32], Bob, Alice, RequestId, RoutingNone, out _).Should().BeFalse();
        AckProof.TryCompute(self.privateKey, new byte[31], Bob, Alice, RequestId, RoutingNone, out _).Should().BeFalse();
        AckProof.TryCompute(self.privateKey, null, Bob, Alice, RequestId, RoutingNone, out _).Should().BeFalse();
    }

    [Test]
    public void ComputeRejectsWrongSizePrivateKey()
    {
        var peer = NewIdentity();

        var act = () => AckProof.TryCompute(new byte[16], peer.publicKey, Bob, Alice, RequestId, RoutingNone, out _);

        act.Should().Throw<ArgumentException>();
    }

    // Costs exactly the proof plus a tag and a length byte, and the Routing message still parses with it present.
    [Test]
    public void SignAppendsProofFieldThatGeneratedParserReads()
    {
        var alice = NewIdentity();
        var bob = NewIdentity();
        var ack = MakeAck(Bob, Alice, RequestId);
        var bare = Payload(ack);

        AckProof.Sign(bob.privateKey, alice.publicKey, ack).Should().BeTrue();
        var signed = Payload(ack);

        signed.Length.Should().Be(bare.Length + AckProof.ProofSize + 2);
        signed.Take(bare.Length).Should().Equal(bare);
        signed[bare.Length].Should().Be(0x22);
        signed[bare.Length + 1].Should().Be(AckProof.ProofSize);

        AckProof.TryExtract(signed, out var extracted, out var fieldStart, out var fieldLength).Should().BeTrue();
        fieldStart.Should().Be(bare.Length);
        fieldLength.Should().Be(AckProof.ProofSize + 2);
        extracted.Should().Equal(Compute(alice.privateKey, bob.publicKey, Bob, Alice, RequestId, bare));

        var parsed = Routing.Parser.ParseFrom(signed);
        parsed.VariantCase.Should().Be(Routing.VariantOneofCase.ErrorReason);
        parsed.ErrorReason.Should().Be(Routing.Types.Error.None);
        parsed.AckProof.ToByteArray().Should().Equal(extracted);
    }

    // A bare ack (every firmware without this feature) is Absent, not Invalid: that is what keeps the scheme
    // deployable alongside nodes that know nothing about it.
    [Test]
    public void VerifyVerdicts()
    {
        var alice = NewIdentity();
        var bob = NewIdentity();
        var mallory = NewIdentity();
        var bare = MakeAck(Bob, Alice, RequestId);
        var proven = SignedAck(bob.privateKey, alice.publicKey);

        AckProof.Verify(alice.privateKey, bob.publicKey, bare, RequestId).Should().Be(MeshPacket.Types.AckProofStatus.AckProofAbsent);
        AckProof.Verify(alice.privateKey, bob.publicKey, proven, RequestId).Should().Be(MeshPacket.Types.AckProofStatus.AckProofValid);

        // Present but unjudgeable: we hold no (usable) key for the acker.
        AckProof.Verify(alice.privateKey, null, proven, RequestId).Should().Be(MeshPacket.Types.AckProofStatus.AckProofNoKey);
        AckProof.Verify(alice.privateKey, new byte[31], proven, RequestId).Should().Be(MeshPacket.Types.AckProofStatus.AckProofNoKey);

        // Right proof, wrong pending packet: retargeting is caught.
        AckProof.Verify(alice.privateKey, bob.publicKey, proven, RequestId + 1).Should().Be(MeshPacket.Types.AckProofStatus.AckProofInvalid);

        // Same ack judged against a different node's key.
        AckProof.Verify(alice.privateKey, mallory.publicKey, proven, RequestId).Should().Be(MeshPacket.Types.AckProofStatus.AckProofInvalid);
    }

    [Test]
    public void VerifyDoesNotModifyThePacket()
    {
        var alice = NewIdentity();
        var bob = NewIdentity();
        var ack = SignedAck(bob.privateKey, alice.publicKey);
        var before = Payload(ack);

        AckProof.Verify(alice.privateKey, bob.publicKey, ack, RequestId);

        Payload(ack).Should().Equal(before);
    }

    [Test]
    public void VerifyRejectsTamperedProof()
    {
        var alice = NewIdentity();
        var bob = NewIdentity();
        var ack = SignedAck(bob.privateKey, alice.publicKey);

        var payload = Payload(ack);
        payload[^1] ^= 0x01;
        SetPayload(ack, payload);

        AckProof.Verify(alice.privateKey, bob.publicKey, ack, RequestId).Should().Be(MeshPacket.Types.AckProofStatus.AckProofInvalid);
    }

    [Test]
    public void VerifyReportsAbsentForEncryptedPacket()
    {
        var alice = NewIdentity();
        var bob = NewIdentity();
        var ack = new MeshPacket { From = Bob, To = Alice, Encrypted = ByteString.CopyFrom(1, 2, 3) };

        AckProof.Verify(alice.privateKey, bob.publicKey, ack, RequestId).Should().Be(MeshPacket.Types.AckProofStatus.AckProofAbsent);
    }

    // An honest sender emits exactly ProofSize bytes, so any other length is malformed rather than a near miss.
    [Test]
    public void MalformedProofFieldIsAbsent()
    {
        var alice = NewIdentity();
        var bob = NewIdentity();
        var ack = MakeAck(Bob, Alice, RequestId);
        byte[] truncated = [.. Payload(ack), 0x22, 0x07, 1, 2, 3, 4, 5, 6, 7];
        SetPayload(ack, truncated);

        AckProof.TryExtract(truncated, out _, out _, out _).Should().BeFalse();
        AckProof.Verify(alice.privateKey, bob.publicKey, ack, RequestId).Should().Be(MeshPacket.Types.AckProofStatus.AckProofAbsent);
    }

    [Test]
    public void ProofFieldRunningPastTheEndIsAbsent()
    {
        // Claims 8 bytes of proof but only 3 follow.
        byte[] payload = [0x18, 0x00, 0x22, 0x08, 1, 2, 3];

        AckProof.TryExtract(payload, out _, out _, out _).Should().BeFalse();
    }

    // Two proof fields mean two possible excisions and so two possible verdicts. Refuse rather than pick one, since
    // anyone with the channel key can append a second field at will.
    [Test]
    public void DuplicateProofFieldIsRejected()
    {
        var alice = NewIdentity();
        var bob = NewIdentity();
        var ack = SignedAck(bob.privateKey, alice.publicKey);
        var signed = Payload(ack);
        byte[] duplicated = [.. signed, .. signed.Skip(signed.Length - (AckProof.ProofSize + 2))];
        SetPayload(ack, duplicated);

        AckProof.TryExtract(duplicated, out _, out _, out _).Should().BeFalse();
        AckProof.Verify(alice.privateKey, bob.publicKey, ack, RequestId).Should().Be(MeshPacket.Types.AckProofStatus.AckProofAbsent);
    }

    // The proof must cover fields this build does not understand, so a future Routing field is protected too.
    // Sign keeps them (the generated parser preserves unknown fields) and Verify cuts the proof out of the received
    // bytes rather than re-encoding, so both sides hash the same thing.
    [Test]
    public void ProofCoversUnknownRoutingFields()
    {
        var alice = NewIdentity();
        var bob = NewIdentity();
        var ack = MakeAck(Bob, Alice, RequestId);
        byte[] withUnknown = [.. Payload(ack), 0x4A, 0x03, 0x11, 0x22, 0x33]; // field 9, length-delimited
        SetPayload(ack, withUnknown);
        AckProof.Sign(bob.privateKey, alice.publicKey, ack).Should().BeTrue();

        AckProof.Verify(alice.privateKey, bob.publicKey, ack, RequestId).Should().Be(MeshPacket.Types.AckProofStatus.AckProofValid);

        // Tamper with the unknown field's CONTENTS (it is serialized last), not its framing, so the verdict is
        // Invalid rather than Absent.
        var payload = Payload(ack);
        payload[^1] ^= 0x01;
        SetPayload(ack, payload);

        AckProof.Verify(alice.privateKey, bob.publicKey, ack, RequestId).Should().Be(MeshPacket.Types.AckProofStatus.AckProofInvalid);
    }

    // Verify must hash the bytes as the sender produced them, not a re-serialization. Here the sender (a stand-in for
    // firmware that has added a Routing field) wrote an unknown field BEFORE error_reason. Google.Protobuf writes
    // unknown fields last, so parse + clear + re-serialize would reorder these bytes and a genuine proof would read as
    // Invalid, i.e. as forged.
    [Test]
    public void VerifyHashesReceivedBytesNotAReEncoding()
    {
        var alice = NewIdentity();
        var bob = NewIdentity();
        byte[] unknownField = [0x4A, 0x03, 0x11, 0x22, 0x33]; // field 9, length-delimited
        byte[] routing = [.. unknownField, .. RoutingNone];

        // Guard: this test only means something while a re-encode really does reorder these bytes.
        Routing.Parser.ParseFrom(routing).ToByteArray().Should().NotEqual(routing);

        var proof = Compute(bob.privateKey, alice.publicKey, Bob, Alice, RequestId, routing);
        var ack = MakeAck(Bob, Alice, RequestId);
        SetPayload(ack, [.. routing, 0x22, 0x08, .. proof]);

        AckProof.Verify(alice.privateKey, bob.publicKey, ack, RequestId).Should().Be(MeshPacket.Types.AckProofStatus.AckProofValid);

        // The unknown field is still covered: change its contents, leave the framing alone.
        var payload = Payload(ack);
        payload[unknownField.Length - 1] ^= 0x01;
        SetPayload(ack, payload);

        AckProof.Verify(alice.privateKey, bob.publicKey, ack, RequestId).Should().Be(MeshPacket.Types.AckProofStatus.AckProofInvalid);
    }

    // Unknown fields of every wire type, on both sides of the proof, must be skipped correctly while locating it and
    // then covered by the MAC.
    [Test]
    public void VerifySkipsUnknownFieldsOfEveryWireType()
    {
        var alice = NewIdentity();
        var bob = NewIdentity();
        byte[] head =
        [
            .. RoutingNone,
            0x50, 0x96, 0x01,                                   // unknown varint, field 10
        ];
        byte[] tail =
        [
            0x61, 1, 2, 3, 4, 5, 6, 7, 8,                       // unknown fixed64, field 12
            0x4A, 0x03, 0x11, 0x22, 0x33,                       // unknown length-delimited, field 9
            0x5D, 0xAA, 0xBB, 0xCC, 0xDD,                       // unknown fixed32, field 11
        ];
        var proof = Compute(bob.privateKey, alice.publicKey, Bob, Alice, RequestId, [.. head, .. tail]);
        byte[] payload = [.. head, 0x22, 0x08, .. proof, .. tail];
        var ack = MakeAck(Bob, Alice, RequestId);
        SetPayload(ack, payload);

        AckProof.TryExtract(payload, out var extracted, out var fieldStart, out var fieldLength).Should().BeTrue();
        extracted.Should().Equal(proof);
        fieldStart.Should().Be(head.Length);
        fieldLength.Should().Be(AckProof.ProofSize + 2);
        AckProof.Verify(alice.privateKey, bob.publicKey, ack, RequestId).Should().Be(MeshPacket.Types.AckProofStatus.AckProofValid);
    }

    // The proof is found by walking the wire format, not by assuming it is the trailing field.
    [Test]
    public void ProofIsFoundAndExcisedWhenNotTrailing()
    {
        var alice = NewIdentity();
        var bob = NewIdentity();
        var proof = Compute(bob.privateKey, alice.publicKey, Bob, Alice, RequestId, RoutingNone);
        byte[] proofFirst = [0x22, 0x08, .. proof, .. RoutingNone];
        var ack = MakeAck(Bob, Alice, RequestId);
        SetPayload(ack, proofFirst);

        AckProof.TryExtract(proofFirst, out var extracted, out var fieldStart, out var fieldLength).Should().BeTrue();
        extracted.Should().Equal(proof);
        fieldStart.Should().Be(0);
        fieldLength.Should().Be(AckProof.ProofSize + 2);
        AckProof.Verify(alice.privateKey, bob.publicKey, ack, RequestId).Should().Be(MeshPacket.Types.AckProofStatus.AckProofValid);
    }

    [Test]
    public void ExtractIgnoresFieldFourWithAnotherWireType()
    {
        byte[] payload = [0x18, 0x00, 0x20, 0x08]; // field 4 as a varint is some other, unknown field

        AckProof.TryExtract(payload, out _, out _, out _).Should().BeFalse();
    }

    // Nothing is attached to packets that are not explicit acks, so no other traffic pays for this.
    [Test]
    public void SignOnlyAppliesToRoutingUnicasts()
    {
        var peer = NewIdentity();
        var self = NewIdentity();

        var broadcast = MakeAck(Bob, NodeNumBroadcast, RequestId);
        var noRequestId = MakeAck(Bob, Alice, 0);
        var text = MakeAck(Bob, Alice, RequestId);
        text.Decoded.Portnum = PortNum.TextMessageApp;
        var encrypted = new MeshPacket { From = Bob, To = Alice, Encrypted = ByteString.CopyFrom(1, 2, 3) };

        foreach (var packet in new[] { broadcast, noRequestId, text, encrypted })
        {
            var before = packet.ToByteArray();
            AckProof.IsProvableAck(packet).Should().BeFalse();
            AckProof.Sign(self.privateKey, peer.publicKey, packet).Should().BeFalse();
            packet.ToByteArray().Should().Equal(before);
        }

        AckProof.IsProvableAck(MakeAck(Bob, Alice, RequestId)).Should().BeTrue();
    }

    [Test]
    public void SignLeavesPacketUntouchedWhenNoProofCanBeComputed()
    {
        var self = NewIdentity();
        var ack = MakeAck(Bob, Alice, RequestId);
        var before = ack.ToByteArray();

        AckProof.Sign(self.privateKey, null, ack).Should().BeFalse();
        AckProof.Sign(self.privateKey, new byte[32], ack).Should().BeFalse(); // weak key

        ack.ToByteArray().Should().Equal(before);
    }

    // Firmware's getFrom(): a locally built ack has no sender stamped yet, so our own node number stands in.
    [Test]
    public void SignUsesOwnNodeNumWhenFromIsUnset()
    {
        var alice = NewIdentity();
        var bob = NewIdentity();
        var unstamped = MakeAck(0, Alice, RequestId);

        AckProof.Sign(bob.privateKey, alice.publicKey, unstamped).Should().BeFalse("without a sender there is nothing to bind");
        AckProof.Sign(bob.privateKey, alice.publicKey, unstamped, ownNodeNum: Bob).Should().BeTrue();

        // The receiver sees the ack stamped with Bob as sender and must reach the same verdict.
        unstamped.From = Bob;
        AckProof.Verify(alice.privateKey, bob.publicKey, unstamped, RequestId).Should().Be(MeshPacket.Types.AckProofStatus.AckProofValid);
    }

    // The ack is dropped unproven rather than truncated when the 10 extra bytes do not fit.
    [Test]
    public void SignRefusesWhenPayloadHasNoRoom()
    {
        var alice = NewIdentity();
        var bob = NewIdentity();
        var max = (int)Constants.DataPayloadLen;
        var overhead = AckProof.ProofSize + 2;

        var full = MakeAck(Bob, Alice, RequestId);
        SetPayload(full, RoutingOfSize(max - overhead + 1));
        AckProof.Sign(bob.privateKey, alice.publicKey, full).Should().BeFalse();
        Payload(full).Length.Should().Be(max - overhead + 1);

        var exact = MakeAck(Bob, Alice, RequestId);
        SetPayload(exact, RoutingOfSize(max - overhead));
        AckProof.Sign(bob.privateKey, alice.publicKey, exact).Should().BeTrue();
        Payload(exact).Length.Should().Be(max);
    }

    // Signing twice replaces the proof instead of leaving two (which a verifier would reject as malformed).
    [Test]
    public void SigningTwiceReplacesTheProof()
    {
        var alice = NewIdentity();
        var bob = NewIdentity();
        var ack = SignedAck(bob.privateKey, alice.publicKey);
        var once = Payload(ack);

        AckProof.Sign(bob.privateKey, alice.publicKey, ack).Should().BeTrue();

        Payload(ack).Should().Equal(once);
        AckProof.Verify(alice.privateKey, bob.publicKey, ack, RequestId).Should().Be(MeshPacket.Types.AckProofStatus.AckProofValid);
    }

    // A Routing message that already carries a proof (stale, from someone else, or the wrong length) must come out with
    // exactly one proof, the correct one, and the old bytes must not leak into what the MAC covers.
    [Test]
    public void SignReplacesProofAlreadySetOnTheMessage()
    {
        var alice = NewIdentity();
        var bob = NewIdentity();
        var correct = Compute(alice.privateKey, bob.publicKey, Bob, Alice, RequestId, RoutingNone);
        byte[] expectedPayload = [.. RoutingNone, 0x22, 0x08, .. correct];

        byte[][] preSetProofs = [[1, 2, 3, 4, 5, 6, 7, 8], [9, 9, 9], new byte[AckProof.ProofSize]];
        foreach (var preSet in preSetProofs)
        {
            var ack = MakeAck(Bob, Alice, RequestId);
            SetPayload(ack, new Routing { ErrorReason = Routing.Types.Error.None, AckProof = ByteString.CopyFrom(preSet) }.ToByteArray());

            AckProof.Sign(bob.privateKey, alice.publicKey, ack).Should().BeTrue();

            Payload(ack).Should().Equal(expectedPayload);
            AckProof.Verify(alice.privateKey, bob.publicKey, ack, RequestId).Should().Be(MeshPacket.Types.AckProofStatus.AckProofValid);
        }
    }

    [Test]
    public void SignRefusesPayloadThatIsNotARoutingMessage()
    {
        var alice = NewIdentity();
        var bob = NewIdentity();
        var ack = MakeAck(Bob, Alice, RequestId);
        byte[] garbage = [0xFF, 0xFF, 0xFF];
        SetPayload(ack, garbage);

        AckProof.Sign(bob.privateKey, alice.publicKey, ack).Should().BeFalse();

        Payload(ack).Should().Equal(garbage);
    }

    // A valid Routing message of exactly this encoded size: the error_reason field plus one padded unknown field.
    private static byte[] RoutingOfSize(int size)
    {
        var padding = size - 5; // 18 00 | 4A <2-byte length> | padding
        return [.. RoutingNone, 0x4A, (byte)((padding & 0x7F) | 0x80), (byte)(padding >> 7), .. new byte[padding]];
    }

    // The proof rides nested inside Data.payload, which is an opaque bytes field, so it survives being
    // serialized and parsed again on its way through the mesh.
    [Test]
    public void ProofSurvivesPacketRoundTrip()
    {
        var alice = NewIdentity();
        var bob = NewIdentity();
        var ack = SignedAck(bob.privateKey, alice.publicKey);

        var received = MeshPacket.Parser.ParseFrom(ack.ToByteArray());

        AckProof.Verify(alice.privateKey, bob.publicKey, received, RequestId).Should().Be(MeshPacket.Types.AckProofStatus.AckProofValid);
    }

    // The MAC only proves its author holds a pairwise key with us, and every keyed peer does. Carol, whose key Alice
    // holds, mints an ack for a packet Alice sent to Bob. It verifies under Carol's key, so a verifier keyed off the
    // ack's claimed sender accepts it, and it must fail under Bob's, the key of the node actually addressed.
    [Test]
    public void ProofFromThirdPeerFailsUnderRecipientKey()
    {
        var alice = NewIdentity();
        var bob = NewIdentity();
        var carol = NewIdentity();
        var ack = SignedAck(carol.privateKey, alice.publicKey, from: Carol);

        AckProof.Verify(alice.privateKey, carol.publicKey, ack, RequestId).Should().Be(MeshPacket.Types.AckProofStatus.AckProofValid);
        AckProof.Verify(alice.privateKey, bob.publicKey, ack, RequestId).Should().Be(MeshPacket.Types.AckProofStatus.AckProofInvalid);
    }
}
