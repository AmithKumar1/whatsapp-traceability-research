from opentrace.protocols.traceback2019 import (
    SyntheticPathServer, build_path, generate_tag, new_message, verify_tag,
)


def test_tag_verifies_and_rejects_wrong_inputs():
    message = b"synthetic message"
    key = bytes(range(16))
    tag = generate_tag(key, message, new_message())
    assert verify_tag(key, message, type("T", (), {"addr": tag.addr})()) is not None
    assert verify_tag(key, b"other", type("T", (), {"addr": tag.addr})()) is None


def test_simple_path_trace():
    server, metadata = build_path(b"Plaintext", 3)
    assert server.trace(b"Plaintext", metadata, 3) == [3, 2, 1, 0]


def test_wrong_message_stops_trace():
    server, metadata = build_path(b"Plaintext", 3)
    assert server.trace(b"Different Plaintext", metadata, 3) == [3]


def test_identity_binding_stops_at_mismatch():
    message = b"Plaintext"
    server = SyntheticPathServer()
    md = new_message()
    from opentrace.protocols.traceback2019 import synthetic_send
    md = synthetic_send(server, message, md, 0, 1)
    md = synthetic_send(server, message, md, 99, 2)
    assert server.trace(message, md, 2) == [2, 99]
