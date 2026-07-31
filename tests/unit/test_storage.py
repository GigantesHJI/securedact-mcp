from securedact_core.storage import EncryptedLocalVault


def test_mapping_is_encrypted_at_rest(tmp_path) -> None:
    database = tmp_path / "vault.sqlite3"
    key = EncryptedLocalVault.generate_key()
    vault = EncryptedLocalVault(database, key)
    vault.save_mapping("conversation-1", {"[PERSON_1]": "Ada Lovelace"})
    assert b"Ada Lovelace" not in database.read_bytes()
    assert vault.load_mapping("conversation-1") == {"[PERSON_1]": "Ada Lovelace"}
    vault.delete_mapping("conversation-1")
    assert vault.load_mapping("conversation-1") is None
