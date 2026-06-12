"""Pytest suite for the Advanced Password Manager."""

import json
import string

import pytest

import password_manager as pm


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture
def vault_path(tmp_path):
    return tmp_path / "test.pm"


@pytest.fixture
def vault(vault_path):
    """A freshly created, unlocked vault."""
    v = pm.Vault(vault_path)
    v.create("masterpass123")
    return v


def make_entry(name="github", **kw):
    defaults = dict(username="user", password="Secret123!", url="github.com", notes="")
    defaults.update(kw)
    return pm.Entry(name=name, **defaults)


# --------------------------------------------------------------------------- #
# Password generation
# --------------------------------------------------------------------------- #

class TestGeneratePassword:
    def test_default_length(self):
        assert len(pm.generate_password()) == 20

    @pytest.mark.parametrize("length", [4, 8, 16, 32, 64])
    def test_custom_length(self, length):
        assert len(pm.generate_password(length)) == length

    def test_too_short_raises(self):
        with pytest.raises(ValueError):
            pm.generate_password(3)

    def test_no_character_class_raises(self):
        with pytest.raises(ValueError):
            pm.generate_password(
                use_upper=False, use_lower=False,
                use_digits=False, use_symbols=False,
            )

    def test_guarantees_each_selected_class(self):
        # Run many times since selection is random.
        for _ in range(50):
            p = pm.generate_password(
                12, use_upper=True, use_lower=True,
                use_digits=True, use_symbols=True,
            )
            assert any(c.islower() for c in p)
            assert any(c.isupper() for c in p)
            assert any(c.isdigit() for c in p)
            assert any(not c.isalnum() for c in p)

    def test_digits_only(self):
        p = pm.generate_password(
            10, use_upper=False, use_lower=False,
            use_digits=True, use_symbols=False,
        )
        assert p.isdigit()

    def test_avoids_ambiguous_characters(self):
        ambiguous = set("Il1O0|`'\"")
        for _ in range(50):
            p = pm.generate_password(40, avoid_ambiguous=True)
            assert not (set(p) & ambiguous)

    def test_outputs_differ(self):
        # Two CSPRNG passwords should essentially never collide.
        assert pm.generate_password(20) != pm.generate_password(20)


# --------------------------------------------------------------------------- #
# Strength meter
# --------------------------------------------------------------------------- #

class TestPasswordStrength:
    def test_weak_short_password(self):
        label, score = pm.password_strength("abc")
        assert label == "Weak"
        assert score < 40

    def test_strong_generated_password(self):
        label, score = pm.password_strength(pm.generate_password(24))
        assert label in {"Strong", "Very Strong"}
        assert score >= 70

    def test_score_bounded(self):
        _, score = pm.password_strength("A1!" * 50)
        assert 0 <= score <= 100


# --------------------------------------------------------------------------- #
# Key derivation
# --------------------------------------------------------------------------- #

class TestDeriveKey:
    def test_deterministic(self):
        salt = b"0123456789abcdef"
        assert pm.derive_key("pw", salt) == pm.derive_key("pw", salt)

    def test_salt_changes_key(self):
        assert pm.derive_key("pw", b"a" * 16) != pm.derive_key("pw", b"b" * 16)

    def test_password_changes_key(self):
        salt = b"0123456789abcdef"
        assert pm.derive_key("pw1", salt) != pm.derive_key("pw2", salt)


# --------------------------------------------------------------------------- #
# Vault lifecycle & auth
# --------------------------------------------------------------------------- #

class TestVaultAuth:
    def test_create_writes_file(self, vault, vault_path):
        assert vault_path.exists()

    def test_unlock_with_correct_password(self, vault, vault_path):
        v2 = pm.Vault(vault_path)
        assert v2.unlock("masterpass123") is True

    def test_unlock_with_wrong_password(self, vault, vault_path):
        v2 = pm.Vault(vault_path)
        assert v2.unlock("wrongpass") is False

    def test_exists(self, vault_path):
        v = pm.Vault(vault_path)
        assert v.exists() is False
        v.create("pw12345678")
        assert v.exists() is True


# --------------------------------------------------------------------------- #
# CRUD operations
# --------------------------------------------------------------------------- #

class TestVaultCRUD:
    def test_add_and_get(self, vault):
        vault.add(make_entry())
        e = vault.get("github")
        assert e is not None
        assert e.username == "user"
        assert e.created and e.updated  # timestamps set

    def test_add_persists_across_reload(self, vault, vault_path):
        vault.add(make_entry(password="RoundTrip!1"))
        v2 = pm.Vault(vault_path)
        v2.unlock("masterpass123")
        assert v2.get("github").password == "RoundTrip!1"

    def test_update(self, vault):
        vault.add(make_entry())
        assert vault.update("github", password="NewPass!9") is True
        assert vault.get("github").password == "NewPass!9"

    def test_update_missing_returns_false(self, vault):
        assert vault.update("nope", password="x") is False

    def test_update_ignores_none_fields(self, vault):
        vault.add(make_entry(username="keep"))
        vault.update("github", username=None, password="changed")
        assert vault.get("github").username == "keep"
        assert vault.get("github").password == "changed"

    def test_delete(self, vault):
        vault.add(make_entry())
        assert vault.delete("github") is True
        assert vault.get("github") is None

    def test_delete_missing_returns_false(self, vault):
        assert vault.delete("nope") is False

    def test_search(self, vault):
        vault.add(make_entry(name="github", url="github.com"))
        vault.add(make_entry(name="gmail", username="me@gmail.com", url="gmail.com"))
        assert {e.name for e in vault.search("git")} == {"github"}
        assert {e.name for e in vault.search("gmail")} == {"gmail"}
        assert {e.name for e in vault.search("com")} == {"github", "gmail"}

    def test_search_is_case_insensitive(self, vault):
        vault.add(make_entry(name="GitHub"))
        assert vault.search("github")


# --------------------------------------------------------------------------- #
# Encryption at rest
# --------------------------------------------------------------------------- #

class TestEncryptionAtRest:
    def test_no_plaintext_leak(self, vault, vault_path):
        vault.add(make_entry(username="secret_user", password="TopSecret!99",
                             notes="my private note"))
        raw = vault_path.read_text()
        assert "secret_user" not in raw
        assert "TopSecret!99" not in raw
        assert "my private note" not in raw

    def test_on_disk_is_json_with_expected_header(self, vault, vault_path):
        blob = json.loads(vault_path.read_text())
        assert blob["version"] == pm.Vault.VERSION
        assert "salt" in blob and "verifier" in blob and "data" in blob


# --------------------------------------------------------------------------- #
# Change master password
# --------------------------------------------------------------------------- #

class TestChangeMasterPassword:
    def test_reencrypt_with_new_password(self, vault, vault_path):
        vault.add(make_entry(password="Preserve!1"))
        entries = vault.entries
        vault.create("brandnewpass456")  # fresh salt + key
        vault.entries = entries
        vault.save()

        # Old password no longer works; new one does, data preserved.
        v_old = pm.Vault(vault_path)
        assert v_old.unlock("masterpass123") is False
        v_new = pm.Vault(vault_path)
        assert v_new.unlock("brandnewpass456") is True
        assert v_new.get("github").password == "Preserve!1"


# --------------------------------------------------------------------------- #
# CLI entry point
# --------------------------------------------------------------------------- #

class TestCLI:
    def test_gen_subcommand(self, capsys):
        rc = pm.main(["gen", "--length", "16"])
        assert rc == 0
        out = capsys.readouterr().out.strip().splitlines()
        assert len(out[0]) == 16

    def test_gen_no_symbols(self, capsys):
        pm.main(["gen", "--length", "30", "--no-symbols"])
        password = capsys.readouterr().out.strip().splitlines()[0]
        assert all(c in string.ascii_letters + string.digits for c in password)
