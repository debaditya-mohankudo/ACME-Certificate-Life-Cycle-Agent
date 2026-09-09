"""
acme_account_setup node — register or retrieve an ACME account.

RFC 8555 §7.3: POST /newAccount with termsOfServiceAgreed=true registers a new
account; the CA returns 201 Created with the account URL in the Location header.
RFC 8555 §7.3.1: POST /newAccount with onlyReturnExisting=true looks up an
existing account without creating one; returns 200 OK if found, 400 if not.
EAB (RFC 8555 §7.3.4) is injected transparently by the CA client subclass when required
(DigiCert, ZeroSSL, Sectigo).

Security note: the account key is never stored in AgentState (which could
leak into LangSmith traces).  Instead the key path is stored in state and
the key is loaded from disk each time it is needed.
"""
from __future__ import annotations

from acme import jws as jwslib
from acme.client import make_client
from agent.state import AgentState

from logger import logger


class AcmeAccountSetupNode:
    """Callable account-setup node implementation."""

    def __call__(self, state: AgentState) -> dict:
        return self.run(state)

    def run(self, state: AgentState) -> dict:
        """
        Ensures an ACME account exists and state["acme_account_url"] is set.

        If an account key already exists at account_key_path:
          - Attempts to look up the existing account (POST /newAccount onlyReturnExisting)
        If no key exists:
          - Generates a new key, saves it, and registers a new account (with EAB)

        Returns updates to: acme_account_url, current_nonce
        """
        account_key_path = state["account_key_path"]

        client = make_client()

        directory = client.get_directory()
        nonce = client.get_nonce(directory)

        if jwslib.account_key_exists(account_key_path):
            logger.info("Loading existing account key from %s", account_key_path)
            account_key = jwslib.load_account_key(account_key_path)

            account_url, new_nonce = client.lookup_account(account_key, nonce, directory)
            if account_url:
                logger.info("Retrieved existing ACME account: %s", account_url)
                return {
                    "acme_account_url": account_url,
                    "current_nonce": new_nonce or nonce,
                }
            logger.warning("Account key exists but account not found — re-registering")
        else:
            logger.info("No account key found — generating new key at %s", account_key_path)
            account_key = jwslib.generate_account_key()
            jwslib.save_account_key(account_key, account_key_path)

        account_url, new_nonce = client.create_account(
            account_key=account_key,
            nonce=nonce,
            directory=directory,
        )
        logger.info("Registered new ACME account: %s", account_url)

        return {
            "acme_account_url": account_url,
            "current_nonce": new_nonce,
        }


def acme_account_setup(state: AgentState) -> dict:
    """Compatibility wrapper delegating to `AcmeAccountSetupNode`."""
    return AcmeAccountSetupNode().run(state)
