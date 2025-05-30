DIRSIGNER = 'python-ref'
PYTHON=python-ref/myenv/bin/python
CORES := $(shell grep -c ^processor /proc/cpuinfo)

# INSTALL

install: install_signer install_verifier

install_signer:
	make -C $(DIRSIGNER) install

install_verifier:
	foundryup
	forge install OpenZeppelin/openzeppelin-contracts-upgradeable --no-commit
	forge install OpenZeppelin/openzeppelin-contracts --no-commit

# GENERATION OF TEST VECTORS

gen_test_vectors:
	make -C $(DIRSIGNER) generate_test_vectors


# TESTS

test: test_signer test_verifier test_onchain

test_slow: test_signer test_verifier_slow test_onchain

test_signer:
	make -C $(DIRSIGNER) test

test_verifier:
	FOUNDRY_PROFILE=lite forge test -vv

test_verifier_slow:
	forge test -j$(CORES) -vv

test_onchain:
	# Generate public and private keys, sign a message, and verify it on-chain using FALCON
	$(PYTHON) python-ref/sign_cli.py genkeys --version='falcon'
	$(PYTHON) python-ref/sign_cli.py sign --privkey='private_key.pem' --data=0123
	$(PYTHON) python-ref/sign_cli.py verifyonchain --pubkey='public_key.pem' --data=0123 --signature='sig' --contractaddress='0xD088Ede58BD1736477d66d114D842bDE279A41Fa' --rpc='https://sepolia.optimism.io'

	# Generate public and private keys, sign a message, and verify it on-chain using ETHFALCON
	$(PYTHON) python-ref/sign_cli.py genkeys --version='ethfalcon'
	$(PYTHON) python-ref/sign_cli.py sign --privkey='private_key.pem' --data=4567
	$(PYTHON) python-ref/sign_cli.py verifyonchain --pubkey='public_key.pem' --data=4567 --signature='sig' --contractaddress='0x2F27b854B719921f03f30d1e5d0aE8e0aE7f96cA' --rpc='https://sepolia.optimism.io'

	# Generate public and private keys, sign a message, and verify it on-chain using EPERVIER
	$(PYTHON) python-ref/sign_cli.py genkeys --version='epervier'
	$(PYTHON) python-ref/sign_cli.py sign --privkey='private_key.pem' --data=89ab
	$(PYTHON) python-ref/sign_cli.py verifyonchain --pubkey='public_key.pem' --data=89ab --signature='sig' --contractaddress='0x5ab1d6db02f48bad63cbef5d51c534A76aEB824B' --rpc='https://sepolia.optimism.io'

	