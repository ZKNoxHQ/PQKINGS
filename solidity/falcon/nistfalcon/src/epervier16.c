/*
 * Wrapper for implementing the NIST API for the PQC standardization
 * process.
 */

#include <stddef.h>
#include <string.h>	

#include "api.h"
#include "inner.h"

#include<stdio.h>
#define NONCELEN   40

/*
 * If stack usage is an issue, define TEMPALLOC to static in order to
 * allocate temporaries in the data section instead of the stack. This
 * would make the crypto_sign_keypair(), crypto_sign(), and
 * crypto_sign_open() functions not reentrant and not thread-safe, so
 * this should be done only for testing purposes.
 */
#define TEMPALLOC

int randombytes(unsigned char *x, unsigned long long xlen);

int
zknox_pk_epervier(unsigned char *pk)
{
	// Additional NTT for epervier
	// Hash is not computed here
	TEMPALLOC uint16_t h[512];
	size_t v;

	// Decode h
	 if (pk[0] != 0x00 + 9) {
		return -1;
	}
	if (Zf(modq_decode16)(h, 9, pk + 1, ZKNOX_CRYPTO_PUBLICKEYBYTES - 1)
		!= ZKNOX_CRYPTO_PUBLICKEYBYTES - 1)
	{
		return -1;
	}

	// NTT not in montgomery representation
	Zf(to_ntt)(h, 9);

	/*
	 * Re-encode public key.
	 */
	pk[0] = 0x00 + 9;
	v = Zf(modq_encode16)(pk + 1, ZKNOX_CRYPTO_PUBLICKEYBYTES - 1, h, 9);
	
	if (v != ZKNOX_CRYPTO_PUBLICKEYBYTES - 1) {
		return -1;
	}

	return 0;
}

int
zknox_crypto_sign_epervier(unsigned char *sm, unsigned long long *smlen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *sk)
{
	TEMPALLOC union {
		uint8_t b[72 * 512];
		uint64_t dummy_u64;
		fpr dummy_fpr;
	} tmp;
	TEMPALLOC int8_t f[512], g[512], F[512], G[512];
	TEMPALLOC union {
		uint16_t hm[512];
	} r;
	TEMPALLOC int16_t s1[512];
	TEMPALLOC int16_t s2[512];
	TEMPALLOC int16_t hint;

	TEMPALLOC unsigned char seed[48], nonce[NONCELEN];
	TEMPALLOC unsigned char esig[ZKNOX_CRYPTO_BYTES_EPERVIER - sizeof nonce - 2];
	TEMPALLOC inner_shake256_context sc;
	size_t u, v, sig_len, s2_len;
	/*
	 * Decode the private key.
	 */
	if (sk[0] != 0x50 + 9) {
		return -1;
	}
	u = 1;
	v = Zf(trim_i8_decode)(f, 9, Zf(max_fg_bits)[9],
		sk + u, CRYPTO_SECRETKEYBYTES - u);
	if (v == 0) {
		return -1;
	}
	u += v;
	v = Zf(trim_i8_decode)(g, 9, Zf(max_fg_bits)[9],
		sk + u, CRYPTO_SECRETKEYBYTES - u);
	if (v == 0) {
		return -1;
	}
	u += v;
	v = Zf(trim_i8_decode)(F, 9, Zf(max_FG_bits)[9],
		sk + u, CRYPTO_SECRETKEYBYTES - u);
	if (v == 0) {
		return -1;
	}
	u += v;
	if (u != CRYPTO_SECRETKEYBYTES) {
		return -1;
	}
	if (!Zf(complete_private)(G, f, g, F, 9, tmp.b)) {
		return -1;
	}

	/*
	 * Create a random nonce (40 bytes).
	 */
	randombytes(nonce, sizeof nonce);

	/*
	 * Hash message nonce + message into a vector.
	 */
	inner_shake256_init(&sc);
	inner_shake256_inject(&sc, nonce, sizeof nonce);
	inner_shake256_inject(&sc, m, mlen);
	inner_shake256_flip(&sc);
	Zf(hash_to_point_vartime)(&sc, r.hm, 9);


	/*
	 * Initialize a RNG.
	 */
	randombytes(seed, sizeof seed);
	inner_shake256_init(&sc);
	inner_shake256_inject(&sc, seed, sizeof seed);
	inner_shake256_flip(&sc);


	/*
	 * Compute the signature.
	 * s2 must be invertible.
	 */
 
	do {
		Zf(sign_dyn)(s2, &sc, f, g, F, G, r.hm, 9, tmp.b);
		memcpy(s1, tmp.b, 512 * sizeof *s1);
	} while (!Zf(is_invertible)(s2, 9, tmp.b));

	/*
	 * Encode the signature and bundle it with the message. Format is:
	 *   signature length     2 bytes, big-endian
	 *   nonce                40 bytes
	 *   message              mlen bytes
	 *   s1			          slen bytes
	 *   s2			          slen bytes
	 */

	esig[0] = 0x20 + 9;
	sig_len = Zf(comp_encode16)(esig + 1, 1024, s1, 9);
	if (sig_len == 0) {
		return -1;
	}
	sig_len ++;
	esig[sig_len] = 0x20 + 9;
	s2_len = Zf(comp_encode16)(esig + sig_len + 1, 1024, s2, 9);
	if (s2_len == 0) {
		return -1;
	}
	sig_len += s2_len;
	sig_len ++;

	// hint computation for Solidity: uint16_t = 2 bytes
	hint = Zf(hint_epervier)(s2, 9);
	sig_len +=2;

	memmove(sm + 2 + sizeof nonce, m, mlen);
	sm[0] = (unsigned char)(sig_len >> 8);
	sm[1] = (unsigned char)sig_len;
	memcpy(sm + 2, nonce, sizeof nonce);
	memcpy(sm + 2 + (sizeof nonce) + mlen, esig, sig_len-2);
	sm[2 + (sizeof nonce) + mlen + sig_len-2] = (unsigned char)(hint >> 8);
	sm[2 + (sizeof nonce) + mlen + sig_len-1] = (unsigned char)hint;
	*smlen = 2 + (sizeof nonce) + mlen + sig_len;
	return 0;
}

int
zknox_crypto_sign_open_epervier(unsigned char *m, unsigned long long *mlen,
	const unsigned char *sm, unsigned long long smlen,
	const unsigned char *pk)
{
	// NB: this function does not utilize the hint.
	// The hint is useful for the Solidity version.
	TEMPALLOC union {
		uint8_t b[2 * 512];
		uint64_t dummy_u64;
		fpr dummy_fpr;
	} tmp;
	const unsigned char *esig;
	TEMPALLOC uint16_t h[512], h2[512], hm[512];
	TEMPALLOC int16_t s1[512], s2[512];
	TEMPALLOC inner_shake256_context sc;
	size_t sig_len, msg_len;

	/*
	 * Decode public key.
	 */
	if (pk[0] != 0x00 + 9) {
		return -1;
	}
	if (Zf(modq_decode16)(h, 9, pk + 1, ZKNOX_CRYPTO_PUBLICKEYBYTES - 1)
		!= ZKNOX_CRYPTO_PUBLICKEYBYTES - 1)
	{
		return -1;
	}

	/*
	 * Find nonce, signature, message length.
	 */
	 if (smlen < 2 + NONCELEN) {
		return -1;
	}
	sig_len = ((size_t)sm[0] << 8) | (size_t)sm[1];
	if (sig_len > (smlen - 2 - NONCELEN)) {
		return -1;
	}
	msg_len = smlen - 2 - NONCELEN - sig_len;
	/*
	 * Decode signature.
	 */
	esig = sm + 2 + NONCELEN + msg_len;
	if (sig_len < 1 || esig[0] != 0x20 + 9 || esig[1025] != 0x20 + 9) {
		return -1;
	}

	if (Zf(comp_decode16)(s1, 9,
		esig + 1, 1024) != 1024)
	{
		return -1;
	}
	if (Zf(comp_decode16)(s2, 9,
		esig+1+1024+1, 1024) != 1024)
	{
		return -1;
	}
	
	/*
	 * Hash nonce +	 message into a vector.
	 */
	inner_shake256_init(&sc);
	inner_shake256_inject(&sc, sm + 2, NONCELEN + msg_len);
	inner_shake256_flip(&sc);
	Zf(hash_to_point_vartime)(&sc, hm, 9);

	if (!Zf(verify_recover_epervier)(h2, hm, s1, s2, 9, tmp.b)) {
		return -1;
	}
	// We check that the recovered public key matches with the input pk.
	// In epervier, we would implement pk = H(NTT(h)) in order to have a smaller pk.
	// Zf(to_ntt_monty)(h2, 9);
	for (uint16_t i = 0 ; i < 512 ; i++){
		if (h[i] != h2[i]) {
			return -1;
		}
	}

	/*
	 * Return plaintext.
	 */
	memmove(m, sm + 2 + NONCELEN, msg_len);
	*mlen = msg_len;
	return 0;
}
