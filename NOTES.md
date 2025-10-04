Digit-decomposition (base-
𝑤
w) of the inner product

Instead of searching a large 
𝑆
S once, recover 
⟨
𝑥
,
𝑦
⟩
⟨x,y⟩ digit-by-digit in a small base.

Pick 
𝑤
=
2
8
w=2
8
 (or 
2
10
2
10
). Represent 
⟨
𝑥
,
𝑦
⟩
=
∑
𝑘
=
0
𝑡
−
1
𝑑
𝑘
𝑤
𝑘
⟨x,y⟩=∑
k=0
t−1
	​

d
k
	​

w
k
 with 
𝑑
𝑘
∈
{
0
,
…
,
𝑤
−
1
}
d
k
	​

∈{0,…,w−1}.

Prepare 
𝑡
t “scaled” keys so each decryption round recovers one digit from a tiny set of size 
𝑤
w (fast flat table or BSGS).

Parallelize the 
𝑡
t rounds across your 32 ciphertexts; overall wall-time drops because each lookup is cheap and very cache-friendly.

This trick is standard in FE implementations when exact recovery over a large range is expensive.


4) Algebraic preprocessing of the plaintext vectors

You can lower encryption/decryption constants without touching security:

Change of basis / whitening: pre-multiply all plaintext vectors by a public, invertible integer matrix 
𝑇
T that (approximately) sparsifies them (e.g., PCA/whitening then quantize). Because inner product is linear, you can absorb 
𝑇
T into setup (into 
𝐵
⋆
B
⋆
) once and for all. Sparsity ⇒ faster multi-exp on the encryptor and smaller effective range.

Bucketing by norm: store a public coarse norm bucket per ciphertext. At query time, eliminate buckets whose maximum possible dot product (Cauchy–Schwarz upper bound) is below the current best—so you decrypt far fewer than 32 in the common case. This is a correctness-preserving filter; it doesn’t reveal the exact value.

Product quantization / codebooks: approximate each 
𝑦
y with a short code made of small subvectors and keep the exact ciphertext as the “tie-breaker.” First pass: compare the codes (fast, possibly in the clear if acceptable). Second pass: only decrypt a few near-winners.

These are common IR-style preprocessors; they don’t alter FE semantics but reduce how often you pay the cryptographic cost.