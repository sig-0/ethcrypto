## NOTICE

This source code was forked from the [`cloudflare/bn256`](https://github.com/cloudflare/bn256) package, on
the [`lattices`](https://github.com/cloudflare/bn256/tree/lattices) branch
at [this](https://github.com/cloudflare/bn256/commit/be78db46651cd48a5adfcfaf61384112e3562613) commit.

This notice will detail exact changes made to the original source code, in order to preserve history.
The fork retains the exact same license constraints and requirements as the original repository.

### Changes applied

From the `master` branch on the [`cloudflare/bn256`](https://github.com/cloudflare/bn256) repository:

- https://github.com/cloudflare/bn256/commit/c6407b1599b81973eded15cf165feb0559c17bd7
- https://github.com/cloudflare/bn256/commit/673829d98a2d5240c951e3f477b025406cb44e80
- https://github.com/cloudflare/bn256/commit/33e0c56ab44707ef8c5d0e9b2bff91d2a64b13ce
- https://github.com/cloudflare/bn256/commit/7e9328474f896e6469c58b3bdcfaacf45a3f58c9
- https://github.com/cloudflare/bn256/commit/806123b6159942fb53397cbb3fbf58067ddc8ba6
- https://github.com/cloudflare/bn256/commit/9bd9f73a0273ed2f42707ed13b3e36d38baa2a49
- https://github.com/cloudflare/bn256/commit/66a4f6353b47b94f61ac466b3f21b28adb76ae29

From
the [`go-ethereum/crypto/bn256/cloudflare`](https://github.com/ethereum/go-ethereum/tree/master/crypto/bn256/cloudflare)
package, changes relating to [EIP-196](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-196.md)
and [EIP-197](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-197.md), which change specific params
of the library, making it incompatible with the original paper.