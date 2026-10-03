"""Reusable, dependency-free binary format parsers.

Standard library only; modules here never import other ipa_analyzer business modules.  They
parse, validate and probe -- they never decrypt, repair or execute anything.

* ``unityfs``        UnityFS AssetBundle header / BlocksInfo / streamed decompression / variant probes
* ``lz4``            bounded LZ4 block decoder and Unity LZMA decoder
* ``lua_bytecode``   Lua 5.1-5.5 and LuaJIT chunk headers with tamper signals
* ``lua_source``     lexical dialect inference for plain Lua source
* ``pe_cli``         PE + .NET metadata summary (assembly name, CLR version, refs, TypeDef count)
* ``magic_scan``     streaming multi-pattern signature scan (chunk-boundary safe)
* ``compress_sniff`` compression container sniffing (zlib/gzip/LZ4 frame/zstd/bzip2/xz/LZMA)

Submodules are imported explicitly by callers (``from ipa_analyzer.formats import unityfs``).
"""
