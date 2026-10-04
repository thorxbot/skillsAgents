# In-house engine playbook (analysis starting points)

Use when `engine.custom` is `yes` / `suspected` (or `engine.primary` is unknown and the profile looks game-like). This is an
analysis method only: it never involves breaking protection, and a FairPlay-encrypted binary must be replaced by a decrypted
IPA supplied by the user.

## 1. Read the profile first
`engine_details.fingerprint`: render API, script VMs, physics / audio middleware, asset formats, containers, host shape.
`engine_details.detect.custom`: per-condition table (`conditions`), evidence, `deviations`, `next_steps`.
A pure native app that merely uses Metal is not a custom engine; the verdict needs render + game signal + >= 2 of
{own script VM, custom container, physics library, C++-heavy code}.

## 2. Binary
* Check `macho` encryption first. Encrypted -> request a decrypted IPA; continue with files only.
* Strings worth searching: Lua (`bad argument #%d to '%s'`, `$LuaVersion`), LuaJIT (`LuaJIT 2.`), QuickJS / Duktape API names,
  `PYTHONHOME`, engine banners, `res://`-style path prefixes, error messages that name a loader.
* Symbols: C API names of the VM (`luaL_newstate`, `JS_NewRuntime`, `Py_Initialize`), physics namespaces (`b2World`, `btRigid*`).
* Stripped release builds keep only imports and strings: look at imported ObjC classes (`CADisplayLink`, `MTKView`, `GCController`).

## 3. Scripts
* Lua bytecode header: ESC `Lua` + version byte (0x51 = 5.1 ... 0x54 = 5.4); ESC `LJ` = LuaJIT. A header that does not match the
  runtime version found in the binary points to a customised build.
* Embedded Python: `.pyc` header = 2-byte magic number + `\r\n`; a non-standard header suggests a customised interpreter (shuffled opcodes);
  standard disassemblers will not work (suspected only).
* High-entropy script files without a known header: a custom cipher or compression; look for the loader function in the binary.

## 4. Containers
`engine_details.fingerprint.containers[*].extra`:
* `header.offset_table` - monotonic offsets (stride = words per record). The table start and stride tell you the record layout.
* `header.size_field` - a header word equal to the file size = self-describing header.
* `streams` / `compression` - compression streams found (zlib checked by checksum). Compressed data is not encrypted data.
* `xor_hypothesis` - header equals a well-known magic XOR a short key (a hypothesis; the file is not decoded).
* `header-cluster:<TAG>` entries: thousands of small files sharing a custom header. Compare one small and one large member: look at
  the bytes after the header (`payload.standard_after_header`), entropy and size field. Do not infer a vendor from the tag.

## 5. Shaders / assets
No `.metallib` and no shader sources usually means runtime-compiled source strings or a custom binary format: search the binary for
`#include` / `precision mediump` / `kernel void` fragments.

## 6. Record what you confirm
Write the confirmed traits to `<user data dir>/engines.user.d/<id>.json` (see `engines-detection.md`), with `sources` describing how
each was verified and `"unverified": true` for guesses. The next run identifies the engine directly.
