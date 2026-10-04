# Egret and LayaAir (WP7b checkers `egret`, `laya`)

The official documentation could not be fetched in this environment (network search returned nothing usable), so **every file name below is UNVERIFIED** (memory of published projects) and used only as a marker; no verdict depends on a single name.

* Egret markers: `resource/*.res.json` (keys `groups`, `resources`), `resource/*.thm.json`, `*.exml`, `manifest.json` (`initial` / `game` lists), `egret(.web)(.min).js`, `libs/modules/egret/`, `main(.min).js`. Version regex `engineVersion = "x.y.z"` in `egret*.js` (U).
* Laya markers: `laya.core(.min).js` and other `laya.*.js`, `.atlas` (JSON), `.lh .lmat .ls .lani .ltc .lav .lm`, `fileconfig.json`, `conch` runtime directory, `libs/laya*`. Version regex `Laya.version = "x.y.z"` (U).

Judgement (both): scripts are every non-SDK `.js/.jsc`; plain or minified text -> `no` (minified / obfuscated code is still text); a script that is neither text nor a known container -> `suspected`. Resources: files whose extension names a standard format are identified by the inventory magic; unidentified files with a custom 4-byte header or high entropy -> `suspected`; clusters of such files are reported in `wrapper_clusters`. Compression and minification are not encryption. Native runtimes (Egret native, Laya conch) may pack resources into formats not covered here: reported as `unknown` / `suspected`, never as `no` without evidence.
