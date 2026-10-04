# libs knowledge base format (`data/libs.json`, `libs.user.json`)

`data/libs.json` ships with the skill; users add or override entries in `libs.user.json`
(`IPA_ANALYZER_HOME/libs.user.json` or `--libs-user PATH`). An entry with the same `id` replaces the shipped one.
A malformed file or entry only produces a warning (the entry is skipped).

```json
{ "version": 1, "categories": ["engine", "..."],
  "libs": [ { "id": "appsflyer", "name": "AppsFlyer", "vendor": "AppsFlyer", "category": "analytics",
              "purpose_zh": "...", "purpose_en": "...", "tags": ["analytics", "attribution", "tracking"],
              "homepage": "https://www.appsflyer.com",
              "match": { "framework": ["AppsFlyerLib"], "bundle": ["AppsFlyerLib_Privacy.bundle"],
                         "objc_prefix": ["AppsFlyerLib"], "namespace": ["AppsFlyerSDK"] },
              "sources": ["https://cocoapods.org/pods/AppsFlyerFramework"] } ] }
```
A bare list of entries is also accepted in the user file.

## Fields
| field | rule |
|---|---|
| `id` | unique, `[a-z0-9][a-z0-9_.-]*`; fingerprint / hotfix hits with the same id merge into the entry |
| `name`, `purpose_zh`, `purpose_en` | required, non-empty |
| `category` | `engine network ads analytics crash payment social push media security hotfix storage ui system other` |
| `tags` | privacy tags: `ads`, `analytics`, `attribution`, `tracking`, `social` (feed `privacy_tags`) |
| `merge_only` | true = no match rules; the entry only supplies name / purpose for ids reported by `engine.fingerprint` / `engine.unity.hotfix` |
| `sources` | URLs (podspec, upstream source, docs) that justify the rules; mandatory for shipped entries |

## `match` rules (all optional lists of strings)
| key | matched against | glob |
|---|---|---|
| `framework` | framework directory name (`Foo` for `Foo.framework`), `LC_LOAD_DYLIB` `.../Foo.framework/Foo`, Swift module `$s<len>Foo` in imported symbols | yes |
| `bundle` | resource bundle name (`Foo.bundle` or `Foo`) | yes |
| `dylib` | leaf of a bundled dylib path (`libfoo.dylib`) | yes |
| `file` | app-relative path (bare name = any directory), case-insensitive | yes |
| `objc_prefix` | ObjC class names of **decrypted** slices and imported `_OBJC_CLASS_$_<Name>` symbols (also readable in encrypted binaries) | prefix |
| `symbol_regex` | imported symbol names (regular expression) | regex |
| `string` | C strings of decrypted binaries (literal) | no |
| `namespace` | Unity il2cpp dump namespaces; token equals the namespace or a dotted ancestor | no |
| `plist_key` | top-level Info.plist keys | no |
| `url_scheme`, `query_scheme` | `CFBundleURLSchemes` / `LSApplicationQueriesSchemes` values | no |

A given `(field, token)` may belong to only one entry (checked by `tests/unit/libs/test_kb_schema.py`).

## Evidence and confidence
Independent evidence classes: framework directory, load command, bundled dylib, resource bundle, file, ObjC class,
imported symbol, Swift module, string, namespace, Info.plist key, URL scheme, hotfix stage, fingerprint stage.
Confidence = strongest class (0.55-0.80) + 0.08 per additional class, capped at 0.97.

## Quality bar
Accuracy over quantity. A rule goes in only if it can be checked against a public source: CocoaPods podspec
(`vendored_frameworks`, `module_name`, `resource_bundles`), the vendor's source tree / docs, or names seen in a real
package. Unverifiable tokens (for example closed-source class names) are left out rather than guessed.
Libraries that match nothing are reported as `unknown` with an empty purpose; look them up online and add
verified entries to `libs.user.json`.
