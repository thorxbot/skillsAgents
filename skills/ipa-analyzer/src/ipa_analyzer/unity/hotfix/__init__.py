"""Unity hot-update analysis (WP5b): which mechanism, where the scripts live, in what format.

Modules: ``detect`` (rules + framework merge), ``metadata_strings`` (identifier pool scan, no dumper),
``native_signals`` (symbols / Lua version strings in Mach-O code), ``storage`` (loose files, sampled
bundles, serialized files), ``lua`` / ``csharp`` / ``js`` (per-language profiles), ``resource_update``
(Addressables, YooAsset, manifests, CDN hosts) and ``summary``.  The stage lives in
``ipa_analyzer.analyzers.unity_hotfix``.  Nothing here executes, decrypts or repairs content.
"""
