"""Unity semantic layer for the ``engine.unity`` stage (WP5).

* ``version``  Unity editor version from SerializedFile headers / bundle headers / binary strings
* ``metadata`` ``global-metadata.dat`` layout, consistency and encryption heuristics
* ``bundles``  AssetBundle discovery, classification, deep checks and aggregation
* ``mono``     managed assembly (PE/CLI) validity for the Mono backend
* ``precheck`` il2cpp dump pre-conditions

Parsing of UnityFS / LZ4 / PE-CLI lives in ``ipa_analyzer.formats``; nothing here decrypts anything.
"""
