"""Small format sniffers / parsers and shared helpers used by the engine checkers (WP7b).

Checkers never import each other; whatever they share lives here.  Nothing in this package
decrypts, repairs or executes anything: it only reads headers and reports what it saw.

* ``common``       file index over the inventory, bounded reads, blob classification, finding helpers
* ``lua_profile``  Lua version profile (same shape as ``engine.unity.hotfix`` ``lua``)
* ``jsc``          Cocos ``.jsc`` script blobs
* ``hermes``       Hermes bytecode header
* ``pak_ue``       Unreal ``.pak`` footer and IoStore ``.utoc`` header
* ``pck_godot``    Godot ``.pck`` header / directory, ``.gdc`` / ``.gde`` markers
* ``xxtea_hint``   script-sign prefix and size-structure hints for XXTEA-style script protection
* ``plist_atlas``  Cocos / TexturePacker plist classification
"""
