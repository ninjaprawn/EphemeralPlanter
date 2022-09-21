# EphemeralPlanter
Dig a hole in your DLL and watch marvelous things grow

This is a project that digs a cave in a target DLL, putting some code that will manually load another DLL using low level APIs. The function in the payload will then run, doing whatever magic it needs to. It can also revert the original DLL code in memory to fool basic memory scanners.

This may be useful for anti-cheats :)
