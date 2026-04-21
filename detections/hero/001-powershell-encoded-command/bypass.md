# Known Bypass Considerations

- Attackers can avoid `-enc` and instead stage script content by alternate loaders.
- Alternate binaries can launch PowerShell with obfuscated arguments not containing explicit encoded markers.
- Script block logging disablement can reduce context for follow-on investigations.

This file is intentionally explicit to preserve honest coverage boundaries.

