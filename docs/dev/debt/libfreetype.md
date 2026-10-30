# libfreetype technical debt

### Callable exports

- [Callable exports](../../../core/libs/prx/libfreetype/Export.cpp) - five callable NIDs appear in a 3.20-labelled `libfreetype` image and a later 13.60-labelled `libSceVshFreeType` image. The images have different module and library identities; matching NIDs do not establish forwarding or equivalent behavior. Neither version label is authenticated. Names, signatures and behavior are unknown; these declarations throw and implement no runtime functionality.
