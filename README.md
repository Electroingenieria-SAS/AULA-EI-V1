# AULA EI V1

Versión operativa independiente de AULA EI basada en la última producción estable anterior al 21 de septiembre de 2026.

## Propósito

Este repositorio conserva la experiencia V1 para los usuarios mientras la nueva versión continúa su desarrollo en `Electroingenieria-SAS/AULA-EI`.

## Base

- Snapshot funcional: producción del 14/09/2026.
- Base histórica: `00c25a2b496a284682dd5cf17a40c360c13fc3c0`.
- Compatibilidad actual: sesión aislada y autenticación MFA/AAL2 al ingresar al módulo administrativo.
- Backend: Supabase institucional existente.

## Despliegue

La publicación se realiza mediante GitHub Actions y GitHub Pages desde `main`. El workflow ejecuta `node b.mjs`, genera `dist/` y publica exclusivamente ese artefacto.
