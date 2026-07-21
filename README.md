<h1 align="center">Digital Forensics · DFIR</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Volatility-1a1a2e?style=flat-square" />
  <img src="https://img.shields.io/badge/FTK%20Imager-4B5563?style=flat-square" />
  <img src="https://img.shields.io/badge/Cadena%20de%20Custodia-E3B341?style=flat-square" />
  <img src="https://img.shields.io/badge/NIST%20SP%20800--86-58A6FF?style=flat-square" />
</p>

---

## Sobre este módulo

Investigación forense y respuesta a incidentes (**DFIR**): adquirir, preservar y analizar evidencia digital de forma que sea **admisible en un juicio**. El rigor metodológico es tan importante como el hallazgo técnico.

**Temas cubiertos:** las 4 fases del análisis forense · adquisición (write blockers, hashing) · sistemas de ficheros NTFS · timestamps y timestomping · análisis de RAM con Volatility 3 · artefactos de Windows (registro, prefetch, event logs) · forense en Linux · cadena de custodia.

---

## Proceso forense

Cuatro fases secuenciales atravesadas por la **cadena de custodia**: sin ella, la prueba es inadmisible. La regla de oro: nunca se trabaja sobre el original, siempre sobre una copia verificada por hash.

![Proceso DFIR](proceso-dfir.png)

---

## Práctica

Análisis forense completo de una imagen de disco Windows comprometida (CTF **27/27**):

- **Adquisición** con verificación de integridad por hash (MD5/SHA-256).
- **Análisis de disco** — identificación del equipo, artefactos NTFS, timeline de eventos, ficheros maliciosos (WMIBackdoor.ps1, xCmd, TeamViewer como backdoor).
- **Análisis de RAM** con Volatility 3 — procesos ocultos, código inyectado (malfind), extracción de credenciales (hashdump), detección de backdoor PowerShell.
- **Correlación** de disco + memoria + logs (Hayabusa) para reconstruir el ataque completo.

---

## Stack

`Volatility 3` · `FTK Imager` · `Registry Explorer` · `PECmd` · `EvtxECmd` · `Hayabusa` · `Mimikatz` · `ExifTool`

---

## Módulos relacionados

- **[Análisis de Malware](https://github.com/juanmalbran/analisis-de-malware)** — YARA, IOCs y análisis de artefactos: disciplinas fuertemente solapadas.
- **[Blue Team](https://github.com/juanmalbran/blue-team)** — el SIEM y los logs del SOC son la fuente de evidencia para una investigación DFIR.

---

<div align="center">
  <sub>Parte del portfolio de <a href="https://github.com/juanmalbran">Juan Malbrán · M4LBYTE</a></sub>
</div>
