# Repository Übersicht
1. eBPF-Programm enthält die ausführbahren Nextflow Executables und die Python-Skripte zum Monitoring
2. nextflow-code enthält die modifizierte Variante vom Nextflow Code, Kompilieranleitung finden Sie dort unter README

# Vorraussetzungen
1. BCC Installation muss nach der Anweisung von [BCC](https://github.com/iovisor/bcc) erfolgen
2. Python muss sich mit der Version 3 unter /usr/bin/python3 befinden
3. Alle notwendigen Pakete für Python installieren (matplotlib, numpy, mplcursors, scipy)
   
# Ausführunganweisung
1. `cd eBPF-Programm`
    Nextflow dient als Referenz ohne Monitoring

2. Ausführen von "nextflow-22.10.0-all" als Superuser, restliche Argumente wie gewohnt mit dazu gehörigem Workflow
   
   `sudo ./nextflow-22.10.0-all run nf-core/mhcquant -profile test,docker --outdir mhcquant_out` wurde für diese Arbeit ausgeführt
   Weitere Parameter entnehmen Sie [Nextflow Dokumentation](https://www.nextflow.io/docs/latest/index.html)

3. Warten Sie, bis die abschließende Ausgabe nach NF-Terminierung erscheint. 
   In Abhängigkeit vom System kann diese Meldung sofort oder nach Verzögerung angezeigt werden.
   

# Ausgaben
- Matplotlib erzeugt 4 Fenster, eins für jede Metrik
- Interaktive Bedienung mit Zoom und Annotationen nur im Fenster der Graphen möglich
- 4 Bilder der Metriken werden automatisch ausgegeben
- Monitoring Skript terminiert nach schließen der 4 Fenster
