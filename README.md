# Aplicatie-de-tip-port-scanner

Un port scanner este o aplicație software prin care putem explora rețeaua sau sistemul de calculatoare pentru a determina traficul care are loc, implicit disponibilitatea porturilor.

# Utilizare
Compilare: make

./myPortScanner   -h   <hostname/IP>  -p  <range porturi>  -T  <nr threaduri>  -s<scan type>
# Exemplu
./myPortScanner   -h   google.com  -p  80  -T  1  -sS

# Optiuni disponibile
-h   -  adresa ip/hostname__
-p   -  portul/range-ul de porturi pe care dorim sa le scanăm__
-T   -  numărul de thread-uri pe care dorim sa le folosim in scanare__
-v   -  verifică tipul de serviciu găsit pe port și tipul de protocol__

# Scanari disponibile
  TCP SYN Scan: -sS__
  TCP CONNECT Scan: -sT__
  UDP Scan: -sU__
  TCP FIN Scan: -sF__
  TCP NULL Scan: -sN__
  TCP XMAS Scan: -sX__
  TCP ACK Scan: -sA__
  TCP WINDOW Scan: -sW__
  CUSTOM Scan Types with flags: -sC <SYNACKURGFINPSHRST>__

  # Rezultate scanare
Open 	- rețeaua țintă acceptă conexiuni sau pachete și a răspuns cu un pachet care arată că este în ascultare__
Closed 	- rețeaua a primit cererea, dar nu rulează niciun serviciu pe acel port__
Filtered 	- un pachet de cerere a fost trimis, dar gazda nu a răspuns și nu este în ascultare__
