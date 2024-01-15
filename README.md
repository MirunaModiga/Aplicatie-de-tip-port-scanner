# Aplicatie-de-tip-port-scanner

Un port scanner este o aplicație software prin care putem explora rețeaua sau sistemul de calculatoare pentru a determina traficul care are loc, implicit disponibilitatea porturilor.

# Utilizare
Compilare: make

./myPortScanner   -h   <hostname/IP>  -p  <range porturi>  -T  <nr threaduri>  -s<scan type>
# Exemplu
./myPortScanner   -h   google.com  -p  80  -T  1  -sS

# Optiuni disponibile
-h   -  adresa ip/hostname\
-p   -  portul/range-ul de porturi pe care dorim sa le scanăm\
-T   -  numărul de thread-uri pe care dorim sa le folosim in scanare\
-v   -  verifică tipul de serviciu găsit pe port și tipul de protocol\

# Scanari disponibile
  TCP SYN Scan: -sS\
  TCP CONNECT Scan: -sT\
  UDP Scan: -sU\
  TCP FIN Scan: -sF\
  TCP NULL Scan: -sN\
  TCP XMAS Scan: -sX\
  TCP ACK Scan: -sA\
  TCP WINDOW Scan: -sW\
  CUSTOM Scan Types with flags: -sC <SYNACKURGFINPSHRST>\
  
  # Rezultate scanare
Open 	- rețeaua țintă acceptă conexiuni sau pachete și a răspuns cu un pachet care arată că este în ascultare\
Closed 	- rețeaua a primit cererea, dar nu rulează niciun serviciu pe acel port\
Filtered 	- un pachet de cerere a fost trimis, dar gazda nu a răspuns și nu este în ascultare\
