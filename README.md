### **Présentation des Modules de l'Application**

L'application est structurée en plusieurs modules principaux :



1. **Module de Capture de Paquets**
    * Utilise Pcap4J pour capturer le trafic réseau en temps réel.
    * Filtre et analyse les paquets selon différents critères, comme l'adresse IP source ou destination.
2. **Module d'Analyse des Intrusions**
    * Implémente des algorithmes de détection pour identifier des comportements suspects, tels que :
        * **Attaque SYN Flood** : Analyse des connexions TCP pour détecter les tentatives de surcharge du serveur.
        * **Transferts de Fichiers Massifs** : Surveillance des transferts supérieurs à un seuil défini (par exemple, 10 GB).
        * **Scan de Ports** : Identification des balayages d'adresses et des ouvertures rapides de ports.
3. **Module de Gestion des Alertes**
    * Génère des alertes en cas de détection d'une activité suspecte.
    * Stocke les alertes pour une consultation ultérieure.
4. **Module d'Interface Utilisateur**
    * Permet la visualisation des informations analysées dans une interface claire et interactive.


### **Algorithmes ou Méthodes Spécifiques**


#### **Détection SYN Flood**



* Analyse des paquets TCP pour compter les requêtes SYN sans réponse ACK dans un délai donné.
* Utilisation de seuils pour identifier les anomalies (ex. : plus de 10000 SYN/s sans ACK).


#### **Détection de Transfert de Fichier Massif**



* Surveillance des sessions TCP pour mesurer le volume de données transférées.
* Déclenchement d'alertes si un seuil (par ex. : 10 GB) est atteint en un temps réduit.


#### **Scan de Ports**



* Suivi des tentatives de connexion sur plusieurs ports en un court laps de temps.
* Détection des comportements de balayage suspect.


## 


## **Interface Utilisateur**

L'application JavaFX offre une interface intuitive composée de plusieurs onglets :


### **Tab Dashboard**



* Visualisation d'un **PieChart** indiquant les pourcentages des protocoles détectés (TCP, UDP, ICMP, etc.).

![image](https://github.com/user-attachments/assets/86bafbc8-75ec-4c30-bdc4-224923bf1820)


### 


### **Tab Sniffer**



* Permet de sélectionner une interface réseau pour débuter la capture des paquets.
* Affiche les paquets capturés en temps réel avec leurs détails (IP source, IP destination, taille, etc.).

![image](https://github.com/user-attachments/assets/3e53c353-4b0e-42d3-b511-fcbcc10daa41)


### **Tab Active Users**



* Liste les utilisateurs actifs sur le réseau.
* Affiche des informations comme les adresses MAC.

![image](https://github.com/user-attachments/assets/3a0cc8e8-c86a-4e80-81c1-1dc7e6906c66)


### **Tab Alerts**



* Présente les alertes générées par le module d'analyse des intrusions.
* Affiche des détails comme le type d'alerte, l'adresse IP concernée, et l'heure de détection.

![image](https://github.com/user-attachments/assets/b2aeca63-e070-48b4-b462-b5a7532009f6)


Chaque onglet est conçu pour fournir des informations claires et permettre une navigation fluide entre les fonctionnalités. Si besoin, des captures d'écran ou des diagrammes peuvent être insérés pour illustrer l'interface utilisateur.
