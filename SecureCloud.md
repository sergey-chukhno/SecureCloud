[= La Plateforme 

La grande école du numérique pour tous 







<!-- Start of picture text -->
’ i ie ; ‘ % a % :<br>oeie ; re Or eeee Lemg —1&5; « " : » a, A<br><!-- End of picture text -->



<!-- Start of picture text -->
= La Plateforme<br><!-- End of picture text -->



= La Plateforme 



Il vous montre les spécifications qu'il a rédigées : 

###### **"SECURECLOUD - Communications Professionnelles Sécurisées"** 

_"J'ai le financement de démarrage. J'ai des bureaux avec vue sur la Méditerranée. Il me faut maintenant l'équipe technique capable de concrétiser cette vision. Le marché nous attend : entreprises sensibles, ONG, journalistes d'investigation. Vous voulez relever le défi ?"_ 

L'aventure technique commence. 

# **Contexte** 



Les entreprises et les journalistes ont besoin de confidentialité absolue. WhatsApp et Telegram, c'est bien pour les particuliers, mais insuffisant pour les enjeux professionnels critiques. Nous allons donc créer un écosystème complet : messagerie sécurisée, partage de fichiers chiffré, infrastructure auto-déployable 

# **Cahier des charges fonctionnel** 

## **Vision Produit** 

Développer une plateforme de communication sécurisée de niveau professionnel, résistante à toutes les formes d'interception et d'espionnage. 

## **Segments Cibles** 



**_** 2 



- **Journalisme d'investigation** : Protection des sources et documents sensibles 

- **ONG internationales** : Communications sécurisées en zones hostiles 

- **Entreprises sensibles** : Finance, santé, défense 

- **Administrations** : Souveraineté numérique et conformité 

## **Analyse Concurrentielle** 

###### **Signal** 

- Chiffrement E2E éprouvé 

- Interface peu professionnelle, pas de gestion d'entreprise 

###### **Slack Enterprise** 

- Interface moderne, adoption massive 

- Slack peut lire tous les messages, pas de chiffrement E2E 

###### **Microsoft Teams** 

- Intégration entreprise, support 24/7 

- ❌ Microsoft peut accéder aux données, surveillance gouvernementale 

**Notre avantage** : Sécurité absolue avec expérience utilisateur professionnelle. 

# **SPÉCIFICATIONS FONCTIONNELLES DÉTAILLÉES** 

### **L'Incident qui Redéfinit Tout** 

_Jour 3, 14h30, bureaux SecureCloud_ 

Thomas entre dans le bureau, téléphone à la main. Par la baie vitrée, on aperçoit les ferries qui partent vers la Corse. 

_"Appel urgent : Médecins Sans Frontières nous contacte. Ils ont 45 000 volontaires dans 70 pays, certains en zones de conflit où leurs communications sont surveillées. Actuellement, ils utilisent WhatsApp et Gmail pour coordonner leurs missions."_ 



**_** 3 





<!-- Start of picture text -->
e meaveugle<br>LA SS eLA<br>clé Clé<br>Secréte secrete<br><!-- End of picture text -->



<!-- Start of picture text -->
= La Plateforme<br><!-- End of picture text -->



= La Plateforme 



_"Le serveur ne voit JAMAIS le contenu. Il ne fait que router des paquets chiffrés."_ 

###### **Justification Technique C++** 

Thomas explique l'architecture : 

_"La messagerie, c'est le cœur du système. 10 000 messages par seconde en pic de charge, temps réel critique, zéro tolérance à la panne. Avec C++, on a le contrôle total : gestion mémoire optimisée, threads natifs, performance prédictible."_ 

###### **Gestion Avancée des Conversations** 

- Recherche dans l'historique (indexation chiffrée locale) 

- Threads de conversation pour organisation 

- Statuts de présence sécurisés 

#### **<u>Module 2 : Partage de fichiers sécurisé</u>** 

Thomas sort des documents confidentiels… 

_"MSF manipule des téraoctets de données médicales sensibles. Avec C++, on peut implémenter un système de fichiers chiffré ultra-performant, sans dépendre de solutions cloud externes."_ 

##### **<u>Story Utilisateur Principale</u>** 

**_En tant que_** _responsable médical MSF_ **_Je veux_** _partager des dossiers patients avec d'autres centres_ **_Afin de_** _coordonner les soins tout en respectant la confidentialité médicale_ 

##### **<u>Justification C++</u>** 

_"Gestion de fichiers = I/O intensif, compression, chiffrement streaming. C++ nous donne la performance nécessaire pour chiffrer des téraoctets sans ralentir l'interface utilisateur."_ 



**_** 5 



msi <I File operations <7 Streaming encryption <I Data compression <I Encrypted filesystem 



<!-- Start of picture text -->
= La Plateforme<br><!-- End of picture text -->



= La Plateforme 



" _Vous savez combien de breaches de sécurité sont dues à des authentifications faibles ? 81% ! Et coûtent en moyenne 4.45 millions de dollars. MSF ne peut pas se permettre une seule faille._ " 

##### **<u>Story Utilisateur Principale</u>** 

**_En tant qu'_** _administrateur système MSF_ **_Je veux_** _gérer centralement les accès de 45 000 utilisateurs_ **_Afin de_** _garantir la sécurité sans impacter les performances_ 

###### **<u>API REST Centralisée pour Tous les Services</u>** 

Thomas ouvre l'interface de développement 

_"Notre microservice Auth expose une API REST que tous les autres services consomment. Chaque endpoint est optimisé pour un cas d'usage spécifique."_ 

###### **<u>Exemples d’Endpoints Principaux du Microservice</u>** 

**POST** /auth/login : Authentification initiale avec vérification multi-facteurs 

**POST** /auth/refresh : Renouvellement de token JWT avec validation continue 

**GET** /auth/validate : Validation rapide de token (cache optimisé) 

**POST** /auth/permissions : Vérification des droits pour action spécifique 

**POST** /auth/revoke : Révocation immédiate de tous les tokens utilisateur 

##### **<u>Justification C++</u>** 

_Thomas trace un comparatif performance au tableau_ 



**_** 7 



##### BENCHMARK AUTHENTIFICATION (1000 logins/seconde) 

Node.js bcrypt 



<!-- Start of picture text -->
C++ bcrypt (OpenSSL)<br><!-- End of picture text -->

850ms response VS 280MB RAM usage 85% CPU usage GC pauses 

45ms response 12MB RAM usage 23% CPU usage Zero GC overhead 





<!-- Start of picture text -->
[= La Plateforme<br><!-- End of picture text -->



[= La Plateforme 



## WEB APP vs QT NATIVE 

Web (Electron/React) 

500MB+ RAM usage Startup : 5-10 secondes Chrome dependency JavaScript vulnerabilities VS Réseau requis pour UI Look alien sur chaque OS 

Qt Native < SOMB RAM usage Startup : < 2 secondes Zéro dépendance externe Type safety C++ Interface 100% locale Look natif par plateforme 



<!-- Start of picture text -->
= La Plateforme<br><!-- End of picture text -->



= La Plateforme 





<!-- Start of picture text -->
a JWT ValidationAPI Gateway + Routing my<br>Messagin<br>Service<br>Inter-Process<br>Communication<br><!-- End of picture text -->



<!-- Start of picture text -->
= La Plateforme<br><!-- End of picture text -->



= La Plateforme 



_"Pas de HTTP entre services, c'est trop lent. Named pipes sous Windows, domain sockets sous Linux. Shared memory pour les gros transferts de données. Performance native."_ 

##### **<u>Exemple d'Interaction Complexe</u>** 

Utilisateur envoie fichier dans chat : 

1. Qt Interface → Messaging Service (nouveau message) 

- → 

- 2. Messaging Auth Service (vérification permissions) 

- → 

- 3. Messaging Files Service (upload fichier) 

4. Files → Audit Service (event "file_uploaded") 

5. Audit → Qt Interface (notification admin si gros fichier) 

# **Stratégie de tests généralisée** 

Thomas efface le tableau et écrit en gros : "MICROSERVICES = COMPLEXITÉ × 5 = TESTS × 10" 

"Écoutez-moi bien. Tester un monolithe, c'est compliqué. Tester 5 microservices qui communiquent entre eux, c'est un cauchemar. Mais MSF nous fait confiance pour protéger des vies humaines. Chaque service, chaque interaction, chaque scénario doit être testé à 100%." 

Il dessine l'architecture complète avec les points de défaillance possibles. 



**_** 11 



<!-- Start of picture text -->
CLIENT QT<br>@ Ul bugs, crashes, memory leaks<br>@Network timeouts, protocol errors<br>@Routing failures, rate limiting bugs<br>a API GATEWAY<br>MSG SVC Auth SVC Deploy SVC Files SVC Audit SVC<br>® Msg loss @Auth Fail @Ops crash @File corrupt @Log loss<br>@ Database“" connection loss<br>Database Cluster<br><!-- End of picture text -->



<!-- Start of picture text -->
[= La Plateforme<br><!-- End of picture text -->



[= La Plateforme 



#### **<u>Module 5 : Déploiement CI/CD avec Docker</u>** 

Thomas se tourne vers l'écran et ouvre GitLab 

_"Dernière étape cruciale : automatiser le déploiement. MSF ne peut pas se permettre des déploiements manuels avec des scp et des prières. Chaque commit doit déclencher une pipeline complète : build, test, deploy automatique."_ 

Il vous montre un schéma simple au tableau. 

_→ → "L'objectif est simple : git push 5 minutes plus tard SecureCloud est déployé et opérationnel. Docker + CI/CD, c'est tout. Mais fait correctement."_ 

##### **<u>Problèmes du Déploiement Manuel MSF</u>** 

- **_Temps_** _: 3 jours pour déployer sur tous les serveurs_ 

- **_Erreurs_** _: 40% des déploiements échouent_ 

- **_Inconsistance_** _: Versions différentes selon les pays_ 

- **_Rollback_** _: Impossible de revenir en arrière rapidement_ 

- **_Documentation_** _: Procédures perdues/obsolètes_ 

##### **<u>Story Utilisateur Principale</u>** 

**_En tant que_** _développeur SecureCloud_ 

**_Je veux_** _déployer automatiquement après une action définie_ **_Afin de_** _livrer facilement et sans erreurs_ 

##### **<u>Étapes de la Pipeline</u>** 

- **Build Stage** : Compilation des 5 microservices C++ 

- **Test Stage** : Tests unitaires + intégration automatiques 

- **Package Stage** : Création des images Docker optimisées 

- **Deploy Stage** : Déploiement sur l'environnement cible 

- **Verify Stage** : Tests de santé post-déploiement 



**_** 13 



##### **<u>Orchestration avec Docker Compose</u>** 

Thomas ouvre le docker-compose.yml 

_"Docker Compose orchestre nos 5 microservices + base de données. Un seul docker-compose up et tout SecureCloud démarre."_ 

##### **<u>Services Orchestrés</u>** 

- **auth-service** : Microservice authentification 

- **messaging-service** : Communication temps réel 

- **files-service** : Partage de fichiers sécurisé 

- **audit-service** : Logs et conformité 

- **deploy-service** : Gestion infrastructure 

- **postgresql** : Base de données 

# **Conclusion** 

Thomas ferme son laptop et se tourne vers vous 

_"Voilà votre mission : construire SecureCloud en 3 mois. Cinq modules, architecture microservices C++, déploiement automatisé. MSF compte sur vous."_ 

Il pointe la photo d'équipe MSF au mur. 

_"Ce n'est pas qu'un projet d'école. Votre code pourrait un jour sauver des vies. Chaque ligne de C++ que vous écrirez sera au service de l'humanitaire."_ 

Thomas vous serre la main 

_"Maintenant, au travail. Le monde nous attend."_ 

##### **Bon développement, futurs ingénieurs SecureCloud !** 



**_** 14 



# **Compétences visées** 

- ➔ Installer et configurer son environnement de travail en fonction du projet. 

- ➔ Développer des interfaces utilisateur 

- ➔ Développer des composants métier 

- ➔ Contribuer à la gestion d'un projet informatique 

- ➔ Analyser les besoins et maquetter une application 

- ➔ Définir l'architecture logicielle d'une application 

- ➔ Préparer et exécuter les plans de tests d'une application 

# **Rendu** 

Votre travail est évalué en présentation avec un support et une revue de code. Le slide doit être composé de : 

- ➔ De l’organisation de votre équipe 

- ➔ De vos problèmes rencontrés ainsi que les solutions apportées 

- ➔ La démonstration de votre programme 

Le projet est à rendre sur **https://github.com/prenom-nom/wizzMania** 

# **Base de connaissances** 

- ➔ <u>Librairie Winsock de windows ou en français</u> 

- ➔ <u>Avec C++</u> 

- ➔ <u>GoogleTest User’s Guide</u> 

- ➔ <u>Qt Documentation</u> 

- ➔ <u>Microservices : définition et architecture | Talend</u> 

- ➔ <u>REST API Tutorial</u> 



**_** 15 





<!-- Start of picture text -->
= La Plateforme<br><!-- End of picture text -->



= La Plateforme 

