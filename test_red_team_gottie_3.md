# 🔴 TEST TECHNIQUE - RED TEAM DEVELOPER
## Évaluation Exhaustive pour Gottie

---

**Profil évalué:** Gottie - Full-Stack Developer (42) → Red Team Developer
**Date:** Janvier 2026
**Durée estimée:** 4-6 heures (révision complète)
**Objectif:** Révision complète des fondamentaux Red Team / Offensive Security

---

## 📚 SOURCES DE RECHERCHE

- Bishop Fox (Red Team Tools 2025)
- OWASP Top 10 2025
- MITRE ATT&CK Framework
- HackTheBox / TryHackMe
- Synacktiv Blog & Methodology
- Altered Security (Evasion Lab)
- GTFOBins
- Microsoft AD Security Guidance 2025
- Maldev Academy
- OffSec (OSCP/OSCE/CRTO)

---

# PARTIE 1: FONDAMENTAUX RÉSEAUX & PROTOCOLES

## 1.1 Modèle OSI & TCP/IP

1. **Listez les 7 couches du modèle OSI avec un protocole exemple pour chaque couche.**

2. **Quelle est la différence entre le modèle OSI (7 couches) et le modèle TCP/IP (4 couches) ? Faites la correspondance entre les couches.**

3. **À quelle couche OSI opèrent les équipements suivants : hub, switch, routeur, firewall applicatif, proxy ?**

4. **Qu'est-ce que l'encapsulation ? Décrivez le parcours d'un paquet HTTP de l'application jusqu'au câble (headers ajoutés à chaque couche).**

5. **Qu'est-ce que le MTU (Maximum Transmission Unit) ? Que se passe-t-il quand un paquet dépasse le MTU ?**

6. **Qu'est-ce que la fragmentation IP ? Comment peut-elle être utilisée pour bypass des IDS/IPS ?**

## 1.2 TCP en profondeur

7. **Qu'est-ce qu'un "three-way handshake" TCP ? Décrivez les étapes (flags SYN, SYN-ACK, ACK).**

8. **Décrivez le processus de fermeture TCP (four-way teardown : FIN, ACK, FIN, ACK). Qu'est-ce qu'un RST ?**

9. **Listez et expliquez tous les flags TCP : SYN, ACK, FIN, RST, PSH, URG, ECE, CWR.**

10. **Qu'est-ce que le TCP sequence number et l'acknowledgement number ? Pourquoi sont-ils importants pour la sécurité ?**

11. **Qu'est-ce que le TCP sequence prediction attack ?**

12. **Qu'est-ce que les différents états TCP ? (LISTEN, ESTABLISHED, TIME_WAIT, CLOSE_WAIT, SYN_SENT, SYN_RECEIVED, etc.)**

13. **Qu'est-ce que le TCP window size ? Comment le TCP window size peut-il être utilisé pour du fingerprinting OS ?**

14. **Expliquez la différence entre un scan TCP SYN (half-open), TCP Connect, TCP FIN, TCP XMAS, TCP NULL et TCP ACK.**
```
# Pour chaque type de scan, indiquez :
# - Les flags envoyés
# - Le comportement attendu (port ouvert vs fermé)
# - Avantages/inconvénients pour l'attaquant
```

15. **Qu'est-ce qu'un Idle Scan (zombie scan) ? Comment fonctionne-t-il avec les IP ID ?**

## 1.3 UDP

16. **Quelle est la différence fondamentale entre TCP et UDP ? Donnez 3 cas d'usage pour chaque.**

17. **Comment scanner des ports UDP ? Pourquoi est-ce plus lent et moins fiable que TCP ?**

18. **Quels protocoles importants utilisent UDP ? (DNS, SNMP, DHCP, TFTP, NTP, etc.)**

19. **Qu'est-ce qu'une UDP amplification attack ? Citez 3 protocoles exploitables et leur facteur d'amplification.**

## 1.4 IP, ICMP & Routage

20. **Qu'est-ce que le TTL (Time To Live) ? Comment peut-il être utilisé pour du fingerprinting OS ?**
```
# Donnez les TTL par défaut pour : Linux, Windows, Cisco, Solaris
```

21. **Qu'est-ce que le protocole ICMP ? Listez les types importants (Echo Request/Reply, Destination Unreachable, Time Exceeded, Redirect).**

22. **Comment ICMP peut-il être utilisé offensivement ? (ICMP tunneling, ICMP redirect attack, ICMP flood)**

23. **Qu'est-ce que le traceroute ? Différence entre traceroute Linux (UDP) et tracert Windows (ICMP) ?**

24. **Qu'est-ce qu'une route statique vs dynamique ? Citez les protocoles de routage (OSPF, BGP, RIP, EIGRP).**

25. **Qu'est-ce que le BGP hijacking ? Pourquoi est-ce un risque majeur pour Internet ?**

26. **Qu'est-ce que le source routing ? Pourquoi est-il désactivé par défaut ?**

27. **Quelle est la différence entre IPv4 et IPv6 ? Quelles implications pour la sécurité ?**

28. **Quelles attaques sont spécifiques à IPv6 ? (RA spoofing, NDP attacks, etc.)**

## 1.5 Couche 2 - Ethernet, ARP, Switching

29. **Qu'est-ce qu'une adresse MAC ? Comment fonctionne la résolution MAC ↔ IP ?**

30. **Expliquez le protocole ARP en détail. Qu'est-ce qu'un ARP Request vs ARP Reply ?**

31. **Qu'est-ce que l'ARP poisoning/spoofing ? Comment le réaliser avec ettercap ou arpspoof ?**
```bash
# Complétez la commande pour un MITM entre la gateway et la cible :
arpspoof -i _____ -t _____ _____
```

32. **Qu'est-ce que le MAC flooding ? Comment saturer la CAM table d'un switch ?**

33. **Qu'est-ce qu'un VLAN ? Qu'est-ce que le VLAN hopping (switch spoofing et double tagging) ?**

34. **Qu'est-ce que le STP (Spanning Tree Protocol) ? Comment exploiter STP pour devenir root bridge ?**

35. **Qu'est-ce que le CDP/LLDP ? Pourquoi ces protocoles sont dangereux ?**

36. **Qu'est-ce que le 802.1X (port-based NAC) ? Comment le contourner ?**

## 1.6 DHCP

37. **Expliquez le processus DHCP (DORA : Discover, Offer, Request, Acknowledge).**

38. **Qu'est-ce qu'une DHCP starvation attack ?**

39. **Qu'est-ce qu'un DHCP rogue server attack ? Que permet-il ?**

40. **Comment se protéger contre les attaques DHCP ? (DHCP snooping)**

## 1.7 DNS en profondeur

41. **Qu'est-ce que le DNS ? Décrivez la résolution complète d'un nom de domaine (recursive, iterative, root servers, TLD, authoritative).**

42. **Différence entre enregistrements A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV.**

43. **Qu'est-ce qu'un DNS zone transfer (AXFR) ? Comment le tester ?**
```bash
# Commande pour tenter un zone transfer :
dig _____ @_____ _____
```

44. **Qu'est-ce que le DNS cache poisoning (attaque de Kaminsky) ?**

45. **Expliquez ce qu'est DNSSEC et pourquoi c'est important.**

46. **Qu'est-ce que le DNS tunneling ? Outils associés (iodine, dnscat2, dns2tcp) ?**

47. **Qu'est-ce que le DNS rebinding attack ?**

48. **Qu'est-ce que le DNS-over-HTTPS (DoH) et DNS-over-TLS (DoT) ? Implications pour le Red Team ?**

49. **Comment utiliser DNS pour l'exfiltration de données ?**
```
# Donnez le concept et un exemple de payload :
# <data_encodée>.attacker.com
```

50. **Quels enregistrements DNS sont utiles pour la reconnaissance ? (SPF, DMARC, DKIM via TXT)**

## 1.8 Ports & Services

51. **Associez ces ports à leurs services et protocoles :**
    - 21, 22, 23, 25, 53, 69, 80, 88, 110, 111, 135, 137, 138, 139, 143, 161, 162, 389, 443, 445, 464, 500, 512-514, 548, 554, 587, 636, 873, 993, 995, 1080, 1433, 1521, 2049, 3128, 3306, 3389, 4443, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 8888, 9200, 11211, 27017

52. **Quels ports sont particulièrement intéressants pour un attaquant ciblant Active Directory ?**

53. **Quelle est la différence entre les ports 139 et 445 (SMB over NetBIOS vs SMB direct) ?**

54. **À quoi sert le port 88 dans un environnement Windows (Kerberos) ?**

55. **Différence entre ports 5985 (WinRM HTTP) et 5986 (WinRM HTTPS) ?**

56. **Quels ports sont associés à la RPC Windows (135, 593, dynamic range) ?**

57. **Quels services sont souvent trouvés sur des ports non-standard et comment les identifier ?**

## 1.9 SSL/TLS & Cryptographie Réseau

58. **Expliquez le handshake TLS 1.2 en détail (ClientHello, ServerHello, Certificate, Key Exchange, Finished).**

59. **Quelles sont les différences entre TLS 1.2 et TLS 1.3 ?**

60. **Qu'est-ce que le SSL stripping ? Comment fonctionne l'outil sslstrip ?**

61. **Qu'est-ce qu'un certificat X.509 ? Chaîne de confiance (Root CA, Intermediate CA) ?**

62. **Qu'est-ce que le certificate pinning ? Comment le contourner ?**

63. **Citez des attaques contre SSL/TLS : BEAST, POODLE, Heartbleed, CRIME, BREACH, DROWN, ROBOT.**

64. **Comment tester la configuration TLS d'un serveur ? (testssl.sh, sslyze, sslscan)**

65. **Qu'est-ce que le SNI (Server Name Indication) ? Utilisation pour la censure et le contournement ?**

## 1.10 HTTP/HTTPS en profondeur

66. **Listez les méthodes HTTP et leur usage : GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE, CONNECT.**

67. **Qu'est-ce que la méthode TRACE et pourquoi est-elle dangereuse (Cross-Site Tracing) ?**

68. **Quels sont les codes de réponse HTTP importants ? (200, 301, 302, 400, 401, 403, 404, 405, 500, 502, 503)**

69. **Quels headers HTTP sont importants pour la sécurité ?**
```
# Expliquez chacun :
# X-Frame-Options, X-Content-Type-Options, X-XSS-Protection,
# Strict-Transport-Security (HSTS), Content-Security-Policy (CSP),
# Access-Control-Allow-Origin (CORS), Referrer-Policy,
# Permissions-Policy, Cache-Control
```

70. **Qu'est-ce que le HTTP/2 ? Quelles implications pour les outils de pentest ?**

71. **Qu'est-ce que le HTTP Request Smuggling ? Différence entre CL.TE, TE.CL, TE.TE ?**

72. **Qu'est-ce que WebSocket ? Comment intercepter et tester les WebSocket ?**

73. **Comment fonctionne un proxy HTTP (forward proxy vs reverse proxy) ? Différence avec un proxy SOCKS ?**

## 1.11 Network Sniffing & Man-in-the-Middle

74. **Qu'est-ce que le mode promiscuous sur une interface réseau ?**

75. **Qu'est-ce que Wireshark ? Citez 10 filtres d'affichage utiles.**
```
# Exemples de filtres :
# tcp.port == 445
# http.request.method == "POST"
# dns.qry.name contains "evil"
# Complétez avec 7 autres filtres utiles en Red Team
```

76. **Qu'est-ce que tcpdump ? Écrivez une commande pour capturer le trafic HTTP.**
```bash
tcpdump -i _____ -w _____ _____
```

77. **Qu'est-ce que Responder ? Quels protocoles exploite-t-il (LLMNR, NBT-NS, MDNS, WPAD) ?**

78. **Qu'est-ce que LLMNR/NBT-NS poisoning ? Pourquoi est-ce si efficace en réseau interne ?**

79. **Qu'est-ce que WPAD (Web Proxy Auto-Discovery) ? Comment l'exploiter ?**

80. **Qu'est-ce que le MITM via rogue Wi-Fi (evil twin) ?**

81. **Qu'est-ce que Bettercap ? Citez 5 modules utiles.**

## 1.12 Firewalls, IDS/IPS & Évasion Réseau

82. **Différence entre un firewall stateful et stateless ?**

83. **Différence entre un IDS (Intrusion Detection System) et un IPS (Intrusion Prevention System) ?**

84. **Qu'est-ce qu'un WAF (Web Application Firewall) ? Exemples (ModSecurity, Cloudflare, AWS WAF) ?**

85. **Techniques d'évasion de firewall avec Nmap ?**
```bash
# Expliquez ces options :
nmap -f
nmap -D decoy1,decoy2,ME
nmap --source-port 53
nmap --data-length 50
nmap -S <spoofed_ip>
nmap --scan-delay 5s
```

86. **Techniques d'évasion IDS/IPS : fragmentation, encoding, timing, protocol-level evasion.**

87. **Comment bypass un WAF ? (Encoding, case variation, commentaires SQL, double URL encoding, etc.)**

88. **Qu'est-ce que le port knocking ?**

## 1.13 Tunneling, Pivoting & Port Forwarding

89. **Qu'est-ce que le SSH port forwarding ? Expliquez Local (-L), Remote (-R) et Dynamic (-D) forwarding.**
```bash
# Complétez les commandes :
# Local forward : accéder au port 3306 de 10.0.0.5 via le pivot
ssh -L _____:_____:_____ user@pivot

# Remote forward : exposer votre port 8080 via le pivot
ssh -R _____:_____:_____ user@pivot

# Dynamic SOCKS proxy
ssh -D _____ user@pivot
```

90. **Qu'est-ce que Chisel ? Comment l'utiliser pour du tunneling ?**

91. **Qu'est-ce que Ligolo-ng ? Avantages par rapport à Chisel ?**

92. **Qu'est-ce que ProxyChains ? Comment le configurer avec un SOCKS proxy ?**

93. **Qu'est-ce que le double pivoting ? Décrivez un scénario avec 3 réseaux.**

94. **Qu'est-ce que socat ? Donnez 3 use cases Red Team.**

95. **Qu'est-ce que netcat ? Différence entre nc, ncat et netcat ? Commandes pour bind shell et reverse shell.**
```bash
# Reverse shell :
nc -e /bin/bash _____ _____
# Bind shell :
nc -lvp _____ -e /bin/bash
```

96. **Qu'est-ce qu'un VPN ? Différences entre OpenVPN, WireGuard, IPSec, L2TP ?**

97. **Qu'est-ce que le GRE tunneling ?**

98. **Qu'est-ce que le DNS tunneling pour C2 ? Comment fonctionne dnscat2 ?**

## 1.14 Protocoles d'authentification réseau

99. **Qu'est-ce que RADIUS ? Où est-il utilisé ?**

100. **Qu'est-ce que TACACS+ ? Différences avec RADIUS ?**

101. **Qu'est-ce que le protocole NTLM au niveau réseau ? Capture et relay.**

102. **Qu'est-ce que le protocole Kerberos au niveau réseau ? Ports et flux.**

## 1.15 Protocoles de partage & services réseau

103. **Qu'est-ce que SMB (Server Message Block) ? Versions (SMBv1, SMBv2, SMBv3) et implications sécurité.**

104. **Qu'est-ce que la null session SMB ? Comment l'exploiter ?**
```bash
# Commandes d'énumération SMB :
smbclient -L _____ -N
enum4linux _____
crackmapexec smb _____ -u '' -p ''
```

105. **Qu'est-ce que le protocole SNMP ? Versions (v1, v2c, v3) et community strings ?**

106. **Comment énumérer SNMP ? (snmpwalk, onesixtyone)**
```bash
snmpwalk -v2c -c _____ _____ _____
```

107. **Qu'est-ce que le protocole FTP ? Mode actif vs passif ? Attaques (bounce attack, anonymous login) ?**

108. **Qu'est-ce que le protocole SSH ? Attaques possibles (brute force, key theft, agent forwarding abuse) ?**

109. **Qu'est-ce que RDP ? Attaques associées (BlueKeep, brute force, MITM RDP) ?**

110. **Qu'est-ce que le protocole SMTP ? Commandes utiles pour l'énumération (VRFY, EXPN, RCPT TO) ?**

## 1.16 Wi-Fi & Sécurité sans fil

111. **Différences entre WEP, WPA, WPA2 et WPA3 ?**

112. **Qu'est-ce que le WPA2 handshake (4-way handshake) ? Comment le capturer ?**

113. **Qu'est-ce qu'une attaque de deauthentication Wi-Fi ?**
```bash
# Avec aireplay-ng :
aireplay-ng -0 _____ -a _____ -c _____ _____
```

114. **Qu'est-ce que l'attaque PMKID ? Avantage par rapport à la capture du handshake ?**

115. **Qu'est-ce qu'un evil twin access point ?**

116. **Qu'est-ce que le WPS (Wi-Fi Protected Setup) et pourquoi est-il vulnérable ?**

117. **Outils Wi-Fi offensifs : aircrack-ng suite, Wifite, Fluxion, hostapd-mana. Décrivez leur usage.**

## 1.17 Outils réseau essentiels

118. **Nmap : écrivez les commandes pour les scénarios suivants :**
```bash
# a) Scan furtif des 1000 ports les plus communs
nmap _____

# b) Scan de tous les ports avec détection de version et scripts
nmap _____

# c) Scan UDP des 100 ports les plus communs
nmap _____

# d) Scan d'un réseau entier /24 pour trouver les hôtes vivants
nmap _____

# e) Scan via un proxy SOCKS
nmap _____
```

119. **Masscan : comment scanner tout Internet sur le port 445 ?**

120. **Netcat : citez 5 use cases offensifs (shell, file transfer, port scan, banner grab, relay).**

121. **Wireshark vs tcpdump vs tshark : quand utiliser lequel ?**

122. **Qu'est-ce que hping3 ? Utilisations offensives ?**

123. **Qu'est-ce que Scapy ? Écrivez un exemple de craft de paquet en Python.**
```python
# Craft d'un SYN scan avec Scapy :
from scapy.all import *
# Complétez...
```

## 1.18 Scénarios réseau pratiques

124. **Vous arrivez sur un réseau interne inconnu. Décrivez les 10 premières étapes de reconnaissance réseau que vous effectuez.**

125. **Vous devez pivoter depuis un serveur Linux compromis vers un réseau interne (10.10.10.0/24) inaccessible depuis votre machine. Décrivez 3 méthodes différentes.**

126. **Vous capturez du trafic réseau avec Wireshark. Comment identifiez-vous : des credentials en clair, du trafic C2, des transferts de fichiers suspects, du DNS tunneling ?**

127. **Un firewall bloque tous les ports sauf 80 et 443. Comment établir un tunnel C2 ?**

128. **Vous devez exfiltrer 500 Mo de données d'un réseau surveillé. Quelles méthodes utilisez-vous et pourquoi ?**

---

# PARTIE 2: LINUX - FONDAMENTAUX & PRIVILEGE ESCALATION

## 2.1 Commandes Essentielles

129. **Expliquez la signification des permissions rwxrwxrwx et les valeurs numériques associées.**

130. **Qu'est-ce que le SUID bit ? Comment le repérer et pourquoi est-il dangereux ?**

131. **Qu'est-ce que le SGID bit ? Différence avec SUID ?**

132. **Qu'est-ce que le Sticky Bit ? Où le trouve-t-on généralement ?**

133. **Commande pour trouver tous les fichiers SUID sur un système ?**
```bash
# Complétez:
find / -perm _____ -type f 2>/dev/null
```

134. **Expliquez la différence entre `/etc/passwd` et `/etc/shadow`.**

135. **Quel est le format d'une entrée dans `/etc/shadow` ?**

136. **Qu'est-ce qu'un "capability" Linux ? Commande pour les lister ?**

137. **Listez 5 capabilities dangereuses et pourquoi.**

138. **Qu'est-ce que GTFOBins ? Citez 5 binaires exploitables via SUID.**

## 2.2 Privilege Escalation Linux

139. **Énumérez les 10 vecteurs principaux de privilege escalation sur Linux.**

140. **Comment exploiter un cron job mal configuré ?**

141. **Qu'est-ce que `sudo -l` révèle et comment l'exploiter ?**

142. **Expliquez l'exploitation via PATH hijacking.**

143. **Qu'est-ce que `no_root_squash` sur NFS et comment l'exploiter ?**

144. **Comment exploiter un Docker socket exposé (`/var/run/docker.sock`) ?**

145. **Qu'est-ce que le groupe `lxd` et pourquoi est-il dangereux ?**

146. **Expliquez l'exploitation via LD_PRELOAD.**

147. **Comment détecter et exploiter des kernel exploits ?**

148. **Citez 3 outils d'énumération automatique Linux (LinPEAS, etc.).**

## 2.3 Enumération Linux

149. **Commande pour lister les processus avec leurs arguments complets ?**

150. **Comment trouver des credentials en clair dans les fichiers ?**
```bash
# Complétez plusieurs commandes
grep -r "password" _____
```

151. **Comment lister les connexions réseau actives ?**

152. **Commande pour voir l'historique bash de tous les utilisateurs ?**

153. **Comment identifier le kernel et la distribution ?**

---

# PARTIE 3: WINDOWS - FONDAMENTAUX (GENERIC REMINDER)

## 3.1 Architecture Windows

154. **Expliquez la différence entre User Mode et Kernel Mode.**

155. **Qu'est-ce que le Registry Windows ? Listez les 5 ruches principales (HKEY_*).**

156. **Où sont stockés les hashes de mots de passe locaux ?**

157. **Qu'est-ce que la SAM database ?**

158. **Qu'est-ce que LSASS ? Pourquoi est-il une cible prioritaire ?**

159. **Qu'est-ce que le fichier NTDS.dit ?**

160. **Expliquez les différents types de tokens Windows (Primary, Impersonation).**

161. **Qu'est-ce que le Windows Event Log ? Événements importants à monitorer ?**

162. **Qu'est-ce que WMI ? Utilisation offensive ?**

163. **Qu'est-ce que le service "Server" (LanmanServer) ?**

## 3.2 Authentification Windows

164. **Expliquez le protocole NTLM en 3 étapes.**

165. **Qu'est-ce qu'un hash NTLM ? Format ?**

166. **Différence entre NTLMv1 et NTLMv2 ?**

167. **Qu'est-ce qu'un pass-the-hash attack ?**

168. **Qu'est-ce qu'un NTLM relay attack ?**

169. **Quelles protections existent contre le NTLM relay ?**

170. **Qu'est-ce que Kerberos ? Avantages sur NTLM ?**

171. **Expliquez le fonctionnement de Kerberos (AS-REQ, AS-REP, TGS-REQ, TGS-REP, AP-REQ).**

172. **Qu'est-ce qu'un TGT (Ticket Granting Ticket) ?**

173. **Qu'est-ce qu'un TGS (Ticket Granting Service) ?**

## 3.3 Active Directory Basics

174. **Qu'est-ce qu'Active Directory ? Composants principaux ?**

175. **Qu'est-ce qu'un Domain Controller ?**

176. **Qu'est-ce qu'un SPN (Service Principal Name) ?**

177. **Qu'est-ce que LDAP ? Ports associés ?**

178. **Qu'est-ce qu'un GPO (Group Policy Object) ?**

179. **Qu'est-ce qu'un Trust relationship ?**

180. **Différence entre Forest, Tree, Domain ?**

181. **Qu'est-ce qu'un OU (Organizational Unit) ?**

182. **Expliquez les groupes privilégiés par défaut (Domain Admins, Enterprise Admins, etc.).**

183. **Qu'est-ce que le groupe "Protected Users" ?**

## 3.4 AD Attacks (Reminders)

184. **Qu'est-ce que le Kerberoasting ? Comment le réaliser ?**

185. **Qu'est-ce que l'AS-REP Roasting ?**

186. **Qu'est-ce qu'un Golden Ticket attack ?**

187. **Qu'est-ce qu'un Silver Ticket attack ?**

188. **Qu'est-ce que le DCSync attack ?**

189. **Qu'est-ce que le DCShadow attack ?**

190. **Qu'est-ce que la délégation Kerberos (Unconstrained, Constrained, RBCD) ?**

191. **Qu'est-ce que PrintNightmare ?**

192. **Qu'est-ce que ZeroLogon (CVE-2020-1472) ?**

193. **Qu'est-ce que PetitPotam ?**

## 3.5 Windows Privilege Escalation (Reminders)

194. **Listez 10 vecteurs de privilege escalation Windows.**

195. **Qu'est-ce qu'un Unquoted Service Path ?**

196. **Comment exploiter un service avec des permissions faibles ?**

197. **Qu'est-ce qu'un AlwaysInstallElevated ?**

198. **Comment exploiter le DLL Hijacking ?**

199. **Qu'est-ce que SeImpersonatePrivilege et comment l'exploiter ?**

200. **Qu'est-ce que SeDebugPrivilege ?**

201. **Citez 3 outils d'énumération Windows (WinPEAS, PowerUp, etc.).**

202. **Qu'est-ce que LOLBAS ?**

203. **Comment extraire des credentials du Credential Manager ?**

---

# PARTIE 4: WEB APPLICATION SECURITY

## 4.1 OWASP Top 10 2025

204. **Listez le OWASP Top 10 2025 dans l'ordre.**

205. **Qu'est-ce que Broken Access Control ? Exemples ?**

206. **Qu'est-ce qu'une Cryptographic Failure ?**

207. **Qu'est-ce que l'Injection ? Types principaux ?**

208. **Qu'est-ce qu'un Insecure Design ?**

209. **Qu'est-ce qu'une Security Misconfiguration ?**

## 4.2 Injection Attacks

210. **Écrivez une payload SQL Injection basique pour bypass login.**

211. **Qu'est-ce qu'une Union-based SQL Injection ? Exemple ?**

212. **Qu'est-ce qu'une Blind SQL Injection (Boolean-based, Time-based) ?**

213. **Qu'est-ce qu'une Out-of-Band SQL Injection ?**

214. **Qu'est-ce qu'une Second Order SQL Injection ?**

215. **Comment prévenir les SQL Injections ? (Prepared Statements, etc.)**

216. **Qu'est-ce qu'une Command Injection ? Exemple ?**

217. **Qu'est-ce qu'une LDAP Injection ?**

218. **Qu'est-ce qu'une XPath Injection ?**

## 4.3 XSS (Cross-Site Scripting)

219. **Différence entre Reflected, Stored et DOM-based XSS ?**

220. **Écrivez 5 payloads XSS basiques.**

221. **Qu'est-ce que le Content Security Policy (CSP) ? Bypass possibles ?**

222. **Qu'est-ce que HTTPOnly et Secure flags sur les cookies ?**

223. **Comment exploiter un XSS pour voler des cookies ?**

224. **Qu'est-ce que le XSS avec event handlers ? Exemples ?**

225. **Qu'est-ce qu'un XSS filter bypass ?**

## 4.4 CSRF & SSRF

226. **Qu'est-ce que CSRF (Cross-Site Request Forgery) ?**

227. **Comment prévenir CSRF ? (Tokens, SameSite cookies, etc.)**

228. **Qu'est-ce que SSRF (Server-Side Request Forgery) ?**

229. **Quelles sont les cibles classiques d'un SSRF ? (metadata services, etc.)**

230. **Comment exploiter un SSRF sur AWS (169.254.169.254) ?**

231. **Qu'est-ce qu'un Blind SSRF ?**

## 4.5 Autres Vulnérabilités Web

232. **Qu'est-ce que l'IDOR (Insecure Direct Object Reference) ?**

233. **Qu'est-ce qu'une XXE (XML External Entity) injection ?**

234. **Qu'est-ce qu'une LFI (Local File Inclusion) ?**

235. **Qu'est-ce qu'une RFI (Remote File Inclusion) ?**

236. **Qu'est-ce qu'un Path Traversal ?**

237. **Qu'est-ce qu'un Open Redirect ?**

238. **Qu'est-ce que l'Insecure Deserialization ?**

239. **Qu'est-ce qu'un JWT ? Attaques possibles ?**

240. **Qu'est-ce que l'Host Header Injection ?**

241. **Qu'est-ce que le HTTP Request Smuggling ?**

## 4.6 Outils Web

242. **Décrivez l'utilisation de Burp Suite (Proxy, Repeater, Intruder, Scanner).**

243. **Qu'est-ce que SQLMap ? Options importantes ?**

244. **Qu'est-ce que ffuf/gobuster/dirbuster ?**

245. **Qu'est-ce que Nikto ?**

246. **Qu'est-ce que Nuclei ?**

---

# PARTIE 5: EXPLOIT DEVELOPMENT & BINARY EXPLOITATION

## 5.1 Buffer Overflow Basics

247. **Qu'est-ce qu'un buffer overflow ?**

248. **Expliquez la structure de la stack (ESP, EBP, EIP).**

249. **Qu'est-ce que l'instruction `ret` en assembleur ?**

250. **Qu'est-ce qu'un NOP sled ?**

251. **Comment trouver l'offset pour écraser EIP ?**

252. **Qu'est-ce qu'un bad character ? Comment les identifier ?**

253. **Qu'est-ce qu'une instruction JMP ESP ? Pourquoi l'utiliser ?**

## 5.2 Protections & Bypass

254. **Qu'est-ce que DEP/NX (Data Execution Prevention) ?**

255. **Qu'est-ce que l'ASLR (Address Space Layout Randomization) ?**

256. **Qu'est-ce que le Stack Canary/Cookie ?**

257. **Qu'est-ce que RELRO ?**

258. **Qu'est-ce que PIE (Position Independent Executable) ?**

259. **Comment bypass DEP avec ROP (Return Oriented Programming) ?**

260. **Qu'est-ce qu'un gadget ROP ?**

261. **Comment bypass ASLR ? (Information leak, brute force, etc.)**

262. **Qu'est-ce que ret2libc ?**

263. **Qu'est-ce que ret2plt ?**

## 5.3 Shellcode

264. **Qu'est-ce qu'un shellcode ?**

265. **Pourquoi éviter les null bytes dans un shellcode ?**

266. **Qu'est-ce que msfvenom ? Générez un reverse shell Linux x64.**

267. **Qu'est-ce qu'un staged vs stageless payload ?**

268. **Qu'est-ce qu'un encoder de shellcode ?**

---

# PARTIE 6: REVERSE ENGINEERING & MALWARE ANALYSIS

## 6.1 Outils & Concepts

269. **Différence entre analyse statique et dynamique ?**

270. **Qu'est-ce que Ghidra ? Fonctionnalités principales ?**

271. **Qu'est-ce que IDA Pro ? Avantages sur Ghidra ?**

272. **Qu'est-ce que x64dbg/OllyDbg ?**

273. **Qu'est-ce que radare2/rizin ?**

274. **Qu'est-ce qu'un disassembler vs decompiler ?**

## 6.2 Formats de fichiers

275. **Qu'est-ce que le format PE (Portable Executable) ? Sections principales ?**

276. **Qu'est-ce que le format ELF (Executable and Linkable Format) ?**

277. **Qu'est-ce qu'une Import Address Table (IAT) ?**

278. **Qu'est-ce qu'une Export Address Table (EAT) ?**

279. **Qu'est-ce que la section .text, .data, .bss, .rodata ?**

## 6.3 Assembleur x86/x64

280. **Listez les registres généraux x86 (EAX, EBX, ECX, EDX, ESI, EDI, ESP, EBP, EIP).**

281. **Listez les registres x64 additionnels.**

282. **Expliquez les calling conventions (cdecl, stdcall, fastcall, System V AMD64).**

283. **Qu'est-ce que l'instruction `call` ?**

284. **Qu'est-ce que l'instruction `leave` ?**

285. **Qu'est-ce que les flags (ZF, CF, SF, OF) ?**

286. **Expliquez `mov`, `push`, `pop`, `lea`, `xor`, `cmp`, `jmp`, `je/jne/jz/jnz`.**

## 6.4 Anti-Analysis

287. **Qu'est-ce que le packing ? Exemples de packers ?**

288. **Qu'est-ce que l'obfuscation de code ?**

289. **Techniques anti-debugging ? (IsDebuggerPresent, timing checks, etc.)**

290. **Techniques anti-VM ? (Detection de VMware, VirtualBox, etc.)**

291. **Qu'est-ce que le code polymorphique/métamorphique ?**

---

# PARTIE 7: C2 FRAMEWORKS & POST-EXPLOITATION

## 7.1 C2 Frameworks

292. **Qu'est-ce qu'un C2 (Command & Control) framework ?**

293. **Listez 5 C2 frameworks populaires et leurs caractéristiques.**

294. **Qu'est-ce que Cobalt Strike ? Composants principaux ?**

295. **Qu'est-ce que Sliver ? Avantages vs Cobalt Strike ?**

296. **Qu'est-ce que Metasploit Framework ? Modules principaux ?**

297. **Qu'est-ce que Havoc C2 ?**

298. **Qu'est-ce que Mythic C2 ?**

## 7.2 Implants & Beacons

299. **Qu'est-ce qu'un beacon/implant ?**

300. **Différence entre session HTTP, HTTPS, DNS pour C2 ?**

301. **Qu'est-ce que le sleep time/jitter ?**

302. **Qu'est-ce que le malleable C2 profile ?**

303. **Qu'est-ce qu'un BOF (Beacon Object File) ?**

## 7.3 Post-Exploitation

304. **Qu'est-ce que Mimikatz ? Commandes principales ?**

305. **Qu'est-ce que BloodHound ? SharpHound ?**

306. **Qu'est-ce que Rubeus ?**

307. **Qu'est-ce que Impacket ? Scripts principaux ?**

308. **Qu'est-ce que CrackMapExec/NetExec ?**

309. **Qu'est-ce que PowerView ?**

310. **Qu'est-ce que Certipy ?**

---

# PARTIE 8: EDR EVASION & MALWARE DEVELOPMENT

## 8.1 EDR Internals

311. **Qu'est-ce qu'un EDR (Endpoint Detection & Response) ?**

312. **Comment les EDR hookent les API Windows ?**

313. **Qu'est-ce qu'un userland hook vs kernel callback ?**

314. **Qu'est-ce qu'ETW (Event Tracing for Windows) ?**

315. **Qu'est-ce que AMSI (Antimalware Scan Interface) ?**

## 8.2 Evasion Techniques

316. **Qu'est-ce que le Direct Syscalls ?**

317. **Qu'est-ce que Hell's Gate/Halo's Gate/Tartarus' Gate ?**

318. **Qu'est-ce que le unhooking NTDLL ?**

319. **Qu'est-ce que le module stomping ?**

320. **Qu'est-ce que le call stack spoofing ?**

321. **Qu'est-ce que BYOVD (Bring Your Own Vulnerable Driver) ?**

322. **Qu'est-ce que le process hollowing ?**

323. **Qu'est-ce que le DLL injection ?**

324. **Qu'est-ce que l'APC injection ?**

325. **Qu'est-ce que le early bird injection ?**

## 8.3 Payload Development

326. **Langages populaires pour malware development ? Avantages de chacun ?**

327. **Qu'est-ce que le shellcode loader ?**

328. **Techniques de chiffrement de payload ? (XOR, AES, etc.)**

329. **Qu'est-ce que le in-memory execution ?**

330. **Qu'est-ce que le reflective DLL loading ?**

331. **Qu'est-ce que Donut ?**

---

# PARTIE 9: SCRIPTING & AUTOMATION

## 9.1 Python pour Red Team

332. **Écrivez un script Python pour scanner les ports ouverts.**

333. **Utilisez la librairie `requests` pour faire une requête POST avec headers custom.**

334. **Écrivez un script pour encoder/décoder en Base64.**

335. **Comment utiliser `pwntools` pour exploit development ?**

336. **Comment parser du HTML avec BeautifulSoup ?**

## 9.2 Bash pour Red Team

337. **Écrivez un one-liner pour reverse shell bash.**

338. **Écrivez un script d'énumération basique.**

339. **Comment utiliser `curl` pour tester une SQLi ?**

340. **Exfiltration de données via DNS ? (Concept)**

341. **Comment utiliser `awk` et `sed` pour parser des outputs ?**

## 9.3 PowerShell (Basics)

342. **Écrivez un reverse shell PowerShell.**

343. **Comment bypass l'Execution Policy ?**

344. **Qu'est-ce que AMSI bypass en PowerShell ?**

345. **Comment télécharger et exécuter un script en mémoire ?**

346. **Qu'est-ce que PowerShell Constrained Language Mode ?**

---

# PARTIE 10: RECONNAISSANCE & OSINT

## 10.1 Passive Recon

347. **Outils pour énumération de sous-domaines ?**

348. **Qu'est-ce que Shodan ? Queries utiles ?**

349. **Qu'est-ce que Censys ?**

350. **Comment utiliser Google Dorks pour recon ?**

351. **Qu'est-ce que theHarvester ?**

352. **Comment trouver des emails d'une organisation ?**

353. **Qu'est-ce que le Certificate Transparency logs ?**

## 10.2 Active Recon

354. **Qu'est-ce que Nmap ? Options importantes ?**

355. **Différence entre `-sS`, `-sT`, `-sU`, `-sV`, `-O`, `-A` ?**

356. **Qu'est-ce que le NSE (Nmap Scripting Engine) ?**

357. **Qu'est-ce que Masscan ?**

358. **Comment énumérer SMB ? (smbclient, enum4linux, etc.)**

359. **Comment énumérer LDAP ?**

360. **Comment énumérer SNMP ?**

---

# PARTIE 11: SOCIAL ENGINEERING & PHISHING

361. **Qu'est-ce que le spear phishing vs phishing générique ?**

362. **Qu'est-ce que le pretexting ?**

363. **Outils pour créer des campagnes de phishing ? (Gophish, etc.)**

364. **Qu'est-ce que le typosquatting ?**

365. **Techniques d'évasion email ? (Homoglyphs, HTML smuggling, etc.)**

---

# PARTIE 12: CLOUD SECURITY BASICS

366. **Vecteurs d'attaque AWS spécifiques ? (SSRF metadata, IAM misconfig, etc.)**

367. **Qu'est-ce que le S3 bucket misconfiguration ?**

368. **Comment énumérer des ressources cloud ?**

369. **Qu'est-ce que PACU pour AWS pentesting ?**

---

# PARTIE 13: MÉTHODOLOGIE & FRAMEWORKS

370. **Décrivez le Cyber Kill Chain.**

371. **Décrivez les phases MITRE ATT&CK.**

372. **Qu'est-ce que le PTES (Penetration Testing Execution Standard) ?**

373. **Différence entre Red Team engagement, Pentest, et Vulnerability Assessment ?**

---

# PARTIE 14: CERTIFICATIONS & RESSOURCES

## Certifications recommandées:
- **OSCP** (Offensive Security Certified Professional)
- **CRTO** (Certified Red Team Operator)
- **CRTP** (Certified Red Team Professional)
- **OSEP** (Offensive Security Experienced Penetration Tester)
- **OSED** (Offensive Security Exploit Developer)
- **CETP** (Certified Evasion Techniques Professional)

## Ressources pour pratiquer:
- HackTheBox
- TryHackMe (Red Team Path)
- PentesterLab
- VulnHub
- PortSwigger Web Security Academy
- Maldev Academy

---

# PARTIE 15: SCÉNARIOS PRATIQUES

## Scénario 1: Initial Access
**Vous avez un périmètre externe composé d'un serveur web, un serveur mail et un VPN. Décrivez votre méthodologie complète pour obtenir un initial foothold.**

## Scénario 2: AD Compromise
**Vous avez un shell utilisateur standard sur un poste Windows joint au domaine. Décrivez les étapes pour atteindre Domain Admin.**

## Scénario 3: Evasion
**Votre implant C2 se fait détecter par l'EDR. Listez 5 techniques pour améliorer l'évasion.**

## Scénario 4: Web Application
**Vous testez une application web e-commerce. Listez les 10 premières choses que vous vérifiez.**

## Scénario 5: Persistence
**Vous êtes Domain Admin. Listez 5 méthodes de persistence pour maintenir l'accès.**

---

# GRILLE D'AUTO-ÉVALUATION

| Catégorie | Score /10 | Priorité de révision |
|-----------|-----------|---------------------|
| Réseaux & Protocoles | | |
| Linux PrivEsc | | |
| Windows Basics | | |
| Active Directory | | |
| Web Security | | |
| Exploit Development | | |
| Reverse Engineering | | |
| C2 & Post-Exploitation | | |
| EDR Evasion | | |
| Scripting | | |
| Reconnaissance | | |
| Méthodologie | | |

---

## 📝 NOTES

Ce test couvre les fondamentaux nécessaires pour un rôle de Red Team Developer. Les sections Windows sont volontairement génériques pour servir de rappel.

**Points forts identifiés du profil Gottie:**
- Reverse engineering (déobfuscation Akamai)
- Développement low-level (virus ELF, Assembly)
- Stack web moderne (JS/TS)

**Points à renforcer potentiellement:**
- Exploit development Windows
- Active Directory attacks en profondeur
- Malware development C/C++

---

*Test généré le 26 Janvier 2026 - Mis à jour le 29 Janvier 2026 (section Réseaux étendue: 128 questions)*
*Sources: Bishop Fox, OWASP, MITRE ATT&CK, Synacktiv, Altered Security, OffSec*
