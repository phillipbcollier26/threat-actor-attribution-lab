# Threat Actor Profiles

## 1. Nation-State

- **Internal/external:** External
- **Resources/funding:** Substantial resources and funding.
- **Sophistication:** Highly sophisticated
- **Likely motivations:** National pride/loyalty, military advantage, political influence
- **Typical targets:** Foreign countries, enemies of the employer's state, critical infrastructure and national security systems of adversary countries
- **What I'd expect to see in logs:**
  - **Timing/pace:** Can occur at any time, often slowly and strategically, just working to get inside of the system and not be detected
  - **Volume:** Can be quiet and low volume to avoid detection
  - **Source (IP count, internal/external):** External, several IP addresses
  - **Targets (accounts/files):** Anything dealing with government secrets, military information, or critical infrastructure.
  - **Noise level:** Low noise
  - **Real world example:** Blends in with normal traffic and quietly enters the system. Will be hard to discover due to expertise and sophistication of attacker.
- **Real-world example:** State-sponsored cyberattacks targeting another country's power grid to disrupt critical infrastructure and gain a strategic advantage.

## 2. Organized Crime

- **Internal/external:** External
- **Resources/funding:** Varies, however in most cases an experienced cyber-crime group has substantial funding and resources, sometimes approaching those of a nation-state group.
- **Sophistication:** Highly Sophisticated
- **Likely motivations:** Financial Gain
- **Typical targets:** Banks, hospitals, schools, and anywhere they can exploit systems or steal money from.
- **What I'd expect to see in logs:**
  - **Timing/pace:** Can occur at any time, sometimes during the middle of the night, and can be quickly executed or spread out over time
  - **Volume:** Can be high, especially during automated attacks or ransomware deployment
  - **Source (IP count, internal/external):** External, several different IP addresses
  - **Targets (accounts/files):** Personal information to sell, banking information, passwords, and data that can be held for ransom
  - **Noise level:** Can be loud or quiet, depending on the attack
  - **Real world example:** A system is compromised, and the attackers quickly encrypt data for a ransomware attack.
- **Real-world example:** When a cyber-crime group infiltrated the systems of Kettering Health and disrupted access to systems and patient information. Ransomware attacks can involve demanding payment in exchange for restoring access to encrypted data.

## 3. Hacktivist

- **Internal/external:** External
- **Resources/funding:** Varies. Often below a crime group and above an unskilled attacker
- **Sophistication:** Varies
- **Likely motivations:** World issues, wanting to send a message, climate causes, animal rights causes, human rights causes. Sending a message.
- **Typical targets:** Oil companies, terrorist groups, supremacist groups, and organizations they disagree with politically or socially
- **What I'd expect to see in logs:**
  - **Timing/pace:** Can occur at any time, sometimes hitting hard and quickly during a coordinated attack.
  - **Volume:** Can be high during coordinated attacks
  - **Source (IP count, internal/external):** External, can involve a low or high number of IP addresses
  - **Targets (accounts/files):** Defacing websites, adding their own propaganda, disrupting services, or leaking information. Often trying to spread awareness or send a message
  - **Noise level:** Can be high, especially during website defacements or denial-of-service attacks
- **Real-world example:** When hacktivists took control of ISIS-related websites and displayed anti-ISIS messages or disrupted their online presence.

## 4. Unskilled Attacker

- **Internal/external:** External
- **Resources/funding:** Few resources, little or no funding
- **Sophistication:** Low
- **Likely motivations:** Financial gain, personal disputes, curiosity, or wanting to prove their skills
- **Typical targets:** Whatever they can get
- **What I'd expect to see in logs:**
  - **Timing/pace:** Hard to predict
  - **Volume:** Can be high due to automated tools or repeated attempts
  - **Source (IP count, internal/external):** Often a single external IP address, but can use multiple IP addresses or automated tools
  - **Targets (accounts/files):** Wherever they can access
  - **Noise level:** Often high due to mistakes, repeated attempts, or poorly configured tools
- **Real-world example:** An 18-year-old cybersecurity major attempting to use the library's public Wi-Fi to steal data from other people using the same network without their permission.

## 5. Insider Threat

- **Internal/external:** Internal
- **Resources/funding:** May have few additional resources or funding, but can already have legitimate access to company systems and information
- **Sophistication:** Varies depending on the employee's skills and level of access
- **Likely motivations:** Upset with company/employer; disgruntled employee, financial gain, or personal benefit
- **Typical targets:** The organization that the attacker works at or is a part of.
- **What I'd expect to see in logs:**
  - **Timing/pace:** During normal working hours or at unusual times, depending on the person's access and intentions
  - **Volume:** Can be low to avoid detection or high if they are copying or deleting large amounts of data
  - **Source (IP count, internal/external):** Often a single internal device or account, but could involve multiple devices
  - **Targets (accounts/files):** Company information to leak, sensitive files, customer data, or other information the employee can access
  - **Noise level:** Often low if the person is trying to avoid detection, but can be high if they make obvious changes or delete large amounts of data
- **Real-world example:** When an employee is upset with the CEO of the company he works for and decides to leak company secrets to the public to ruin the reputation of the company.

# Threat Actor Group Example Analysis

## APT28

The group “APT 28” is a Nation State Russian cyber-military group with a history of interfering with a U.S. presidential elections, nuclear facility, and Anti-Doping Agency. Their motivations follow Russian agendas such as to interfere with foreign enemies Ukraine and the United States.

### Common Techniques

**Disk Wipe:** APT 28 has been known to use disk wiping. Disk whiping is a technique focused on destroying data. In disk whiping attacks, data is often overwritten, corrupted, or erased altogether. Disk whiping is most commonly done through malware with worm features that hop across a network through additional techniques.

**Proxy:** Proxys are used to direct traffic through systems or act as a middleman between the internet and an adversary's main infrastructure. This protects the identity of the attacker and allows the attacker to blend in with normal traffic and avoid detection.

**Command and Scripting Interpreter:** Command and Scripting Interpreters are used by attackers to execute scripts and commands on their victims' infrastructure. Since most systems come with a built-in interpreter, attackers use scripts to further exploit their victims' using commands and scripts once they have gained access to their infrastructure.

ATP 28 has significant resources and patience since they are seemingly funded by the Russian Government. The group does not perform attacks in search of money. Instead, ATP 28 attacks critical infrastructure of Russia's adversaries. ATP 28 has patience, experience, and an abundance of resources, making them a significant threat to any potential targets.

### What I'd expect to see in logs

- I would expect APT 28 to attempt to first breach a system during hours of highest traffic to avoid detection.
- ATP 28 would be quiet and would attack and search for data sensitive to a countries national security.
- I would expect to see unusual command line and scripting performed inside the targets system

## INC Ransom

The group INC Ransom is a ransomware threat group. INC has targeted a multitude of organizations. Their targets often include healthcare and education industries in the U.S. and Europe.

### Common Techniques

**Archive Collected Data:** An Archive Collected Data technique is used by attackers to compress or encrypt data prior to exfiltration to reduce the amount of data being sent over a network. This makes it difficult for victims to identify that sensitive information is being sent through their network and unable to see what data is being sent through it as well. This makes exfiltration hard to detect and investigate.

**Data Staged:** Data Staging is used by attackers to hide exfiltration from a victim. Data Staging occurs when an attacker organizes data in a disguised location, such as a cleverly named folder or file to evade detection during exfiltration.

**Ingress Tool Transfer:** An Ingress Tool Transfer occurs when an attacker, already inside of the target’s infrastructure, uses the targets technology to download malware or other harmful technology directly to the target’s infrastructure. This is commonly done through PowerShell and other OS interpreters.

Since INC Ransom is a financially motivated cyber crime syndicate, they are self-funded through their attacks which when executed properly yield them significant financial gain. The group uses their own, custom ransomware technology which paired with their elusiveness to law enforcement indicates a high level of expertise and experience.

### What I'd expect to see in logs

- I would expect INC ransom to attack swiftly at night when most cybersecurity professionals are inactive.
- INC ransom would come in quickly and hit hard immediately once they gained access to a target's system
- I expect INC ransom to target sensitive user data that could then be encrypted to the system administrators.
- In logs I would expect to see unusual commands being entered inside of the OS terminal of infected systems.

## Committed Predictions (made before seeing any data)

\| Actor              | Hours      | Pace| Source IPs| Noise|

\|                    |            |     |           |      |

\| Nation-state       |Business    |Slow |Few        |Low   | 2/4

\| Organized crime    |After-hours |Burst|Many       |High  | 4/4

\| Hacktivist         |Overnight   |Burst|Many       |High  | 4/4

\| Unskilled attacker |After-hours |Slow |1          |High  | 2/4

\| Insider            |Business    |Slow |1          |Low   | 3/4

### Incorrect

**Nation State:** The hours of the nation state were at night and not the predicted business hours. My theory is that this is because they would be able to slip in under the disguise of the svc_backup and look routine. There was no reason to go during the daytime. I was also incorrect about the amount of source IPs. There was only one, which makes sense because a nation state group would not want to be seen and only one IP makes as little noise as possible.

**Unskilled Attacker:** I predicted the unskilled attacker would be after hours and slow. However the attack occurred during business hours which I believe the attack thought would mask their activity. However since the system is not used to that much traffic, it was an obvious red flag. The attacker was not slow with their pace. Their python script quickly tried several sensitive points in the system to check for weaknesses. Thankfully the server shut the attacks down.

**Insider:** I predicted that the insider would work in business times, however they waited until after business hours (probably waited until they were alone in the office) to copy files to a personal drive.t