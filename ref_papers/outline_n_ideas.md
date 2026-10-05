Project Name: Context-aware Vulnerability Classification using Knowledge Graph and Threat Intelligence

Goal:

- Use Threat Ingelligence to classify security alert's impact.
- Add info about operating platform, i.e. system info, assets value, network config and topology, as context for classification
- When alert from security tool comes in, use it to query the knowledge graph for attack path and affected assets.
- use the query results to re-classify the threat impact and priority

New project scope and ideas:

- main inspriration: Nagaty's framework. Build upon his work as shortcut to not build our own knowledge graphs
- Use CVE records (from cve github) and MITRE ATT&CK (use python util from github) as CTI (Cyber Threat Intelligence)
- Create two knowledge graphs using Neo4j
- Use CTI to create Theat Intelligence knowledge graph
  - Method to create the knowledge. Replicate the method use in Nagaty's paper in creating the knowledge graph
  - do as much as possible, leave rooms for manual adjustments.
- Use Platform Info to create Asset Knowledge graph
  - Info includes:
    - operating system
    - network config
    - network topology
    - computer assets
    - software assets
    - asset value
- Create relations between the knowledge graphs to link them
- Input security alert from security tools (Wazuh for testing)
- Extract the entities and relations from security alert
- Query to the linked knowledge graph to get attack path and affected assets
- Classify the damage and impact of the attack based on the knowledge graph relations
- Compare the re-classified score to the CVSS score of the original vulneratiblity

Production Stages:

1. Prepare the data


    - Gather the CTI data
      - CVE records
      - MITRE ATT&CK vectors
      - (optional) NVD CVE dataset
      - CWE
    - Gather the asset data
      - configure the testing environment
        - host nodes
          - valuable assets
          - priority classification
        - security tools node
        - networking nodes
        - attacker node (outside of the victim nodes)
          - Kali Linux
          - Atomic Red Team

2. Constructing the Knowledge Graph


    - Construct CTI Knowledge Graph
    - Construct Asset Knowledge Graph
    - Create relational links between the two knowledge graphs
    - Test and validate the links by test querying
      - For now, don't know how

3. Querying


    - Get alert from secruity tools via there APIs
    - Extract entities and relations from the alert
    - Query the knowledge graph to find the path and affected assets

4. Classification


    - Calculate the new score relative to its original CVSS score
      - Potential solution: secBERT, ML for Text Classification

5. Validation


    - TBD, consult with proff
