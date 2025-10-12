# Automatisation de la Sécurité dans le Cloud – Cas Pratique GCP

## Objectif du projet

Ce projet s’inscrit dans le cadre d’un **mémoire de recherche en cybersécurité et cloud computing**, dont la problématique est la suivante :

> *Les erreurs humaines lors de la gestion manuelle des configurations cloud génèrent régulièrement des vulnérabilités exploitables par des attaquants.  
> Dans ce contexte, comment l’automatisation peut-elle contribuer à réduire significativement ces risques, tout en évitant l’introduction de nouvelles vulnérabilités dues à une automatisation mal maîtrisée ou trop complexe ?*

Ce dépôt illustre la mise en œuvre concrète d’une **infrastructure sécurisée sur Google Cloud Platform (GCP)**, entièrement déployée, vérifiée et auditée via des outils d’automatisation DevSecOps.

---

## Architecture et technologies

### Infrastructure as Code (IaC)
- **Terraform** : déploiement automatisé des composants GCP :
  - VPC et sous-réseaux privés
  - Règles de pare-feu restreintes
  - Machines virtuelles sécurisées (OS Login activé, clés SSH désactivées)
  - Buckets Cloud Storage avec accès restreint
  - Journaux d’audit centralisés et buckets de logs
  - Règles IAM minimales (principe du moindre privilège)
  - Politiques de surveillance et d’alerte (Monitoring & Logging)

---

## Sécurité et conformité

### Contrôles automatiques intégrés
Le code est validé avant chaque commit et chaque déploiement grâce à un **pipeline CI/CD sécurisé**.

#### Étapes automatisées :
1. **`terraform fmt` & `terraform validate`** → validation syntaxique et structurale.
2. **Checkov** → analyse statique de conformité du code Terraform.
3. **Prowler** → audit complet de l’environnement GCP déployé.
4. **Rapports** → génération automatique des rapports dans le dossier `reports/` et publication dans les artifacts GitHub Actions.

---

## Pipeline CI/CD

### GitHub Actions : `.github/workflows/ci.yml`
Le workflow est exécuté à chaque `push` ou `pull request` sur la branche `main`.  
Il effectue les étapes suivantes :

1. **Terraform Init / Validate / Plan**
2. **Déploiement automatique sur GCP**
3. **Scan Checkov (Terraform)**
4. **Audit Prowler (sécurité GCP)**
5. **Upload des rapports de conformité**

L’authentification au projet GCP est réalisée via un **Service Account (`ci-deployer`)** dont la clé est stockée dans les secrets GitHub (`GCP_SA_KEY`).

---

## Gestion des alertes de sécurité

Lorsqu’une non-conformité est détectée par Checkov ou Prowler dans la pipeline :

1. **Analyser le rapport** dans les logs GitHub Actions ou dans `/reports/`.
2. **Appliquer la correction** recommandée (ex. configuration IAM, pare-feu, logs).
3. **Valider localement** avec `terraform validate` et `checkov`.
4. **Committer et re-pousser** pour relancer la pipeline.
5. **Documenter la correction** pour assurer la traçabilité et l’amélioration continue.

> Le processus doit être suivi avant tout nouveau déploiement afin de garantir la conformité continue de l’infrastructure.

## Structure du dépôt

```bash
memoire-GCP/
├── main.tf                 # Définition principale de l'infrastructure GCP
├── variables.tf            # Variables paramétrables
├── outputs.tf              # Sorties Terraform (VM, VPC, buckets, etc.)
├── backend.tf              # Configuration du backend Terraform (bucket de state)
├── version.tf              # Configuration du provider et des versions Terraform
├── .pre-commit-config.yaml # Hooks de validation automatique avant commit
├── .github/
│   └── workflows/
│       └── ci.yml          # Pipeline GitHub Actions (CI/CD)
└── reports/                # Rapports Checkov & Prowler générés automatiquement
