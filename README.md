# Analyzer — Least Privilege Gap

Cet outil compare les **permissions IAM accordées** aux rôles AWS (déclarées dans Terraform) avec les **permissions réellement utilisées** (observées dans CloudTrail via Athena). Il produit un rapport HTML (`gap_report.html`) qui montre l'écart (gap) de moindre privilège, avec traçabilité vers le code Terraform à l'origine de chaque permission superflue.

## Fonctionnement

1. `run_analysis.ps1` lit `terraform/terraform.tfstate` et en extrait automatiquement les noms des rôles `aws_iam_role`.
2. Il appelle `least_privilege_gap.py` avec ces rôles et les options ci-dessous.
3. Le script Python :
   - récupère les permissions accordées (policies inline + managed) via l'API IAM ;
   - interroge Athena pour lister les actions réellement appelées par chaque rôle ;
   - calcule l'écart, remonte à la source Terraform (`tf_tracer.py`), et génère `gap_report.html`.

## Prérequis

- PowerShell
- Python (`py`) avec `boto3` installé, et idéalement `policyuniverse` (pour l'expansion exhaustive des wildcards `*`)
- Des identifiants AWS valides et configurés (variables d'environnement, `aws configure`, ou profil)
- Un `terraform apply` déjà effectué (le fichier `terraform/terraform.tfstate` doit exister)
- La table Athena des logs CloudTrail (`-AthenaTable`) doit exister dans la base (`-AthenaDb`), et l'emplacement de résultats S3 (`-AthenaOutput`) doit être accessible en écriture

## Options passées à l'analyseur

Ces paramètres sont exposés par `run_analysis.ps1` et transmis à `least_privilege_gap.py`.

| Paramètre PowerShell | Argument Python | Valeur par défaut | Description |
|----------------------|-----------------|-------------------|-------------|
| `-TerraformDir` | `--tf-dir` | `terraform` | Dossier contenant le `terraform.tfstate` et les fichiers `.tf` (utilisé pour extraire les rôles et pour la traçabilité). |
| `-AthenaDb` | `--athena-db` | `default` | Base de données Athena où se trouve la table CloudTrail. |
| `-AthenaTable` | `--athena-table` | `cloudtrail_logs_lpg_trail_logs_438641189182` | Table Athena des logs CloudTrail à interroger. |
| `-AthenaOutput` | `--athena-output` | `s3://lpg-athena-results-438641189182/` | Emplacement S3 où Athena écrit les résultats de requête. |
| `-Region` | `--region` | `eu-west-3` | Région AWS pour les clients IAM et Athena. |

> Les rôles (`--roles`) ne sont **pas** un paramètre à saisir : ils sont détectés automatiquement à partir du `terraform.tfstate`.
>
> `--name-prefix` (défaut `lpg`) existe côté Python pour résoudre les noms dans les `.tf` mais n'est pas exposé par le script PowerShell.

## Exécution

Depuis le dossier `analyzer/` dans PowerShell.

### Avec les options par défaut

```powershell
.\run_analysis.ps1
```

### Avec des options personnalisées

Passez uniquement les paramètres que vous voulez surcharger :

```powershell
.\run_analysis.ps1 -Region "eu-west-1" -AthenaDb "cloudtrail"
```

Exemple avec tous les paramètres :

```powershell
.\run_analysis.ps1 `
    -TerraformDir "..\terraform" `
    -AthenaDb "default" `
    -AthenaTable "cloudtrail_logs_lpg_trail_logs_438641189182" `
    -AthenaOutput "s3://lpg-athena-results-438641189182/" `
    -Region "eu-west-3"
```

## Résultat

À la fin de l'exécution, le rapport est généré dans `gap_report.html` (le chemin complet `file:///...` est affiché dans la console). 