param(
    [string]$TerraformDir = "terraform",

    [string]$AthenaDb = "<athena-db>",
    [string]$AthenaTable = "<athena-table>",
    [string]$AthenaOutput = "<athena-output-bucket>",
    [string]$Region = "<region>"
)

$ErrorActionPreference = "Stop"

$statePath = Join-Path $TerraformDir "terraform.tfstate"

if (-not (Test-Path $statePath)) {
    throw "Fichier state introuvable : $statePath. 'terraform apply' à eté fait ?"
}

$state = Get-Content $statePath -Raw | ConvertFrom-Json

$roles = @()
foreach ($res in $state.resources) {
    if ($res.type -eq "aws_iam_role") {
        foreach ($inst in $res.instances) {
            if ($inst.attributes.name) {
                $roles += $inst.attributes.name
            }
        }
    }
}

if (-not $roles -or $roles.Count -eq 0) {
    throw "Aucun rôle aws_iam_role trouvé dans le state."
}

py least_privilege_gap.py `
    --roles @roles `
    --athena-db $AthenaDb `
    --athena-table $AthenaTable `
    --athena-output $AthenaOutput `
    --region $Region `
    --tf-dir $TerraformDir

if ($LASTEXITCODE -ne 0) {
    Write-Warning "L'analyse Python s'est terminée avec une erreur."
}
