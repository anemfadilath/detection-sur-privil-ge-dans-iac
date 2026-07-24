param(
    [int]$Iterations = 30,
    [int]$DelaySeconds = 1
)

$ErrorActionPreference = "Stop"
$outFile     = Join-Path $env:TEMP "lpg_out.json"
$payloadFile = Join-Path $env:TEMP "lpg_payload.json"

Write-Host "=== Génération de trafic : $Iterations itérations ===" -ForegroundColor Cyan

function Write-Payload($obj) {
    $json = $obj | ConvertTo-Json -Compress
    [System.IO.File]::WriteAllText($payloadFile, $json, [System.Text.Encoding]::ASCII)
}

for ($i = 1; $i -le $Iterations; $i++) {

    $fileName = "fichier_$i.txt"
    $content  = "contenu du fichier numero $i"

    Write-Payload @{ file_name = $fileName; content = $content }
    aws lambda invoke --function-name lpg-file-handler `
        --cli-binary-format raw-in-base64-out `
        --payload "file://$payloadFile" $outFile | Out-Null

    Write-Payload @{ file_name = $fileName; content = $content }
    aws lambda invoke --function-name lpg-metadata-store `
        --cli-binary-format raw-in-base64-out `
        --payload "file://$payloadFile" $outFile | Out-Null

    if ($i % 10 -eq 0) {
        Write-Payload @{ file_name = $fileName; hash = "demo" }
        aws lambda invoke --function-name lpg-notifier `
            --cli-binary-format raw-in-base64-out `
            --payload "file://$payloadFile" $outFile | Out-Null
    }

    Write-Host ("[{0}/{1}] traite : {2}" -f $i, $Iterations, $fileName) -ForegroundColor Green
    Start-Sleep -Seconds $DelaySeconds
}
