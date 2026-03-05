$files = Get-ChildItem -Path ".\kolaji\full" -File | Sort-Object Name
$paths = $files | ForEach-Object { "/kolaji/full/$($_.Name)" }
$paths | ConvertTo-Json | Set-Content -Encoding UTF8 ".\slideshow\slideshow.json"
Write-Host "Updated slideshow/slideshow.json with $($files.Count) items."