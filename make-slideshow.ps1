$files = Get-ChildItem -Path ".\kolaji\full" -File |
  Where-Object { $_.Extension -match '^\.(jpg|jpeg|png|webp)$' } |
  Sort-Object Name

$paths = $files | ForEach-Object { "/kolaji/full/$($_.Name)" }

# gallery: always all images
$paths | ConvertTo-Json | Set-Content -Encoding UTF8 ".\slideshow\gallery.json"
Write-Host "Updated slideshow/gallery.json with $($files.Count) images."

# slideshow: start as full list (you can manually delete rows later)
$paths | ConvertTo-Json | Set-Content -Encoding UTF8 ".\slideshow\slideshow.json"
Write-Host "Updated slideshow/slideshow.json with $($files.Count) images."