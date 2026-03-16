$files = Get-ChildItem -Path ".\kolaji\full" -File |
  Where-Object { $_.Extension -match '^\.(jpg|jpeg|png|webp)$' } |
  Sort-Object Name

$paths = $files | ForEach-Object { "/kolaji/full/$($_.Name)" }

$excludeFile = ".\slideshow\slideshow-exclude.json"

# Load excludes if file exists, otherwise use empty array
if (Test-Path $excludeFile) {
    $excluded = Get-Content $excludeFile -Raw | ConvertFrom-Json
} else {
    $excluded = @()
}

# gallery: always all images
$paths | ConvertTo-Json | Set-Content -Encoding UTF8 ".\slideshow\gallery.json"
Write-Host "Updated slideshow/gallery.json with $($files.Count) images."

# slideshow: all except excluded
$slideshowPaths = $paths | Where-Object { $_ -notin $excluded }

$slideshowPaths | ConvertTo-Json | Set-Content -Encoding UTF8 ".\slideshow\slideshow.json"
Write-Host "Updated slideshow/slideshow.json with $($slideshowPaths.Count) images."