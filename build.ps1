function BuildVariants {
  param (
    $ldflags,
    $compileflags,
    $prefix,
    $suffix,
    $arch,
    $os,
    $path
  )

  foreach ($currentarch in $arch) {
    foreach ($currentos in $os) {
      Write-Output "Building $currentarch for $currentos"
      $env:GOARCH = $currentarch
      $env:GOOS = $currentos
      $outputfile = "binaries/$prefix-$currentos-$currentarch$suffix"
      if ($currentos -eq "windows") {
        $outputfile += ".exe"
      }
      go build -ldflags "$ldflags" -o $outputfile $compileflags $path
      if (Get-Command "cyclonedx-gomod" -ErrorAction SilentlyContinue)
      {
        cyclonedx-gomod app -json -licenses -output $outputfile.bom.json -main $path .
      }
    }
  }
}

Set-Location $PSScriptRoot

# Release
BuildVariants -ldflags "$LDFLAGS -s" -prefix inhaler -path . -arch @("amd64") -os @("linux", "openbsd", "darwin", "freebsd", "windows")
