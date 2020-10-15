Param(
  [string]$dropBaseA,
  [string]$dropBaseB,
  $versionMap,
  [switch]$force,
  [string]$signToolPath = "signtool.exe",
  [string]$nugetPath = "nuget.exe",
  [string]$snPath = "sn.exe"
)

enum FileCheckState { 
    Passed;
    Failed;
    NotChecked;
}

enum FileUnpackState { 
    Unpacked;
    NotUnpacked;
    Unknown;
}

class CheckError {
    CheckError(
        [string]$err,
        [string]$a,
        [string]$b
    ){
        $this.errorName = $err
        $this.fileA = $a
        $this.fileB = $b
    }
    [string]$errorName
    [string]$fileA
    [string]$fileB
}

$global:errors = new-object System.Collections.ArrayList

function IsTotallyNothingFile($fileItem) {
    if ($fileItem.EndsWith(".txt") -or
        $fileItem.EndsWith(".json") -or
        $fileItem.EndsWith(".unpk") -or
        $fileItem.EndsWith(".xml") -or
        $fileItem.EndsWith(".p7s") -or
        $fileItem.EndsWith(".png") -or
        $fileItem.EndsWith(".TXT") -or
        $fileItem.EndsWith(".psmdcp") -or
        $fileItem.EndsWith(".props") -or
        $fileItem.EndsWith(".targets") -or
        $fileItem.EndsWith(".Targets") -or
        $fileItem.EndsWith(".cs") -or
        $fileItem.EndsWith(".nuspec") -or
        $fileItem.EndsWith(".h") -or
        $fileItem.EndsWith(".cpp") -or
        $fileItem.EndsWith(".hxx") -or
        $fileItem.EndsWith(".tpl") -or
        $fileItem.EndsWith(".ruleset") -or
        $fileItem.EndsWith(".tt") -or
        $fileItem.EndsWith(".so") -or
        $fileItem.EndsWith(".ini") -or
        $fileItem.EndsWith(".hpp") -or
        $fileItem.EndsWith(".evxml") -or
        $fileItem.EndsWith(".man") -or
        $fileItem.EndsWith(".proj") -or
        $fileItem.EndsWith(".wixpdb") -or
        $fileItem.EndsWith(".config") -or
        $fileItem.EndsWith(".toolsetversion") -or
        $fileItem.EndsWith(".inc") -or
        $fileItem.EndsWith(".pl") -or
        $fileItem.EndsWith(".swr") -or
        $fileItem.EndsWith(".Config") -or
        $fileItem.EndsWith("corerun") -or
        $fileItem.EndsWith("opt") -or
        $fileItem.EndsWith("llc") -or
        $fileItem.EndsWith("prefercliruntime") -or
        $fileItem.EndsWith("ilasm") -or
        $fileItem.EndsWith("ildasm") -or
        $fileItem.EndsWith("dotnet") -or
        $fileItem.EndsWith("mono-aot-cross") -or
        $fileItem.EndsWith(".githook") -or
        $fileItem.EndsWith(".a") -or
        $fileItem.EndsWith(".version") -or
        $fileItem.EndsWith(".svg") -or
        $fileItem.EndsWith(".dbg") -or
        $fileItem.EndsWith(".pkg") -or
        $fileItem.EndsWith(".pdb") -or
        $fileItem.EndsWith(".cxspec") -or
        $fileItem.EndsWith(".deb") -or
        $fileItem.EndsWith("README") -or
        $fileItem.EndsWith(".rpm") -or
        $fileItem.EndsWith(".tar.gz") -or
        $fileItem.EndsWith(".zip") -or
        $fileItem.EndsWith(".map") -or
        $fileItem.EndsWith(".cache") -or
        $fileItem.EndsWith(".CopyComplete") -or
        $fileItem.EndsWith(".sarif") -or
        $fileItem.EndsWith(".resx") -or
        $fileItem.EndsWith(".snk") -or
        $fileItem.EndsWith(".projitems") -or
        $fileItem.EndsWith(".shproj") -or
        $fileItem.EndsWith(".dcproj") -or
        $fileItem.EndsWith(".Stamp") -or
        $fileItem.EndsWith("word") -or
        $fileItem.EndsWith(".filters") -or
        $fileItem.EndsWith(".user") -or
        $fileItem.EndsWith(".unknownproj") -or
        $fileItem.EndsWith(".sha") -or
        $fileItem.EndsWith(".settings") -or
        $fileItem.EndsWith(".runsettings") -or
        $fileItem.EndsWith(".rsp") -or
        $fileItem.EndsWith(".xsd") -or
        $fileItem.EndsWith(".tlb") -or
        $fileItem.EndsWith(".sha512") -or
        $fileItem.EndsWith(".wixlib") -or
        $fileItem.EndsWith(".yml") -or
        $fileItem.EndsWith(".less") -or
        $fileItem.EndsWith(".scss") -or
        $fileItem.EndsWith(".tgz") -or
        $fileItem.EndsWith(".pom") -or
        $fileItem.EndsWith(".psd1") -or
        $fileItem.EndsWith(".psm1") -or
        $fileItem.EndsWith(".tgz") -or
        $fileItem.EndsWith(".jar") -or # JAR files are signed, but the process of stripping down the diff is pretty annoying. Verified manually
        $fileItem.EndsWith(".lib") -or
        $fileItem.EndsWith(".rels") -or
        $fileItem.EndsWith(".vb") -or
        $fileItem.EndsWith(".vbproj") -or
        $fileItem.EndsWith(".overridetasks") -or
        $fileItem.EndsWith(".manifest") -or
        $fileItem.EndsWith(".fsproj") -or
        $fileItem.EndsWith(".fs") -or
        $fileItem.EndsWith(".proto") -or
        $fileItem.EndsWith(".razor") -or
        $fileItem.EndsWith(".cshtml") -or
        $fileItem.EndsWith(".db") -or
        $fileItem.EndsWith(".css") -or
        $fileItem.EndsWith(".ico") -or
        $fileItem.EndsWith(".eot") -or
        $fileItem.EndsWith(".otf") -or
        $fileItem.EndsWith(".ttf") -or
        $fileItem.EndsWith(".woff") -or
        $fileItem.EndsWith(".html") -or
        $fileItem.EndsWith("browserslist") -or
        $fileItem.EndsWith(".ts") -or
        $fileItem.EndsWith(".gitignore") -or
        $fileItem.EndsWith(".gitkeep") -or
        $fileItem.EndsWith(".env") -or
        $fileItem.EndsWith(".tsx") -or
        $fileItem.EndsWith(".rtf") -or
        $fileItem.EndsWith(".tsx") -or
        $fileItem.EndsWith(".tsx") -or
        $fileItem.EndsWith(".tsx") -or
        $fileItem.EndsWith(".gitignore") -or
        $fileItem.EndsWith(".tasks") -or
        $fileItem.EndsWith("minimumMSBuildVersion") -or
        $fileItem.EndsWith("default.win32manifest") -or
        $fileItem.EndsWith(".editorconfig") -or
        $fileItem.EndsWith(".pubxml") -or
        $fileItem.EndsWith(".transform") -or
        $fileItem.EndsWith(".myapp") -or
        $fileItem.EndsWith("createdump") -or
        $fileItem.EndsWith(".blat") -or
        $fileItem.EndsWith(".wasm") -or
        $fileItem.EndsWith(".xdt") -or
        $fileItem.EndsWith("crossgen") -or
        $fileItem.EndsWith("crossgen2") -or
        $fileItem.EndsWith("apphost") -or
        $fileItem.EndsWith(".dwarf") -or
        $fileItem.EndsWith("singlefilehost") -or
        $fileItem.EndsWith(".vbproj.user") -or
        $fileItem.EndsWith(".csproj.user") -or
        $fileItem.EndsWith("-.") -or
        $fileItem.EndsWith("_._") -or
        $fileItem.EndsWith("LICENSE") -or
        $fileItem.EndsWith(".dat") -or
        $fileItem.EndsWith(".wixpack.zip") -or
        $fileItem.EndsWith(".wixobj") -or
        $fileItem.EndsWith(".xaml") -or
        $fileItem.EndsWith(".dylib") -or
        $fileItem.EndsWith(".inl") -or
        $fileItem.EndsWith(".cxx") -or
        $fileItem.EndsWith(".c") -or
        $fileItem.EndsWith(".vcxproj") -or
        $fileItem.EndsWith(".csproj") -or
        $fileItem.EndsWith(".sln") -or
        $fileItem.EndsWith(".cmd") -or
        $fileItem.EndsWith("TEMP.BIN") -or
        $fileItem.EndsWith(".bin") -or
        $fileItem.EndsWith(".md") -or
        $fileItem.EndsWith(".rc") -or
        $fileItem.EndsWith(".unpk") -or
        $fileItem.EndsWith("unpacked.sem")) {
        return $true
    }
    return $false
}

$beginSigBlockStr = "Begin signature block"

function CompareJsSignature($fileItemA, $fileItemB) {
    if ($fileItemA.EndsWith(".js")) {
        Write-Host "Checking (js) $fileItemA against $fileItemB..."
        
        $toTestFileA = CreateShortFileIfVeryLong $fileItemA
        $toTestFileB = CreateShortFileIfVeryLong $fileItemB
        
        $certCheckA = Select-String -Path $toTestFileA.file -Pattern $beginSigBlockStr -Quiet
        $certCheckB = Select-String -Path $toTestFileB.file -Pattern $beginSigBlockStr -Quiet
        
        DeleteShortFileIfVeryLong $toTestFileA
        DeleteShortFileIfVeryLong $toTestFileB
        
        if ($certCheckA -and -not $certCheckB) {
            [void]$global:errors.Add([CheckError]::new("JS_A_SIG_B_NOSIG", $fileItemA, $fileItemB))
            Write-Error "  JS cert checked failed (JS_A_SIG_B_NOSIG) between $fileItemA and $fileItemB"
            return [FileCheckState]::Failed
        } elseif (-not $certCheckA -and $certCheckB) {
            [void]$global:errors.Add([CheckError]::new("JS_A_NOSIG_B_SIG", $fileItemA, $fileItemB))
            Write-Error "  JS cert checked failed (JS_A_NOSIG_B_SIG) between $fileItemA and $fileItemB"
            return [FileCheckState]::Failed
        } else {        
            return [FileCheckState]::Passed
        }
    } else {
        return [FileCheckState]::NotChecked
    }
}

function CompareEverythingElse($fileItemA, $fileItemB) {
    if (IsTotallyNothingFile $fileItemA) {
        return [FileCheckState]::Passed
    }
    return [FileCheckState]::NotChecked
}

function CompareNupkgSignature($fileItemA, $fileItemB) {
    if ($fileItemA.EndsWith(".nupkg")) {
        Write-Host "Checking (nupkg) $fileItemA against $fileItemB..."
        
        $toTestFileA = CreateShortFileIfVeryLong $fileItemA
        $toTestFileB = CreateShortFileIfVeryLong $fileItemB
        
        $certCheckA = & $nugetPath verify -Signatures $toTestFileA.file
        $certCheckAFailed = $($LASTEXITCODE -ne 0)
        $certCheckB = & $nugetPath verify -Signatures $toTestFileB.file
        $certCheckBFailed = $($LASTEXITCODE -ne 0)
        
        DeleteShortFileIfVeryLong $toTestFileA
        DeleteShortFileIfVeryLong $toTestFileB
        
        # Replace filenames in the output
        $strippedCertCheckA = $certCheckA.Replace($toTestFileA.file, "")
        $strippedCertCheckB = $certCheckB.Replace($toTestFileB.file, "")
        
        # Replace file names without extension in the output. Use the original file name.
        # If symbols.nupkg, remove that bit.
        $strippedCertCheckA = $strippedCertCheckA.Replace([System.IO.Path]::GetFileNameWithoutExtension($fileItemA.Replace(".symbols.nupkg", ".nupkg")), "")
        $strippedCertCheckB = $strippedCertCheckB.Replace([System.IO.Path]::GetFileNameWithoutExtension($fileItemB.Replace(".symbols.nupkg", ".nupkg")), "")
        
        $diff = Diff $strippedCertCheckA $strippedCertCheckB
        
        # Diff should be two items, a timestamp on either side
        if ($diff.Count -eq 2) {
            if ($diff[0].InputObject.StartsWith("Timestamp: ") -and 
                $diff[1].InputObject.StartsWith("Timestamp: ")) {
                $diff = $null
            }
        }
        
        if ($diff) {
            if ($certCheckAFailed -and -not $certCheckBFailed) {
                [void]$global:errors.Add([CheckError]::new("NUPKG_A_NOSIG_B_SIG", $fileItemA, $fileItemB))
                Write-Error "  Nupkg cert checked failed (NUPKG_A_NOSIG_B_SIG) between $fileItemA and $fileItemB"
                return [FileCheckState]::Failed
            } elseif ($certCheckBFailed -and -not $certCheckAFailed) {
                [void]$global:errors.Add([CheckError]::new("NUPKG_A_SIG_B_NOSIG", $fileItemA, $fileItemB))
                Write-Error "  Nupkg cert checked failed (NUPKG_A_SIG_B_NOSIG) between $fileItemA and $fileItemB"
                return [FileCheckState]::Failed
            } else {
                Write-Host $($diff -join '`n')
                [void]$global:errors.Add([CheckError]::new("NUPKG_CHECK_OTHER", $fileItemA, $fileItemB))
                Write-Error "  Nupkg cert checked failed (NUPKG_CHECK_OTHER) between $fileItemA and $fileItemB"
                return [FileCheckState]::Failed
            }
        }
        else {
            return [FileCheckState]::Passed
        }
    } else {
        return [FileCheckState]::NotChecked
    }
}

function CreateShortFileIfVeryLong($fileItem) {
    if ($fileItem.Length -gt 255) {
        $tempFile = New-TemporaryFile
        cp $fileItem $tempFile
        return @{file = $tempFile; isTemp = $true}
    } else {
        return @{file = $fileItem; isTemp = $false}
    }
}

function DeleteShortFileIfVeryLong($potentiallyShortFileInfo) {
    if ($potentiallyShortFileInfo.isTemp) {
        rm $potentiallyShortFileInfo.file
    }
}

function CompareStrongName($fileItemA, $fileItemB) {
    if ($fileItemA.EndsWith(".exe") -or $fileItemA.EndsWith(".dll")) {
        Write-Host "Checking (sn) $fileItemA against $fileItemB..."
        
        $toTestFileA = CreateShortFileIfVeryLong $fileItemA
        $toTestFileB = CreateShortFileIfVeryLong $fileItemB
        
        $snCheckA = & $snPath -T $toTestFileA.file
        $snCheckB = & $snPath -T $toTestFileB.file
        
        # Replace filenames in the output
        $strippedCertCheckA = $snCheckA.Replace($toTestFileA.file, "")
        $strippedCertCheckB = $snCheckB.Replace($toTestFileB.file, "")
        
        $diff = Diff $strippedCertCheckA $strippedCertCheckB
        
        DeleteShortFileIfVeryLong $toTestFileA
        DeleteShortFileIfVeryLong $toTestFileB

        if ($diff) {
            [void]$global:errors.Add([CheckError]::new("SN_CHECK", $fileItemA, $fileItemB))
            Write-Error "  SN check failed (SN_CHECK): SN differences between $fileItemA and $fileItemB"
            return [FileCheckState]::Failed
        }
        else {
            return [FileCheckState]::Passed
        }
    } else {
        return [FileCheckState]::NotChecked
    }
}

function CompareAuthenticode($fileItemA, $fileItemB) {
    if ($fileItemA.EndsWith(".exe") -or $fileItemA.EndsWith(".dll") -or
        $fileItemA.EndsWith(".ps1") -or $fileItemA.EndsWith(".msi")) {
        Write-Host "Checking (auth) $fileItemA against $fileItemB..."
        
        $toTestFileA = CreateShortFileIfVeryLong $fileItemA
        $toTestFileB = CreateShortFileIfVeryLong $fileItemB
        
        $sigA = Get-AuthenticodeSignature $toTestFileA.file
        $sigB = Get-AuthenticodeSignature $toTestFileB.file
        
        DeleteShortFileIfVeryLong $toTestFileA
        DeleteShortFileIfVeryLong $toTestFileB
        
        if ($sigA.SignerCertificate -eq $sigB.SignerCertificate -and
            
            $sigA.Status -eq $sigB.Status) {
            return [FileCheckState]::Passed

        } elseif ($sigA.Status -eq "NotSigned" -and $sigB.Status -eq "Valid") {
            
            [void]$global:errors.Add([CheckError]::new("AUTH_A_NOSIG_B_SIG", $fileItemA, $fileItemB))
            Write-Error "  Cert check failed (AUTH_B_SIG_A_NOSIG): $fileItemB has signature but $fileItemA does not"
            return [FileCheckState]::Failed

        } elseif ($sigA.Status -eq "Valid" -and $sigB.Status -eq "NotSigned") {
            
            [void]$global:errors.Add([CheckError]::new("AUTH_A_SIG_B_NOSIG", $fileItemA, $fileItemB))
            Write-Error "  Cert check failed (AUTH_A_SIG_B_NOSIG): $fileItemA has signature but $fileItemB does not"
            return [FileCheckState]::Failed

        } elseif ($sigA.SignerCertificate -ne $sigB.SignerCertificate) {
            
            [void]$global:errors.Add([CheckError]::new("AUTH_SIG_CERT_DIFF", $fileItemA, $fileItemB))
            Write-Error "  Cert check failed (AUTH_SIG_CERT_DIFF): Cert differences between $fileItemA and $fileItemB"
            return [FileCheckState]::Failed

        } else {
            
            [void]$global:errors.Add([CheckError]::new("AUTH_SIG_DIFF_OTHER", $fileItemA, $fileItemB))
            Write-Error "  Cert check failed (AUTH_SIG_DIFF_OTHER): Check diff between $fileItemA and $fileItemB"
            return [FileCheckState]::Failed

        }
    } else {
        return [FileCheckState]::NotChecked
    }
}

function UnpackContainer($fileItem, $fileUnpackRoot) {
    # Don't unpack wixpack.zips becuase they aren't actually
    # repacked after signing anyway.
    if ($($fileItem.EndsWith(".zip") -or $fileItem.EndsWith(".nupkg")) `
        -and -not $fileItem.EndsWith("wixpack.zip") `
        -and -not $fileItem.Contains("Microsoft.NET.Sdk.Publish") `
        -and -not $fileItem.Contains("Microsoft.NET.Sdk.Web") `
        -and -not $fileItem.Contains("Microsoft.NET.Sdk.Worker")) {
        $unpackedSemFile = Join-Path $fileUnpackRoot "unpacked.sem"
        $semFileExists = $(Test-Path $unpackedSemFile)
        if ($force -and $semFileExists) {
            rm $unpackedSemFile | Out-Null
        }
        if (-not $(Test-Path $fileUnpackRoot) -or -not $(Test-Path $unpackedSemFile)) {
            if (Test-Path $fileUnpackRoot) {
                rmdir -R -Force $fileUnpackRoot | Out-Null
            }
            mkdir $fileUnpackRoot | Out-Null
            try {
                Write-Host "Unpacking $fileItem to $fileUnpackRoot"
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                [System.IO.Compression.ZipFile]::ExtractToDirectory($fileItem, $fileUnpackRoot)
                Set-Content $unpackedSemFile "unpacked"
            }
            catch {
                Write-Host $_
                throw "Couldn't unpack $fileItem to $fileUnpackRoot"
                return [FileUnpackState]::Unknown
            }
        }
        return [FileUnpackState]::Unpacked
    } elseif (IsTotallyNothingFile $fileItem) {
        return [FileUnpackState]::NotUnpacked
    } else {
        return [FileUnpackState]::Unknown
    }
}

function Escape-Path($path) {
    $escaped = $path.Replace("`[", "``[")
    $escaped = $escaped.Replace("`]", "``]")
    return $escaped
}

function VerifySubdrop([string]$baseA, [string]$baseB) {
    $passed = $true
    $alreadyVerifiedDropSem = Join-Path $baseA "drop.vfied"
    $semFileExists = $(Test-Path $(Escape-Path $alreadyVerifiedDropSem))
    if ($force -and $semFileExists) {
        rm $alreadyVerifiedDropSem
    }
    
    if ($(Test-Path $(Escape-Path $alreadyVerifiedDropSem))) {
        return $true
    }
        
    Write-Host "Verifying subdrop $baseA against $baseB"
    # Exclude files that are in nested archives
    $fileListA = ls -R -File $baseA | % { if (-not $_.FullName.Replace($baseA, "").Contains("unpk")) { $_.FullName } }
    foreach ($fileItemA in $fileListA) {
        $replacedBaseItemB = $fileItemA.Replace($baseA, $baseB)
        $fileItemB = $null
        foreach ($mapItem in $versionMap) {
            $fileItemB = $replacedBaseItemB.Replace($mapItem.key, $mapItem.value)
            if (-not $(Test-Path $(Escape-Path $fileItemB))) {
                # If fileItemB's path is different than mapItem.key,
                # then we should check the version map for a second level of
                # items. There are many places in SDK and installer
                # where multiple versions appear in a path
                if ($fileItemB -ne $replacedBaseItemB) {
                    $partiallyReplacedBaseItemB = $fileItemB
                    foreach ($mapItem in $versionMap) {
                        $fileItemB = $partiallyReplacedBaseItemB.Replace($mapItem.key, $mapItem.value)
                        if (-not $(Test-Path $(Escape-Path $fileItemB))) {
                            $fileItemB = $null
                        }
                        else {
                            break;
                        }
                    }
                } else {
                    $fileItemB = $null
                }
                if ($fileItemB) {
                    break;
                }
            }
            else {
                break;
            }
        }
        
        $alreadyVerifiedSem = "$fileItemA.vfied"
        $semFileExists = $(Test-Path $(Escape-Path $alreadyVerifiedSem))
        if ($force -and $semFileExists) {
            rm $alreadyVerifiedSem
        }
        
        if (!$fileItemB) {
            # A few files we don't care about right now
            if ($fileItemA.EndsWith("-engine.exe") -or `
                $fileItemA.EndsWith("-engine.exe.sha512") -or `
                $fileItemA.EndsWith(".wixpack.zip.sha512") -or `
                $fileItemA.EndsWith(".wixpack.zip") -or `
                $fileItemA.EndsWith("}.map") -or `
                $fileItemA.EndsWith("MergedManifest.xml") -or `
                $fileItemA.EndsWith("RuntimeList.xml") -or `
                $fileItemA.Contains(".template.config") -or `
                $fileItemA.EndsWith(".vfied") -or `
                $fileItemA.Contains("Microsoft.NETCore.Runtime.ICU.Transport") -or `
                $fileItemA.EndsWith(".p7s") -or `
                $fileItemA.EndsWith(".psmdcp") -or `
                $fileItemA.Contains("`[Content_Types`]") -or `
                $fileItemA.Contains("mscordaccore_")) {
                continue
            }
            
            [void]$global:errors.Add([CheckError]::new("FILE_NOT_FOUND_IN_B", $fileItemA, $fileItemA))
            continue
        }

        if (-not $(Test-Path $(Escape-Path $alreadyVerifiedSem))) {
        
            # Check file, then determine whether it's a container
            $authenticodeCheckState2 = CompareAuthenticode $fileItemA $fileItemB
            [FileCheckState]$authenticodeCheckState = CompareAuthenticode $fileItemA $fileItemB
            [FileCheckState]$nupkgCheckState = CompareNupkgSignature $fileItemA $fileItemB
            [FileCheckState]$snCheckState = CompareStrongName $fileItemA $fileItemB
            [FileCheckState]$jsCheckState = CompareJsSignature $fileItemA $fileItemB
            [FileCheckState]$everyThingElseCheckState = CompareEverythingElse $fileItemA $fileItemB
            
            if ($authenticodeCheckState -eq [FileCheckState]::NotChecked -and
                $everyThingElseCheckState -eq [FileCheckState]::NotChecked -and
                $snCheckState -eq [FileCheckState]::NotChecked -and
                $nupkgCheckState -eq [FileCheckState]::NotChecked -and
                $jsCheckState -eq [FileCheckState]::NotChecked) {
                
                $passed = $false
                
                [void]$global:errors.Add([CheckError]::new("NO_WAY_TO_CHECK", $fileItemA, $fileItemB))
            } elseif ($($authenticodeCheckState -eq [FileCheckState]::Passed -or
                      $everyThingElseCheckState -eq [FileCheckState]::Passed -or
                      $snCheckState -eq [FileCheckState]::Passed -or
                      $jsCheckState -eq [FileCheckState]::Passed -or
                      $nupkgCheckState -eq [FileCheckState]::Passed) -and 
                      $($authenticodeCheckState -ne [FileCheckState]::Failed -and
                      $everyThingElseCheckState -ne [FileCheckState]::Failed -and
                      $snCheckState -ne [FileCheckState]::Failed -and
                      $jsCheckState -ne [FileCheckState]::Failed -and
                      $nupkgCheckState -ne [FileCheckState]::Failed)) {
                Set-Content $(Escape-Path $alreadyVerifiedSem) "verified"
            } else {
                $passed = $false
            }
        }
        
        $fileItemAUnpackRoot = "$fileItemA.unpk"
        $fileItemBUnpackRoot = "$fileItemB.unpk"
        [FileUnpackState]$fileUnpackAState = UnpackContainer $fileItemA $fileItemAUnpackRoot
        [FileUnpackState]$fileUnpackBState = UnpackContainer $fileItemB $fileItemBUnpackRoot
        
        if ($fileUnpackAState -ne $fileUnpackBState) {
            $passed = $false
            throw "$fileItemA did not unpack the same way as $fileItemB"
        } elseif ($fileUnpackAState -eq [FileUnpackState]::NotChecked) {
            $passed = $false
            throw "Could not find a way to unpack or ignore $fileItemA"
        } elseif ($fileUnpackAState -eq [FileUnpackState]::Unpacked) {
            $subDropPassed = VerifySubdrop $fileItemAUnpackRoot $fileItemBUnpackRoot
            $passed = $passed -and $subDropPassed
        }
    }
    
    if ($passed) {
        Set-Content $alreadyVerifiedDropSem "verified"
    }
    
    return $passed
}

if ($(VerifySubdrop $dropBaseA $dropBaseB)) {
    Write-Host "Passed"
} else {
    Write-Host "Failed"
}

$global:errors