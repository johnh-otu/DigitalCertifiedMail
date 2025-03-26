# Digital Certified Mail
```
X=======================================================================================X
|____/\\\\\\\\\\\\___________/\\\\\\\\\__/\\\\____________/\\\\____/\\\__/\\\___________|
|____\/\\\////////\\\______/\\\////////__\/\\\\\\________/\\\\\\___\/\\\_\/\\\__________|
|_____\/\\\______\//\\\___/\\\/___________\/\\\//\\\____/\\\//\\\__/\\\\\\\\\\\\\_______|
|______\/\\\_______\/\\\__/\\\_____________\/\\\\///\\\/\\\/_\/\\\_\///\\\///\\\/_______|
|_______\/\\\_______\/\\\_\/\\\_____________\/\\\__\///\\\/___\/\\\___\/\\\_\/\\\_______|
|________\/\\\_______\/\\\_\//\\\____________\/\\\____\///_____\/\\\__/\\\\\\\\\\\\\____|
|_________\/\\\_______/\\\___\///\\\__________\/\\\_____________\/\\\_\///\\\///\\\/____|
|__________\/\\\\\\\\\\\\/______\////\\\\\\\\\_\/\\\_____________\/\\\___\/\\\_\/\\\____|
|___________\////////////___________\/////////__\///______________\///____\///__\///____|
X=======================================================================================X
| DCM Sharp - Digital Certified Mail Windows Console App  (V1.0)                        |
X=======================================================================================X
```
This is our final project for the Software and Computer Security course.

---
# How to Run: (Temporary)
### Certificate Setup
1. Open Powershell with Admin privileges
2. Create an X509 certificate with the following commands:
> *** NOTE: Replace \<PATH\> and \<PASSWORD\> in the commands with your own values. ***
```powershell
$cert = New-SelfSignedCertificate -CertStoreLocation Cert:\LocalMachine\My -DnsName "127.0.0.1" -FriendlyName "LocalhostCert" -NotAfter (Get-Date).AddYears(10)
$password = ConvertTo-SecureString -String "<PASSWORD>" -Force -AsPlainText
Export-PfxCertificate -Cert "Cert:\LocalMachine\My\$($cert.Thumbprint)" -FilePath "<PATH>" -Password $password
```
3. Open "Manage Computer Certificates" in your start menu
4. Navigate to "Certificates - LocalComputer" > Personal > Certificates
5. Drag your new certificate and drop it into "Trusted Root Certification Authorities" > Certificates
### Run in Terminal:
1. Download compiled EXE file
2. Run exe in CMD with the following argument structure:
```
dcm#.exe <host-ip> <host-port> <X509-Certificate-Path> <X509-Certificate-Password>
```
### Run in Visual Studio:
1. Open Visual Studio Community or Enterprise
2. Open the solution file
3. Edit the project debug properties to include the following debug arguments:
```
<host-ip> <host-port> <X509-Certificate-Path> <X509-Certificate-Password>
```
4. Click "Start" or press F5
