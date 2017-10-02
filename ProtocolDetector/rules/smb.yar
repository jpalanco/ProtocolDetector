rule smb : protocols
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@dinoflux.com>"
    description = "SMB"
  strings:
    $netbios_header = { 00 } 
    $smb_header = { FF 53 4D 42 }
  condition:
    $netbios_header at 0 and $smb_header at 4
}

