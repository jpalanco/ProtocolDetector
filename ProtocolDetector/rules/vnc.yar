rule vnc : protocols
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@dinoflux.com>"
    description = "VNC Protocol"
  strings:
    $vnc_header = { 52 46 42 20 }
  condition:
    $vnc_header at 0
}

