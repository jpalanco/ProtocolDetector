rule teamviewer : protocols
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@dinoflux.com>"
    description = "Teamviewer Protocol"
  strings:
    $tv_header = { 11 30 }
  condition:
    $tv_header at 0
}

