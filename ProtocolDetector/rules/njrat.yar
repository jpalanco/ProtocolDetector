rule njrat : protocols
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@dinoflux.com>"
    description = "njRAT Protocol"
  strings:
    $header = /\d{1,6}\x00/
    $sep = { 7C 27 7C 27 7C }
  condition:
    $header at 0 and $sep
}