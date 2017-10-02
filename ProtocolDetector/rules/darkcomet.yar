rule darkcomet : protocols
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@dinoflux.com>"
    description = "Darkcomet Protocol"
  strings:
    $payload = /KEEPALIVE\d{7}/
  condition:
    $payload at 0
}