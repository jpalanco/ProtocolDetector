rule ssh : protocols 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@dinoflux.com>"
    description = "SSH Protocol"
  strings: 
    $header_v2 = "SSH-2.0-" 
    $header_v1 = "SSH-1.99-" 
  condition: 
    $header_v2 at 0 or $header_v1 at 0
}
