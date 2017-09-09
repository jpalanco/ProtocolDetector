rule smtp : protocols 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@dinoflux.com>"
    description = "SMTP Protocol"
  strings: 
    $command = /(EHLO\s+.*|AUTH\sLOGIN|MAIL\s+FROM)/i
  condition: 
    $command at 0
}
