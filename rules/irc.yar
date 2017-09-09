rule irc : protocols 
{
  meta:
    author = "Jose Ramon Palanco <jose.palanco@dinoflux.com>"
    description = "IRC Protocol"
  strings: 
    $command = /(USER|USERHOST|PASS|NICK|JOIN|MODE|MSG|PRIVMSG|PUBMSG|TOPIC|TOPICINFO|CURRENTTOPIC|identify)\s+/i
  condition: 
    $command at 0
}
