
package SPFBL;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Timeout;
use Mail::SpamAssassin::PerMsgStatus;
use IO::Socket::INET;

use strict;
use warnings;
use bytes;
use re 'taint';

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

# auto-flush on socket
$| = 1;

# configs
my $CONFIG = {
    socket => {
        PeerHost => 'tower.spfbl.net',
        PeerPort => 9877,
        Proto    => 'tcp',
        Timeout  => 10,
    }
};

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  # signatures
  $self->register_eval_rule("spfbl_check");

  return $self;
}

sub spfbl_check {
  my ($self, $pms, $header) = @_;	
  my $score = 0;
  my $returnMsg = "";

  my $filename = "/tmp/spfbl_spamassassin.log";
  open(my $fhLogger, '>>', $filename) or die "Could not open file '$filename' $!";
  $fhLogger->autoflush(1);

  my $msg = $pms->{msg};
  my $mid = $msg->get_header("Message-Id");

  
  print $fhLogger gmtime() . " SPFBL Init SenderIP:" . $pms->get_tag('LASTEXTERNALIP') . " SenderHELO:" . $pms->get_tag('LASTEXTERNALHELO') . " From:" . $pms->get('From') . " To:" . $pms->get('To') . " MsgId:" . $mid . "\n";


  my $senderIP = $pms->get_tag('LASTEXTERNALIP');
  my $senderHELO = $pms->get_tag('LASTEXTERNALHELO');
  chomp($mid);
  my $subject = $pms->get('Subject');
  chomp($subject);

  $_ = $pms->get('From');
  s/.*<+(.+)>+.*/$1/;
  my $from  = $_;
  chomp($from);

  #$_ = $pms->get('To');
  $_ = 'marechalepi@opcaonet.com.br, atendimento.apb@gmail.com';
  s/([^,]+),?.*/$1/;
  #s/.*<+(.+)>+.*/$1/;
  #s/(.+),?.*/$1/;
  my $to  = $_;
  #my $to = 'marechalepi@opcaonet.com.br, atendimento.apb@gmail.com';
  chomp($to);

  if ($from eq 'ignore@compiling.spamassassin.taint.org') {
    print $fhLogger gmtime() . " SPFBL: no scan in lint mode, quitting\n";
    close $fhLogger;
    return 0;
  }

  if ($to eq 'abuse@opcaonet.com.br') {
    print $fhLogger gmtime() . " SPFBL: Whitelist Manual MSG:$mid from:$from to:$to\n";
    close $fhLogger;
    return 0;
  }


  print $fhLogger gmtime() . " SPFBL SenderIP:$senderIP SenderHELO:$senderHELO From:$from To:$to Subject:$subject MsgId:$mid\n";
  
  my $socket = IO::Socket::INET->new( %{ $CONFIG->{socket} } )
      or print $fhLogger gmtime() . " Can't connect to SPFBL server!\n";

  # build and send query
  my $query = "SPF '$senderIP' '$from' '$senderHELO' '$to'\n";
  print $fhLogger gmtime() . " SPFBL Query:$query MsgId:$mid\n";
  $socket->send($query);

  shutdown $socket, 1;

  my $result = '';
  $socket->recv( $result, 4096 );
  $socket->close();
  $result =~ s/\s+$//;


  print $fhLogger gmtime() . " SPFBL Result:$result MsgId:$mid\n";


  # parse the result

  if ( $result =~ /^LISTED/ ) {
      $score = 5;
      $returnMsg = "[RBL] you are temporarily blocked on this server.";
  }
  elsif ( $result =~ /^NXDOMAIN/ ) {
      $score = 5;
      $returnMsg = "[RBL] sender has non-existent internet domain.";
  }
  elsif ( $result =~ /^BLOCKED/ ) {
      $score = 5;
      $returnMsg = "[RBL] you are permanently blocked in this server.";
  }
  elsif ( $result =~ /^INVALID/ ) {
      $score = 3;
      $returnMsg = "[SPF] IP or sender is invalid.";
  }
  elsif ( $result =~ /^GREYLIST/ ) {
      $score = 2;
      $returnMsg = "[RBL] you are greylisted on this server.";
  }
  elsif ( $result =~ /^SPAMTRAP/ ) {
      $score = 0;
      $returnMsg = "[RBL] discarded by spamtrap.";
  }
  elsif ( $result =~ /^ERROR: INVALID SENDER/ ) {
      $score = 4;
      $returnMsg = "[RBL] $from is not a valid e-mail address.";
  }
  elsif ( $result =~ /^ERROR: HOST NOT FOUND/ ) {
      $score = 4;
      $returnMsg = "[SPF] A transient error occurred when checking SPF record from $from, preventing a result from being reached. Try again later.";
  }
  elsif ( $result =~ /^ERROR: QUERY/ ) {
      $returnMsg = "[SPF] A transient error occurred when checking SPF record from $from, preventing a result from being reached. Try again later.";
  }
  elsif ( $result =~ /^ERROR: / ) {
      $returnMsg = "[SPF] One or more SPF records from $from could not be interpreted. Please see http://www.openspf.org/SPF_Record_Syntax for details.";
  }
  elsif ( $result =~ /^NONE / ) {
      $score = -1;
      $returnMsg = "Received-SPFBL: $result\n\n";
  }
  elsif ( $result =~ /^PASS / ) {
      $score = -2;
      $returnMsg = "Received-SPFBL: $result\n\n";
  }
  elsif ( $result =~ /^FAIL / ) {
      $score = -1;
      # retornou FAIL com ticket.
      $returnMsg = "Received-SPFBL: $result\n\n";
  }
  elsif ( $result =~ /^FAIL/ ) {
      $score = 3;
      $returnMsg = "[SPF] $from is not allowed to send mail from $senderIP. Please see http://www.openspf.org/why.html?sender=$from&ip=$senderIP for details.";
  }
  elsif ( $result =~ /^SOFTFAIL / ) {
      $score = 2;
      $returnMsg = "Received-SPFBL: $result\n\n";
  }
  elsif ( $result =~ /^NEUTRAL / ) {
      $score = 0;
      $returnMsg = "Received-SPFBL: $result\n\n";
  }
  else {
      $score = 0.5;
      $returnMsg = "[SPF] A transient error occurred when checking SPF record from $senderIP, preventing a result from being reached. Try again later.";
  }
  $pms->set_tag ("SPFBLSENTENCE", $result);

  if($result =~ /PASS/){
  	$pms->set_tag ("SPFBLSENTENCEDESC", 'Pass');
  } else {
  	$pms->set_tag ("SPFBLSENTENCEDESC", $returnMsg);
  }
  

  if($score <=0){
      print $fhLogger gmtime() . " SPFBL score <=0 MsgId:$mid\n";
      
  } else {
    print $fhLogger gmtime() . " SPFBL score ELSE MsgId:$mid\n";
  }
	
  print $fhLogger gmtime() . " SPFBL ResultScore:$score Message:$returnMsg MsgId:$mid\n";
 
  #############################################

  #my $score = -3.8;
  $score = 0;
  my $description = $pms->{conf}->{descriptions}->{SPFBL};
  $description .= " -- with score $score";
  $pms->{conf}->{descriptions}->{SPFBL} = $description;

  $pms->got_hit("SPFBL", "HEADER: ", score => $score);



  for my $set (0..3) {
     $pms->{conf}->{scoreset}->[$set]->{"SPFBL"} =
          sprintf("%0.3f", $score);
  }
  close $fhLogger;

  return 0;
}


1;
